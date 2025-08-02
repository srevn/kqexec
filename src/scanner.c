#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <dirent.h>
#include <pthread.h>

#include "scanner.h"
#include "states.h"
#include "stability.h"
#include "monitor.h"
#include "logger.h"
#include "events.h"

/* Create a scanner state */
scanner_t *scanner_create(const char *path) {
	scanner_t *scanner = calloc(1, sizeof(scanner_t));
	if (!scanner) {
		log_message(ERROR, "Failed to allocate scanner state");
		return NULL;
	}

	scanner->sample_count = 0;
	scanner->sample_index = 0;
	scanner->active = false;
	scanner->active_path = path ? strdup(path) : NULL;
	clock_gettime(CLOCK_MONOTONIC, &scanner->latest_time);

	return scanner;
}

/* Destroy a scanner state */
void scanner_destroy(scanner_t *scanner) {
	if (scanner) {
		free(scanner->active_path);
		free(scanner);
	}
}

/* Update cumulative changes based on current vs. previous stats */
void scanner_update(entity_t *state) {
	if (!state || !state->node || !state->stability) return;

	/* Calculate incremental changes */
	int new_files, new_dirs, new_depth;
	ssize_t new_size;

	/* Calculate the difference from previous stats */
	new_files = state->stability->stats.tree_files - state->stability->prev_stats.tree_files;
	new_dirs = state->stability->stats.tree_dirs - state->stability->prev_stats.tree_dirs;
	new_depth = state->stability->stats.max_depth - state->stability->prev_stats.max_depth;
	new_size = (ssize_t) state->stability->stats.tree_size - (ssize_t) state->stability->prev_stats.tree_size;

	/* Accumulate changes */
	state->stability->delta_files += new_files;
	state->stability->delta_dirs += new_dirs;
	state->stability->delta_depth += new_depth;
	state->stability->delta_size += new_size;

	/* Set flag indicating stability was lost if we're detecting new changes */
	bool active = state->scanner ? state->scanner->active : false;
	if (!active && (new_files != 0 || new_dirs != 0 || new_depth != 0 || new_size != 0)) {
		state->stability->stability_lost = true;
	}

	/* Log significant cumulative changes */
	if (new_files != 0 || new_dirs != 0 || new_depth != 0 || new_size != 0) {
		log_message(DEBUG, "Updated cumulative changes for %s: files=%+d (%+d), dirs=%+d (%+d), depth=%+d (%+d), size=%s (%s)",
		            state->node->path, state->stability->delta_files, new_files, state->stability->delta_dirs,
		            new_dirs, state->stability->delta_depth, new_depth, format_size(state->stability->delta_size, true),
		            format_size(new_size, true));
	}
}

/* Gather basic directory statistics */
bool scanner_scan(const char *dir_path, stats_t *stats, bool recursive, bool hidden) {
	DIR *dir;
	struct dirent *dirent;
	struct stat info;
	char path[PATH_MAX];

	if (!dir_path || !stats) {
		return false;
	}

	/* Initialize stats with recursive fields */
	memset(stats, 0, sizeof(stats_t));

	dir = opendir(dir_path);
	if (!dir) {
		log_message(WARNING, "Failed to open directory for stats gathering: %s", dir_path);
		return false;
	}

	time_t current_time;
	time(&current_time);

	while ((dirent = readdir(dir))) {
		/* Skip . and .. */
		if (strcmp(dirent->d_name, ".") == 0 || strcmp(dirent->d_name, "..") == 0) {
			continue;
		}

		snprintf(path, sizeof(path), "%s/%s", dir_path, dirent->d_name);

		/* Skip hidden files if not requested */
		if (!hidden) {
			const char *basename = strrchr(path, '/');
			if ((basename ? basename + 1 : path)[0] == '.') {
				continue;
			}
		}

		if (stat(path, &info) != 0) {
			/* Skip files that can't be stat'd but continue processing */
			continue;
		}

		if (S_ISREG(info.st_mode)) {
			stats->local_files++;
			stats->local_size += info.st_size;

			/* Update latest modification time */
			if (info.st_mtime > stats->last_mtime) {
				stats->last_mtime = info.st_mtime;
			}
		} else if (S_ISDIR(info.st_mode)) {
			stats->local_dirs++;

			/* If recursive, scan subdirectories */
			if (recursive) {
				stats_t sub_stats;
				if (scanner_scan(path, &sub_stats, recursive, hidden)) {
					/* Update maximum tree depth based on subdirectory scan results */
					if (sub_stats.depth + 1 > stats->depth) {
						stats->depth = sub_stats.depth + 1;
					}

					/* Calculate and update recursive stats by summing up from subdirectories */
					stats->tree_files += sub_stats.tree_files;
					stats->tree_dirs += sub_stats.tree_dirs;
					stats->tree_size += sub_stats.tree_size;

					/* Update max_depth considering subdirectory's max depth */
					if (sub_stats.max_depth + 1 > stats->max_depth) {
						stats->max_depth = sub_stats.max_depth + 1;
					}

					if (sub_stats.last_mtime > stats->last_mtime) {
						stats->last_mtime = sub_stats.last_mtime;
					}
				}
			}
		}
	}

	/* Ensure recursive stats include direct stats at this level */
	stats->tree_files += stats->local_files;
	stats->tree_dirs += stats->local_dirs;
	stats->tree_size += stats->local_size;

	/* If max_depth is not set, use depth */
	if (stats->max_depth == 0 && stats->depth > 0) {
		stats->max_depth = stats->depth;
	}

	closedir(dir);
	return true;
}

/* Compare two directory statistics to check for stability */
bool scanner_compare(stats_t *prev_stats, stats_t *current_stats) {
	if (!prev_stats || !current_stats) return false;

	/* Calculate content changes using recursive stats for a complete view of the tree */
	int file_change = current_stats->tree_files - prev_stats->tree_files;
	int dir_change = current_stats->tree_dirs - prev_stats->tree_dirs;
	int depth_change = current_stats->max_depth - prev_stats->max_depth;
	int total_change = abs(file_change) + abs(dir_change);

	/* Log depth changes */
	if (depth_change != 0) {
		log_message(DEBUG, "Directory tree depth changed: %d -> %d (%+d levels)",
		            prev_stats->max_depth, current_stats->max_depth, depth_change);
	}

	/* Allow small changes for larger directories */
	int prev_total = prev_stats->tree_files + prev_stats->tree_dirs;
	float change_percentage = (prev_total > 0) ? ((float) total_change / prev_total) * 100.0 : 0;

	/* Use a threshold that scales with directory size */
	int max_allowed_change;
	float max_allowed_percent;

	if (prev_total < 10) {
		/* Very small directories - no changes allowed */
		max_allowed_change = 0;
		max_allowed_percent = 0.0;
	} else if (prev_total < 50) {
		/* Small directories - allow 1 change */
		max_allowed_change = 1;
		max_allowed_percent = 5.0;
	} else if (prev_total < 200) {
		/* Medium directories - allow 2 changes or 3% */
		max_allowed_change = 2;
		max_allowed_percent = 3.0;
	} else if (prev_total < 1000) {
		/* Large directories - allow 4 changes or 2% */
		max_allowed_change = 4;
		max_allowed_percent = 2.0;
	} else {
		/* Very large directories - allow 10 changes or 1% */
		max_allowed_change = 10;
		max_allowed_percent = 1.0;
	}

	/* Check for instability due to various factors */
	bool is_stable = true;

	/* Always consider unstable if tree depth changes significantly */
	if (abs(depth_change) > 1) {
		log_message(DEBUG, "Directory unstable: significant tree depth change (%+d levels)", depth_change);
		is_stable = false;
	}

	/* Check if changes are within allowances */
	if (!((total_change <= max_allowed_change || change_percentage <= max_allowed_percent) &&
	      (depth_change == 0 || (abs(depth_change) == 1 && prev_stats->max_depth > 2)))) {
		log_message(DEBUG, "Directory unstable: %d/%d to %d/%d, depth %d to %d (%+d files, %+d dirs, %+d depth, %.1f%% change)",
		            prev_stats->tree_files, prev_stats->tree_dirs, current_stats->tree_files, current_stats->tree_dirs,
		            prev_stats->max_depth, current_stats->max_depth, file_change, dir_change, depth_change, change_percentage);
		is_stable = false;
	}

	/* Check for temporary files */
	if (current_stats->temp_files) {
		log_message(DEBUG, "Directory unstable: temporary files detected");
		is_stable = false;
	}

	/* Log if stable despite minor changes */
	if (is_stable && (total_change > 0 || depth_change != 0)) {
		log_message(DEBUG, "Directory considered stable despite small changes: %+d files, %+d dirs, %+d depth (%.1f%% change)",
		            file_change, dir_change, depth_change, change_percentage);
	}

	return is_stable;
}

/* Collect statistics about a directory and its contents, and determine stability */
bool scanner_stable(monitor_t *monitor, entity_t *context, const char *dir_path, stats_t *stats, bool recursive, bool hidden) {
	DIR *dir;
	struct dirent *dirent;
	struct stat info;
	char path[PATH_MAX];
	bool is_stable = true; /* Assume stable until proven otherwise */

	if (!dir_path || !stats || !context) {
		return false;
	}

	/* Initialize stats including the new recursive fields */
	memset(stats, 0, sizeof(stats_t));

	dir = opendir(dir_path);
	if (!dir) {
		log_message(WARNING, "Failed to open directory for stability check: %s", dir_path);
		return false; /* Cannot scan, so not stable */
	}

	time_t current_time;
	time(&current_time);

	while ((dirent = readdir(dir))) {
		/* Skip . and .. */
		if (strcmp(dirent->d_name, ".") == 0 || strcmp(dirent->d_name, "..") == 0) {
			continue;
		}

		snprintf(path, sizeof(path), "%s/%s", dir_path, dirent->d_name);

		/* Skip hidden files if not requested */
		if (!hidden) {
			const char *basename = strrchr(path, '/');
			if ((basename ? basename + 1 : path)[0] == '.') {
				continue;
			}
		}

		if (stat(path, &info) != 0) {
			/* If a file disappears during scan, the directory is not stable */
			log_message(DEBUG, "Directory %s unstable: file disappeared during scan (%s)", dir_path, path);
			is_stable = false;
			continue; /* Continue scanning other files */
		}

		/* Look for temporary files or recent changes */
		if (S_ISREG(info.st_mode)) {
			stats->local_files++;
			stats->local_size += info.st_size; /* Always accumulate size */

			/* Update latest modification time */
			if (info.st_mtime > stats->last_mtime) {
				stats->last_mtime = info.st_mtime;
			}

			/* Check for very recent file modifications (< 1 seconds) */
			if (difftime(current_time, info.st_mtime) < 1.0) {
				log_message(DEBUG, "Directory %s unstable: recent file modification (%s, %.1f seconds ago)",
				            dir_path, dirent->d_name, difftime(current_time, info.st_mtime));
				stats->temp_files = true;
				is_stable = false; /* Mark as unstable but continue scanning */
			}
		} else if (S_ISDIR(info.st_mode)) {
			stats->local_dirs++;

			/* If recursive, check subdirectories */
			if (recursive) {
				stats_t sub_stats;
				if (!scanner_stable(monitor, context, path, &sub_stats, recursive, hidden)) {
					is_stable = false; /* Propagate instability from subdirectories */
				}

				/* Update maximum tree depth based on subdirectory scan results */
				if (sub_stats.depth + 1 > stats->depth) {
					stats->depth = sub_stats.depth + 1;
				}

				/* Check for temp files */
				stats->temp_files |= sub_stats.temp_files;

				/* Update recursive stats by summing up from subdirectories */
				stats->tree_files += sub_stats.tree_files;
				stats->tree_dirs += sub_stats.tree_dirs;
				stats->tree_size += sub_stats.tree_size;

				/* Update max_depth considering subdirectory's max depth */
				if (sub_stats.max_depth + 1 > stats->max_depth) {
					stats->max_depth = sub_stats.max_depth + 1;
				}

				if (sub_stats.last_mtime > stats->last_mtime) {
					stats->last_mtime = sub_stats.last_mtime;
				}
			}
		}
	}

	/* Ensure recursive stats include direct stats at this level */
	stats->tree_files += stats->local_files;
	stats->tree_dirs += stats->local_dirs;
	stats->tree_size += stats->local_size;

	/* If max_depth is not set, use depth */
	if (stats->max_depth == 0 && stats->depth > 0) {
		stats->max_depth = stats->depth;
	}

	closedir(dir);
	return is_stable;
}

/* Synchronize activity states for all watches on a given path */
void scanner_sync(monitor_t *monitor, node_t *node, entity_t *source) {
	if (!node || !source || state_corrupted(source)) {
		if (source && state_corrupted(source)) {
			log_message(WARNING, "Skipping synchronization due to corrupted trigger state");
		}
		return;
	}

	if (!monitor || !monitor->states) {
		log_message(WARNING, "Monitor or state table is null in scanner_sync");
		return;
	}

	/* Calculate bucket hash for this node's path */
	unsigned int hash = states_hash(node->path, monitor->states->bucket_count);

	/* Lock only the specific mutex for this path */
	pthread_mutex_lock(&monitor->states->mutexes[hash]);

	struct timespec sync_time = source->scanner ? source->scanner->latest_time : source->last_time;
	bool path_active = source->scanner ? source->scanner->active : false;
	int max_unstable_count = source->stability ? source->stability->unstable_count : 0;

	/* First pass: Find the most recent activity time and active status */
	for (entity_t *state = node->entities; state; state = state->next) {
		if (state_corrupted(state) || state == source) continue;

		struct timespec state_time = state->scanner ? state->scanner->latest_time : state->last_time;
		if (state_time.tv_sec > sync_time.tv_sec ||
		    (state_time.tv_sec == sync_time.tv_sec &&
		     state_time.tv_nsec > sync_time.tv_nsec)) {
			sync_time = state_time;
		}

		/* If source state is active, merge values from other states */
		bool source_active = source->scanner ? source->scanner->active : false;
		if (source_active) {
			bool state_active = state->scanner ? state->scanner->active : false;
			path_active = path_active || state_active;
			int unstable_count = state->stability ? state->stability->unstable_count : 0;
			if (unstable_count > max_unstable_count) {
				max_unstable_count = unstable_count;
			}
		}
	}

	/* Also update the trigger state's instability count to the max value */
	if (source->stability) {
		source->stability->unstable_count = max_unstable_count;
	}

	/* Second pass: Apply canonical values to ALL entities (including source) */
	for (entity_t *state = node->entities; state; state = state->next) {
		if (state_corrupted(state)) continue;

		watch_t *state_watch = registry_get(monitor->registry, state->watchref);
		log_message(DEBUG, "Synchronizing state for watch %s", state_watch ? state_watch->name : "unknown");

		/* Always share universal directory state regardless of watch configuration */
		state->exists = source->exists;
		state->last_time = source->last_time;
		state->wall_time = source->wall_time;

		/* Update activity state with canonical values */
		if (!state->scanner && path_active) {
			state->scanner = scanner_create(state->node->path);
		}
		if (state->scanner) {
			state->scanner->latest_time = sync_time;
			state->scanner->active = path_active;
		}

		/* Update stability state with canonical values */
		if (!state->stability && max_unstable_count > 0) {
			state->stability = stability_create();
		}
		if (state->stability) {
			state->stability->unstable_count = max_unstable_count;
		}

		/* Synchronize directory statistics - source has canonical stats */
		if (state->kind == ENTITY_DIRECTORY && source->kind == ENTITY_DIRECTORY) {
			watch_t *state_watch = registry_get(monitor->registry, state->watchref);
			watch_t *source_watch = registry_get(monitor->registry, source->watchref);
			bool stats_compatible = (state_watch && source_watch &&
			                         state_watch->recursive == source_watch->recursive &&
			                         state_watch->hidden == source_watch->hidden);

			if (stats_compatible) {
				/* Compatible watches: copy stats from source (canonical) to others */
				if (state != source && source->stability) {
					if (!state->stability) {
						state->stability = stability_create();
					}
					if (state->stability) {
						/* Perform a full copy of the entire stability struct */
						*state->stability = *source->stability;
					}
					log_message(DEBUG, "Shared directory statistics with compatible watch %s", state_watch ? state_watch->name : "unknown");
				}
			} else {
				/* Incompatible watches: each needs its own rescan */
				stats_t new_stats;
				if (scanner_scan(state->node->path, &new_stats, state_watch->recursive, state_watch->hidden)) {
					/* Save previous stats for comparison and update with fresh scan */
					if (!state->stability) {
						state->stability = stability_create();
					}
					if (state->stability) {
						state->stability->prev_stats = state->stability->stats;
						state->stability->stats = new_stats;
					}
					scanner_update(state);
					log_message(DEBUG, "Rescanned directory for incompatible watch %s (recursive=%s, hidden=%s)",
					            state_watch ? state_watch->name : "unknown",
					            state_watch && state_watch->recursive ? "true" : "false",
					            state_watch && state_watch->hidden ? "true" : "false");
				} else {
					log_message(WARNING, "Failed to rescan directory for watch %s during sync", state_watch ? state_watch->name : "unknown");
				}
			}
		}
	}

	/* Unlock the specific mutex */
	pthread_mutex_unlock(&monitor->states->mutexes[hash]);
}

/* Record basic activity in circular buffer and update state */
static void scanner_record(entity_t *state, optype_t optype) {
	/* Create activity state if needed */
	if (!state->scanner) {
		state->scanner = scanner_create(state->node->path);
		if (!state->scanner) return;
	}

	/* Store in circular buffer */
	state->scanner->samples[state->scanner->sample_index].timestamp = state->last_time;
	state->scanner->samples[state->scanner->sample_index].operation = optype;
	state->scanner->sample_index = (state->scanner->sample_index + 1) % MAX_SAMPLES;
	if (state->scanner->sample_count < MAX_SAMPLES) {
		state->scanner->sample_count++;
	}

	/* Reset stability check counter when new activity occurs */
	if (state->stability) {
		state->stability->checks_count = 0;
	}

	/* Update activity timestamp for this state, which is the basis for tree activity time */
	state->scanner->latest_time = state->last_time;

	/* Update the last activity path */
	free(state->scanner->active_path);
	state->scanner->active_path = strdup(state->node->path);
}

/* Update directory stats when content changes */
static void scanner_stats(monitor_t *monitor, entity_t *state, optype_t optype) {
	if (optype == OP_DIR_CONTENT_CHANGED && state->kind == ENTITY_DIRECTORY) {
		/* Update directory stats immediately to reflect the change */
		stats_t new_stats;
		watch_t *watch = registry_get(monitor->registry, state->watchref);
		if (watch && scanner_scan(state->node->path, &new_stats, watch->recursive, watch->hidden)) {
			/* Create stability state if needed */
			if (!state->stability) {
				state->stability = stability_create();
				if (!state->stability) return;
			}

			/* Save previous stats for comparison */
			state->stability->prev_stats = state->stability->stats;
			/* Update with new stats */
			state->stability->stats = new_stats;

			/* Update cumulative changes */
			scanner_update(state);
		}

		if (state->stability) {
			log_message(DEBUG, "Directory stats for %s: files=%d, dirs=%d, max_depth=%d (was: files=%d, dirs=%d, max_depth=%d)",
			            state->node->path, state->stability->stats.tree_files, state->stability->stats.tree_dirs,
			            state->stability->stats.max_depth, state->stability->prev_stats.tree_files,
			            state->stability->prev_stats.tree_dirs, state->stability->prev_stats.max_depth);
		}
	}
}

/* Propagate activity to all parent directories between entity and root */
static void scanner_propagate(monitor_t *monitor, entity_t *state, entity_t *root, optype_t optype, stats_t *root_stats) {
	/* Get watches for state and root */
	watch_t *root_watch = registry_get(monitor->registry, root->watchref);
	if (!root_watch) {
		log_message(WARNING, "Cannot get root watch for scanner propagation");
		return;
	}

	char *path_copy = strdup(state->node->path);
	if (path_copy) {
		/* Get parent directory path */
		char *last_slash = strrchr(path_copy, '/');
		while (last_slash && last_slash > path_copy) {
			*last_slash = '\0'; /* Truncate to get parent directory */

			/* Skip if we've reached or gone beyond the root watch path */
			if (strlen(path_copy) < strlen(root_watch->path)) {
				break;
			}

			/* Update state for this parent directory */
			entity_t *parent = states_get(monitor->states, monitor->registry, path_copy, state->watchref, ENTITY_DIRECTORY);
			if (parent) {
				/* Create activity state if needed */
				if (!parent->scanner) {
					parent->scanner = scanner_create(parent->node->path);
				}
				if (parent->scanner) {
					parent->scanner->latest_time = state->last_time;
					free(parent->scanner->active_path);
					parent->scanner->active_path = strdup(state->node->path);
					parent->scanner->active = true;
				}

				/* Create stability state if needed */
				if (!parent->stability) {
					parent->stability = stability_create();
				}
				if (parent->stability) {
					parent->stability->checks_count = 0;
				}

				/* Reset stability_lost flag when activity becomes active to prevent repeated penalties */
				if (parent->stability) {
					parent->stability->stability_lost = false;
				}

				/* Update directory stats for parent if this is a content change */
				if (optype == OP_DIR_CONTENT_CHANGED && parent->kind == ENTITY_DIRECTORY) {
					/* For recursive watches within the same scope, propagate incremental changes */
					watch_t *parent_watch = registry_get(monitor->registry, parent->watchref);
					watch_t *root_watch_for_scope = registry_get(monitor->registry, root->watchref);
					bool in_scope = (root_stats && parent_watch && root_watch_for_scope &&
					                 parent_watch->recursive &&
					                 parent_watch == root_watch_for_scope &&
					                 strlen(path_copy) >= strlen(root_watch_for_scope->path));

					if (in_scope && root->stability && parent->stability) {
						if (parent != root) {
							/* Calculate incremental changes from root's current update */
							int root_files = root->stability->stats.tree_files - root->stability->prev_stats.tree_files;
							int root_dirs = root->stability->stats.tree_dirs - root->stability->prev_stats.tree_dirs;
							int root_depth = root->stability->stats.max_depth - root->stability->prev_stats.max_depth;
							ssize_t root_size = (ssize_t) root->stability->stats.tree_size - (ssize_t) root->stability->prev_stats.tree_size;

							/* Apply incremental changes to parent while preserving its absolute state */
							parent->stability->prev_stats = parent->stability->stats;
							parent->stability->stats.tree_files += root_files;
							parent->stability->stats.tree_dirs += root_dirs;
							parent->stability->stats.max_depth = (root_depth > 0) ? parent->stability->stats.max_depth + root_depth : parent->stability->stats.max_depth;
							parent->stability->stats.tree_size += root_size;

							/* Update cumulative changes */
							scanner_update(parent);
						}
					} else {
						/* Fall back to scanning for non-recursive or cross-scope parents */
						stats_t parent_new_stats;
						watch_t *parent_watch = registry_get(monitor->registry, parent->watchref);
						if (parent_watch && scanner_scan(parent->node->path, &parent_new_stats, parent_watch->recursive, parent_watch->hidden)) {
							if (!parent->stability) {
								parent->stability = stability_create();
							}
							if (parent->stability) {
								parent->stability->prev_stats = parent->stability->stats;
								parent->stability->stats = parent_new_stats;

								/* Update cumulative changes */
								scanner_update(parent);
							}
						}
					}
				}

				scanner_sync(monitor, parent->node, parent);
			}

			/* Move to next parent directory */
			last_slash = strrchr(path_copy, '/');
		}
		free(path_copy);
	}
}

/* Handle activity recording for recursive watches */
static void scanner_recursive(monitor_t *monitor, entity_t *state, optype_t optype) {
	/* First, find the root state */
	entity_t *root = stability_root(monitor, state);
	if (root) {
		/* Update the root's tree activity time and path */
		if (!root->scanner) {
			root->scanner = scanner_create(root->node->path);
		}
		if (root->scanner) {
			root->scanner->latest_time = state->last_time;
			free(root->scanner->active_path);
			root->scanner->active_path = strdup(state->node->path);
			root->scanner->active = true;
		}

		/* Reset stability_lost flag when activity becomes active to prevent repeated penalties */
		if (!root->stability) {
			root->stability = stability_create();
		}
		if (root->stability) {
			root->stability->stability_lost = false;
			root->stability->checks_count = 0;
		}

		/* For directory operations, update directory stats immediately */
		scanner_stats(monitor, root, optype);

		/* Synchronize with other watches for the same path */
		scanner_sync(monitor, root->node, root);

		/* Now propagate activity to all parent directories between this entity and root */
		stats_t *root_stats = root->stability ? &root->stability->stats : NULL;
		scanner_propagate(monitor, state, root, optype, root_stats);
	}
}

/* Handle activity when state is the root path itself */
static void scanner_root(monitor_t *monitor, entity_t *state, optype_t optype) {
	/* This is the root itself */
	if (!state->scanner) {
		state->scanner = scanner_create(state->node->path);
	}
	if (state->scanner) {
		state->scanner->latest_time = state->last_time;
		free(state->scanner->active_path);
		state->scanner->active_path = strdup(state->node->path);
	}

	/* Update directory stats immediately for content changes to root */
	scanner_stats(monitor, state, optype);

	/* Always sync the current state */
	scanner_sync(monitor, state->node, state);
}

/* Record a new activity event in the entity's history */
void scanner_track(monitor_t *monitor, entity_t *state, optype_t optype) {
	if (!state) return;

	/* Check for duplicate tracking to avoid re-processing the same event */
	if (state->op_time.tv_sec == state->last_time.tv_sec &&
	    state->op_time.tv_nsec == state->last_time.tv_nsec) {
		log_message(DEBUG, "Skipping duplicate track for %s (optype=%d)",
		            state->node ? state->node->path : "NULL", optype);
		return;
	}

	/* Record basic activity in circular buffer */
	scanner_record(state, optype);

	/* Get the watch for this state */
	watch_t *state_watch = registry_get(monitor->registry, state->watchref);
	if (!state_watch) {
		log_message(WARNING, "Cannot get watch for state %s in scanner_track", state->node->path);
		return;
	}

	/* If the event is on a directory that is the root of any watch, handle it */
	if (state->kind == ENTITY_DIRECTORY && strcmp(state->node->path, state_watch->path) == 0) {
		scanner_root(monitor, state, optype);
	}
	/* Otherwise, if it's a recursive watch, it must be a sub-path event */
	else if (state_watch->recursive) {
		scanner_recursive(monitor, state, optype);
	}

	/* Always sync the current state */
	scanner_sync(monitor, state->node, state);

	/* Record the timestamp of this operation to prevent duplicates */
	state->op_time = state->last_time;
}

/* Calculate base quiet period based on recent change magnitude */
static long scanner_base(int recent_files, int recent_dirs, int recent_depth, ssize_t recent_size) {
	int total_change = recent_files + recent_dirs;

	/* Start with a base quiet period based primarily on change magnitude */
	if (total_change == 0 && recent_depth == 0 && recent_size == 0) {
		/* No change - minimal quiet period */
		return 250;
	} else if (total_change < 5 && recent_depth == 0 && recent_size < 1024 * 1024) {
		/* Few files change with no structural changes and small size changes - short quiet period */
		return 500;
	} else if (total_change < 10 && recent_depth == 0 && recent_size < 10 * 1024 * 1024) {
		/* Several files changed, no structural changes, moderate size changes - modest quiet period */
		return 1000;
	} else if (total_change < 10 && recent_depth == 0 && recent_size < 100 * 1024 * 1024) {
		/* Few files changed, no structural changes, but large size changes (10-100MB) - longer quiet period */
		return 1500;
	} else if (recent_depth > 0 || recent_size > 100 * 1024 * 1024) {
		/* Structural depth changes or large size changes - significant quiet period */
		int size_factor = (recent_size > 100 * 1024 * 1024) ? (int) (recent_size / (100 * 1024 * 1024)) : 0;
		return 1500 + (recent_depth * 500) + (size_factor * 250);
	} else if (total_change < 10) {
		/* Moderate changes - medium quiet period */
		return 1250;
	} else {
		/* Many changes - longer quiet period */
		return 2000 + (total_change / 10) * 250;
	}
}

/* Calculate current activity magnitude (changes from reference state) for responsive adjustments */
static void scanner_recent(entity_t *state, int *recent_files, int *recent_dirs, int *recent_depth, ssize_t *recent_size) {
	/* Calculate changes from the previous scan state to measure the current rate of change */
	if (state->stability) {
		*recent_depth = abs(state->stability->stats.max_depth - state->stability->prev_stats.max_depth);
		*recent_files = abs(state->stability->stats.tree_files - state->stability->prev_stats.tree_files);
		*recent_dirs = abs(state->stability->stats.tree_dirs - state->stability->prev_stats.tree_dirs);
		*recent_size = labs((ssize_t) state->stability->stats.tree_size - (ssize_t) state->stability->prev_stats.tree_size);
	} else {
		*recent_depth = 0;
		*recent_files = 0;
		*recent_dirs = 0;
		*recent_size = 0;
	}
}

/* Apply stability, depth, and size adjustments to quiet period */
static long scanner_adjust(entity_t *state, long base_ms) {
	long required_ms = base_ms;
	int tree_entries = 0;
	int tree_depth = 0;

	if (state->stability) {
		tree_entries = state->stability->stats.tree_files + state->stability->stats.tree_dirs;
		tree_depth = state->stability->stats.max_depth > 0 ? state->stability->stats.max_depth : state->stability->stats.depth;
	}

	/* Use current activity magnitude for responsiveness */
	int recent_files, recent_dirs, recent_depth;
	ssize_t recent_size;
	scanner_recent(state, &recent_files, &recent_dirs, &recent_depth, &recent_size);
	/* Calculate comprehensive activity magnitude including depth and size changes */
	int size_weight = 0;
	if (recent_size > 100 * 1024 * 1024) {
		size_weight = (int) (recent_size / (100 * 1024 * 1024)); /* 1 point per 100MB */
	} else if (recent_size > 10 * 1024 * 1024) {
		size_weight = 1; /* 1 point for 10-100MB */
	} else if (recent_size > 1024 * 1024) {
		size_weight = 0; /* No weight for 1-10MB */
	}
	int recent_change = recent_files + recent_dirs + recent_depth + size_weight;

	/* Log recent activity calculation */
	log_message(DEBUG, "Recent activity for %s: files=%d, dirs=%d, depth=%d, size=%s, size_weight=%d (total_change=%d)",
	            state->node->path, recent_files, recent_dirs, recent_depth,
	            format_size(recent_size, true), size_weight, recent_change);

	if (state->stability) {
		/* Calculate a cumulative magnitude factor to scale the quiet period */
		ssize_t cumulative_size = state->stability->delta_size > 0 ? state->stability->delta_size : 0;
		int cumulative_size_weight = (int) (cumulative_size / (100 * 1024 * 1024)); /* 1 point per 100MB */

		int cumulative_magnitude = abs(state->stability->delta_files) +
		                           abs(state->stability->delta_dirs) +
		                           abs(state->stability->delta_depth) +
		                           cumulative_size_weight;

		/* Only apply the multiplier if the cumulative change is significant */
		if (cumulative_magnitude > 100) {
			float magnitude_factor = 1.0 + (cumulative_magnitude / 50.0);

			/* Cap the factor to prevent excessively long quiet periods */
			if (magnitude_factor > 5.0) {
				magnitude_factor = 5.0;
			}

			long pre_magnitude = required_ms;
			required_ms = (long) (required_ms * magnitude_factor);
			log_message(DEBUG, "Applied magnitude factor %.2f: %ld ms -> %ld ms",
			            magnitude_factor, pre_magnitude, required_ms);
		}
	}

	/* If stability was previously achieved and then lost, increase quiet period */
	if (state->stability && state->stability->stability_lost) {
		/* We need a more careful check for resumed activity */
		long pre_stability = required_ms;
		required_ms = (long) (required_ms * 1.25); /* 25% increase */
		log_message(DEBUG, "Applied stability loss penalty: %ld ms -> %ld ms",
		            pre_stability, required_ms);
	}

	/* Tree depth multiplier - based on recent activity rate */
	if (tree_depth > 0) {
		/* Scale down the depth impact for simple operations */
		float depth_factor = (recent_change <= 1) ? 0.5 : 1.0;
		required_ms += tree_depth * 150 * depth_factor; /* 150ms per level */
	}

	/* Directory size complexity factor - based on recent activity */
	if (tree_entries > 100) {
		float size_factor = (recent_change <= 3) ? 0.3 : 0.7;
		int size_addition = (int) (250 * size_factor * (tree_entries / 200.0));
		/* Cap the size adjustment for small operations */
		if (recent_change <= 1 && size_addition > 300) size_addition = 300;
		required_ms += size_addition;
	}

	return required_ms;
}

/* Apply exponential backoff for consecutive instability */
static long scanner_backoff(entity_t *state, long required_ms) {
	int unstable_count = state->stability ? state->stability->unstable_count : 0;

	if (unstable_count < 3) {
		/* Only apply backoff after 3 consecutive unstable counts */
		return required_ms;
	}

	/* Start with a base multiplier */
	double backoff_factor = 1.0;

	/* Increase backoff factor for repeated instability after 3 consecutive unstable counts */
	for (int i = 3; i <= unstable_count; i++) {
		backoff_factor *= 1.25;
	}

	/* Apply a cap to the backoff factor to prevent excessive delays */
	if (backoff_factor > 5.0) {
		backoff_factor = 5.0;
	}

	long adjusted_ms = (long) (required_ms * backoff_factor);
	log_message(DEBUG, "Applied backoff factor %.2f: %ld ms -> %ld ms",
	            backoff_factor, required_ms, adjusted_ms);

	return adjusted_ms;
}

/* Apply final limits and complexity multiplier */
static long scanner_limit(monitor_t *monitor, entity_t *state, long required_ms) {
	/* Set reasonable limits */
	if (required_ms < 100) required_ms = 100;

	/* Dynamic cap based on operation characteristics */
	long maximum_ms = 90000; /* Default 90 seconds */

	if (required_ms > maximum_ms) {
		log_message(DEBUG, "Capping quiet period for %s from %ld ms to %ld ms",
		            state->node->path, required_ms, maximum_ms);
		required_ms = maximum_ms;
	}

	/* Apply complexity multiplier from watch config */
	watch_t *state_watch = registry_get(monitor->registry, state->watchref);
	if (state_watch && state_watch->complexity > 0) {
		long pre_multiplier = required_ms;
		required_ms = (long) (required_ms * state_watch->complexity);
		log_message(DEBUG, "Applied complexity multiplier %.2f to %s: %ld ms -> %ld ms",
		            state_watch->complexity, state->node->path, pre_multiplier, required_ms);
	}

	return required_ms;
}

/* Determine the required quiet period based on state type and activity */
long scanner_delay(monitor_t *monitor, entity_t *state) {
	if (!state) return QUIET_PERIOD_MS;

	long required_ms = QUIET_PERIOD_MS;

	/* Use a longer base period for directories */
	if (state->kind == ENTITY_DIRECTORY) {
		/* Default quiet period */
		required_ms = DIR_QUIET_PERIOD_MS; /* Default 1000ms */

		/* For active directories, use adaptive complexity measurement */
		bool active = state->scanner ? state->scanner->active : false;
		if (active) {
			/* Extract complexity indicators */
			int tree_entries = 0;
			int tree_depth = 0;
			if (state->stability) {
				tree_entries = state->stability->stats.tree_files + state->stability->stats.tree_dirs;
				tree_depth = state->stability->stats.max_depth > 0 ? state->stability->stats.max_depth : state->stability->stats.depth;
			}

			/* Get recent activity to drive the base period calculation */
			int recent_files, recent_dirs, recent_depth;
			ssize_t recent_size;
			scanner_recent(state, &recent_files, &recent_dirs, &recent_depth, &recent_size);

			/* Calculate base period from recent change magnitude */
			required_ms = scanner_base(recent_files, recent_dirs, recent_depth, recent_size);

			/* Apply stability adjustments (depth, size, stability loss) */
			required_ms = scanner_adjust(state, required_ms);

			/* Apply exponential backoff for consecutive instability */
			required_ms = scanner_backoff(state, required_ms);

			int delta_files = state->stability ? state->stability->delta_files : 0;
			int delta_dirs = state->stability ? state->stability->delta_dirs : 0;
			int delta_depth = state->stability ? state->stability->delta_depth : 0;
			ssize_t delta_size = state->stability ? state->stability->delta_size : 0;

			log_message(DEBUG, "Quiet period for %s: %ld ms (cumulative: %+d files, %+d dirs, %+d depth, %s size) (total: %d entries, %d depth)",
			            state->node->path, required_ms, delta_files, delta_dirs, delta_depth,
			            format_size(delta_size, true), tree_entries, tree_depth);
		} else {
			/* For inactive directories, just log the base period with recursive stats */
			int tree_entries = 0;
			int tree_depth = 0;
			int num_subdir = 0;
			if (state->stability) {
				tree_entries = state->stability->stats.tree_files + state->stability->stats.tree_dirs;
				tree_depth = state->stability->stats.max_depth > 0 ? state->stability->stats.max_depth : state->stability->stats.depth;
				num_subdir = state->stability->stats.tree_dirs;
			}

			log_message(DEBUG, "Using base quiet period for %s: %ld ms (recursive entries: %d, depth: %d, subdirs: %d)",
			            state->node->path, required_ms, tree_entries, tree_depth, num_subdir);
		}
	}

	/* Apply final limits and complexity multiplier */
	return scanner_limit(monitor, state, required_ms);
}

/* Check if enough quiet time has passed since the last activity */
bool scanner_ready(monitor_t *monitor, entity_t *state, struct timespec *current_time, long required_quiet) {
	if (!state || !current_time) return true; /* Cannot check, assume elapsed */

	struct timespec *scanner_time = NULL;
	const char *source_path = state->node->path;

	/* Get the watch for timestamp checking */
	watch_t *state_watch = registry_get(monitor->registry, state->watchref);

	/* Determine which timestamp to check against */
	if (state->kind == ENTITY_DIRECTORY && state_watch && state_watch->recursive) {
		/* For recursive directory watches, always check the root's tree time */
		entity_t *root = stability_root(monitor, state);
		if (root) {
			scanner_time = root->scanner ? &root->scanner->latest_time : &root->last_time;
			source_path = root->node->path;
		} else {
			log_message(WARNING, "Cannot find root state for %s, falling back to local activity", state->node->path);
			/* Fallback: use local activity if root not found */
			if (!state->scanner || state->scanner->sample_count == 0) return true;
			int latest_idx = (state->scanner->sample_index + MAX_SAMPLES - 1) % MAX_SAMPLES;
			scanner_time = &state->scanner->samples[latest_idx].timestamp;
		}
	} else {
		/* For files or non-recursive dirs, use local activity time */
		if (!state->scanner || state->scanner->sample_count == 0) return true;
		int latest_idx = (state->scanner->sample_index + MAX_SAMPLES - 1) % MAX_SAMPLES;
		scanner_time = &state->scanner->samples[latest_idx].timestamp;
	}

	/* Check for valid timestamp */
	if (!scanner_time || (scanner_time->tv_sec == 0 && scanner_time->tv_nsec == 0)) {
		log_message(DEBUG, "No valid activity timestamp for %s, quiet period assumed elapsed", state->node->path);
		return true;
	}

	/* Calculate elapsed time */
	long elapsed_ms;
	if (current_time->tv_sec < scanner_time->tv_sec ||
	    (current_time->tv_sec == scanner_time->tv_sec && current_time->tv_nsec < scanner_time->tv_nsec)) {
		elapsed_ms = -1; /* Clock went backwards */
	} else {
		struct timespec diff_time;
		diff_time.tv_sec = current_time->tv_sec - scanner_time->tv_sec;
		if (current_time->tv_nsec >= scanner_time->tv_nsec) {
			diff_time.tv_nsec = current_time->tv_nsec - scanner_time->tv_nsec;
		} else {
			diff_time.tv_sec--;
			diff_time.tv_nsec = 1000000000 + current_time->tv_nsec - scanner_time->tv_nsec;
		}
		elapsed_ms = diff_time.tv_sec * 1000 + diff_time.tv_nsec / 1000000;
	}

	if (elapsed_ms < 0) {
		log_message(WARNING, "Clock appears to have moved backwards for %s, assuming quiet period elapsed",
		            state->node->path);
		return true;
	}

	bool elapsed = elapsed_ms >= required_quiet;

	if (!elapsed) {
		log_message(DEBUG, "Quiet period check for %s: %ld ms elapsed < %ld ms required (using time from %s)",
		            state->node->path, elapsed_ms, required_quiet, source_path);
	} else {
		log_message(DEBUG, "Quiet period elapsed for %s: %ld ms >= %ld ms required",
		            state->node->path, elapsed_ms, required_quiet);
	}

	return elapsed;
}

/* Find the most recently modified file in a directory */
char *scanner_newest(const char *dir_path) {
	DIR *dir;
	struct dirent *dirent;
	struct stat info;
	char path[PATH_MAX];
	char *newest_file = NULL;
	time_t newest_time = 0;

	dir = opendir(dir_path);
	if (!dir) {
		return NULL;
	}

	while ((dirent = readdir(dir))) {
		if (strcmp(dirent->d_name, ".") == 0 || strcmp(dirent->d_name, "..") == 0) {
			continue;
		}

		/* Skip .DS_Store files created by macOS */
		if (strcmp(dirent->d_name, ".DS_Store") == 0) {
			continue;
		}

		snprintf(path, sizeof(path), "%s/%s", dir_path, dirent->d_name);
		if (stat(path, &info) == 0) {
			/* Consider both modification time and change time */
			time_t latest_time = (info.st_mtime > info.st_ctime) ? info.st_mtime : info.st_ctime;
			if (latest_time > newest_time) {
				newest_time = latest_time;
				free(newest_file);
				newest_file = strdup(path);
			}
		}
	}

	closedir(dir);
	return newest_file;
}

/* Find all files modified since a specific time */
char *scanner_modified(const char *base_path, time_t since_time, bool recursive, bool basename) {
	DIR *dir;
	struct dirent *dirent;
	struct stat info;
	char path[PATH_MAX];
	char *result = NULL;
	size_t result_size = 0;
	size_t result_capacity = 1024;

	if (!base_path) {
		return NULL;
	}

	/* Allocate initial buffer */
	result = malloc(result_capacity);
	if (!result) {
		return NULL;
	}
	result[0] = '\0';

	dir = opendir(base_path);
	if (!dir) {
		free(result);
		return NULL;
	}

	while ((dirent = readdir(dir))) {
		if (strcmp(dirent->d_name, ".") == 0 || strcmp(dirent->d_name, "..") == 0) {
			continue;
		}

		/* Skip .DS_Store files created by macOS */
		if (strcmp(dirent->d_name, ".DS_Store") == 0) {
			continue;
		}

		snprintf(path, sizeof(path), "%s/%s", base_path, dirent->d_name);
		if (stat(path, &info) != 0) {
			continue;
		}

		if (S_ISREG(info.st_mode)) {
			/* Consider both modification time and change time */
			time_t latest_time = (info.st_mtime > info.st_ctime) ? info.st_mtime : info.st_ctime;
			if (latest_time > since_time) {
				/* Add this file to the result */
				const char *output_name = basename ? dirent->d_name : path;
				size_t name_len = strlen(output_name);
				size_t required_size = result_size + name_len + 2; /* +2 for newline and null terminator */

				if (required_size > result_capacity) {
					result_capacity = required_size * 2;
					char *new_result = realloc(result, result_capacity);
					if (!new_result) {
						free(result);
						closedir(dir);
						return NULL;
					}
					result = new_result;
				}

				if (result_size > 0) {
					result[result_size] = '\n';
					result_size++;
				}
				strcpy(result + result_size, output_name);
				result_size += name_len;
			}
		} else if (S_ISDIR(info.st_mode) && recursive) {
			/* Recursively scan subdirectory */
			char *subdir_result = scanner_modified(path, since_time, recursive, basename);
			if (subdir_result && strlen(subdir_result) > 0) {
				size_t subdir_len = strlen(subdir_result);
				size_t required_size = result_size + subdir_len + 2; /* +2 for newline and null terminator */

				if (required_size > result_capacity) {
					result_capacity = required_size * 2;
					char *new_result = realloc(result, result_capacity);
					if (!new_result) {
						free(result);
						free(subdir_result);
						closedir(dir);
						return NULL;
					}
					result = new_result;
				}

				if (result_size > 0) {
					result[result_size] = '\n';
					result_size++;
				}
				strcpy(result + result_size, subdir_result);
				result_size += subdir_len;
			}
			free(subdir_result);
		}
	}

	closedir(dir);
	return result;
}
