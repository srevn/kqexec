#include "scanner.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "events.h"
#include "logger.h"
#include "monitor.h"
#include "stability.h"
#include "states.h"

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
void scanner_update(group_t *group, const char *path) {
	if (!group || !group->stability) return;

	/* Calculate incremental changes */
	int new_files, new_dirs, new_depth;
	ssize_t new_size;

	/* Calculate the difference from previous stats */
	new_files = group->stability->stats.tree_files - group->stability->prev_stats.tree_files;
	new_dirs = group->stability->stats.tree_dirs - group->stability->prev_stats.tree_dirs;
	new_depth = group->stability->stats.max_depth - group->stability->prev_stats.max_depth;
	new_size = (ssize_t) group->stability->stats.tree_size - (ssize_t) group->stability->prev_stats.tree_size;

	/* Accumulate changes */
	group->stability->delta_files += new_files;
	group->stability->delta_dirs += new_dirs;
	group->stability->delta_depth += new_depth;
	group->stability->delta_size += new_size;

	/* Set flag indicating stability was lost if we're detecting new changes */
	bool active = group->scanner ? group->scanner->active : false;
	if (!active && (new_files != 0 || new_dirs != 0 || new_depth != 0 || new_size != 0)) {
		group->stability->stability_lost = true;
	}

	/* Log significant cumulative changes */
	if (new_files != 0 || new_dirs != 0 || new_depth != 0 || new_size != 0) {
		log_message(DEBUG, "Updated cumulative changes for %s: files=%+d (%+d), dirs=%+d (%+d), depth=%+d (%+d), size=%s (%s)",
					path, group->stability->delta_files, new_files, group->stability->delta_dirs, new_dirs,
					group->stability->delta_depth, new_depth, format_size(group->stability->delta_size, true),
					format_size(new_size, true));
	}
}

/* Gather basic directory statistics */
bool scanner_scan(const char *dir_path, const watch_t *watch, stats_t *stats) {
	DIR *dir;
	struct dirent *dirent;
	struct stat info;
	char path[PATH_MAX];

	if (!dir_path || !stats) {
		return false;
	}

	/* Extract flags from watch with correct defaults */
	bool recursive = watch ? watch->recursive : true; /* Default: recursive for directories */
	bool hidden = watch ? watch->hidden : false;	  /* Default: exclude hidden files */

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

		/* Skip excluded paths */
		if (watch && config_exclude_match(watch, path)) {
			continue;
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
				if (scanner_scan(path, watch, &sub_stats)) {
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
bool scanner_stable(monitor_t *monitor, node_t *node, const char *dir_path, const watch_t *watch, stats_t *stats) {
	DIR *dir;
	struct dirent *dirent;
	struct stat info;
	char path[PATH_MAX];
	bool is_stable = true; /* Assume stable until proven otherwise */

	if (!dir_path || !stats || !node) {
		return false;
	}

	/* Extract flags from watch with sensible defaults */
	bool recursive = watch ? watch->recursive : true; /* Default: recursive for directories */
	bool hidden = watch ? watch->hidden : false;	  /* Default: exclude hidden files */

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

		/* Skip excluded paths */
		if (watch && config_exclude_match(watch, path)) {
			continue;
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
				if (!scanner_stable(monitor, node, path, watch, &sub_stats)) {
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

/* Record basic activity in circular buffer and update state */
static void scanner_record(group_t *group, struct timespec timestamp, const char *path, optype_t optype) {
	/* Create activity state if needed */
	if (!group->scanner) {
		group->scanner = scanner_create(path);
		if (!group->scanner) return;
	}

	/* Store in circular buffer */
	group->scanner->samples[group->scanner->sample_index].timestamp = timestamp;
	group->scanner->samples[group->scanner->sample_index].operation = optype;
	group->scanner->sample_index = (group->scanner->sample_index + 1) % MAX_SAMPLES;
	if (group->scanner->sample_count < MAX_SAMPLES) {
		group->scanner->sample_count++;
	}

	/* Reset stability check counter when new activity occurs */
	if (group->stability) {
		group->stability->checks_count = 0;
	}

	/* Update activity timestamp for this group, which is the basis for tree activity time */
	group->scanner->latest_time = timestamp;

	/* Update the last activity path */
	free(group->scanner->active_path);
	group->scanner->active_path = strdup(path);
}

/* Update directory stats when content changes */
static void scanner_stats(monitor_t *monitor, entity_t *state, optype_t optype) {
	if (optype == OP_DIR_CONTENT_CHANGED && state->node->kind == ENTITY_DIRECTORY) {
		/* Update directory stats immediately to reflect the change */
		stats_t new_stats;
		watch_t *watch = registry_get(monitor->registry, state->watchref);
		if (watch && scanner_scan(state->node->path, watch, &new_stats)) {
			/* Create stability state if needed */
			if (!state->group->stability) {
				state->group->stability = stability_create();
				if (!state->group->stability) return;
			}

			/* Save previous stats for comparison */
			state->group->stability->prev_stats = state->group->stability->stats;
			/* Update with new stats */
			state->group->stability->stats = new_stats;

			/* Update cumulative changes */
			scanner_update(state->group, state->node->path);
		}

		if (state->group->stability) {
			log_message(DEBUG, "Directory stats for %s: files=%d, dirs=%d, max_depth=%d (was: files=%d, dirs=%d, max_depth=%d)",
						state->node->path, state->group->stability->stats.tree_files, state->group->stability->stats.tree_dirs,
						state->group->stability->stats.max_depth, state->group->stability->prev_stats.tree_files,
						state->group->stability->prev_stats.tree_dirs, state->group->stability->prev_stats.max_depth);
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
				if (!parent->group->scanner) {
					parent->group->scanner = scanner_create(parent->node->path);
				}
				if (parent->group->scanner) {
					parent->group->scanner->latest_time = state->node->last_time;
					free(parent->group->scanner->active_path);
					parent->group->scanner->active_path = strdup(state->node->path);
					parent->group->scanner->active = true;
				}

				/* Create stability state if needed */
				if (!parent->group->stability) {
					parent->group->stability = stability_create();
				}
				if (parent->group->stability) {
					parent->group->stability->checks_count = 0;
				}

				/* Reset stability_lost flag when activity becomes active to prevent repeated penalties */
				if (parent->group->stability) {
					parent->group->stability->stability_lost = false;
				}

				/* Update directory stats for parent if this is a content change */
				if (optype == OP_DIR_CONTENT_CHANGED && parent->node->kind == ENTITY_DIRECTORY) {
					/* For recursive watches within the same scope, propagate incremental changes */
					watch_t *parent_watch = registry_get(monitor->registry, parent->watchref);
					watch_t *root_watch_for_scope = registry_get(monitor->registry, root->watchref);
					bool in_scope = (root_stats && parent_watch && root_watch_for_scope &&
									 parent_watch->recursive && parent_watch == root_watch_for_scope &&
									 strlen(path_copy) >= strlen(root_watch_for_scope->path));

					if (in_scope && root->group->stability && parent->group->stability) {
						if (parent != root) {
							/* Calculate incremental changes from root's current update */
							int root_files = root->group->stability->stats.tree_files - root->group->stability->prev_stats.tree_files;
							int root_dirs = root->group->stability->stats.tree_dirs - root->group->stability->prev_stats.tree_dirs;
							int root_depth = root->group->stability->stats.max_depth - root->group->stability->prev_stats.max_depth;
							ssize_t root_size = (ssize_t) root->group->stability->stats.tree_size - (ssize_t) root->group->stability->prev_stats.tree_size;

							/* Apply incremental changes to parent while preserving its absolute state */
							parent->group->stability->prev_stats = parent->group->stability->stats;
							parent->group->stability->stats.tree_files += root_files;
							parent->group->stability->stats.tree_dirs += root_dirs;
							parent->group->stability->stats.max_depth = (root_depth > 0) ? parent->group->stability->stats.max_depth + root_depth : parent->group->stability->stats.max_depth;
							parent->group->stability->stats.tree_size += root_size;

							/* Update cumulative changes */
							scanner_update(parent->group, parent->node->path);
						}
					} else {
						/* Fall back to scanning for non-recursive or cross-scope parents */
						stats_t parent_new_stats;
						watch_t *parent_watch = registry_get(monitor->registry, parent->watchref);
						if (parent_watch && scanner_scan(parent->node->path, parent_watch, &parent_new_stats)) {
							if (!parent->group->stability) {
								parent->group->stability = stability_create();
							}
							if (parent->group->stability) {
								parent->group->stability->prev_stats = parent->group->stability->stats;
								parent->group->stability->stats = parent_new_stats;

								/* Update cumulative changes */
								scanner_update(parent->group, parent->node->path);
							}
						}
					}
				}
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
		if (!root->group->scanner) {
			root->group->scanner = scanner_create(root->node->path);
		}
		if (root->group->scanner) {
			root->group->scanner->latest_time = state->node->last_time;
			free(root->group->scanner->active_path);
			root->group->scanner->active_path = strdup(state->node->path);
			root->group->scanner->active = true;
		}

		/* Reset stability_lost flag when activity becomes active to prevent repeated penalties */
		if (!root->group->stability) {
			root->group->stability = stability_create();
		}
		if (root->group->stability) {
			root->group->stability->stability_lost = false;
			root->group->stability->checks_count = 0;
		}

		/* For directory operations, update directory stats immediately */
		scanner_stats(monitor, root, optype);

		/* Now propagate activity to all parent directories between this entity and root */
		stats_t *root_stats = root->group->stability ? &root->group->stability->stats : NULL;
		scanner_propagate(monitor, state, root, optype, root_stats);
	}
}

/* Handle activity when state is the root path itself */
static void scanner_root(monitor_t *monitor, entity_t *state, optype_t optype) {
	/* This is the root itself */
	if (!state->group->scanner) {
		state->group->scanner = scanner_create(state->node->path);
	}
	if (state->group->scanner) {
		state->group->scanner->latest_time = state->node->last_time;
		free(state->group->scanner->active_path);
		state->group->scanner->active_path = strdup(state->node->path);
	}

	/* Update directory stats immediately for content changes to root */
	scanner_stats(monitor, state, optype);
}

/* Record a new activity event in the entity's history */
void scanner_track(monitor_t *monitor, entity_t *state, optype_t optype) {
	if (!state || !state->group) return;

	/* Check for duplicate tracking to avoid re-processing the same event */
	if (state->node->op_time.tv_sec == state->node->last_time.tv_sec && state->node->op_time.tv_nsec == state->node->last_time.tv_nsec) {
		log_message(DEBUG, "Skipping duplicate track for %s (optype=%d)",
					state->node ? state->node->path : "NULL", optype);
		return;
	}

	/* Lock the group mutex to protect shared state */
	pthread_mutex_lock(&state->group->mutex);

	/* Record basic activity in circular buffer */
	scanner_record(state->group, state->node->last_time, state->node->path, optype);

	/* Get the watch for this state */
	watch_t *state_watch = registry_get(monitor->registry, state->watchref);
	if (!state_watch) {
		log_message(WARNING, "Cannot get watch for state %s in scanner_track", state->node->path);
		pthread_mutex_unlock(&state->group->mutex);
		return;
	}

	/* If the event is on a directory that is the root of any watch, handle it */
	if (state->node->kind == ENTITY_DIRECTORY && strcmp(state->node->path, state_watch->path) == 0) {
		scanner_root(monitor, state, optype);
	}
	/* Otherwise, if it's a recursive watch, it must be a sub-path event */
	else if (state_watch->recursive) {
		scanner_recursive(monitor, state, optype);
	}

	/* Record the timestamp of this operation to prevent duplicates */
	state->node->op_time = state->node->last_time;

	/* Unlock the group mutex */
	pthread_mutex_unlock(&state->group->mutex);
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
	if (state->group->stability) {
		*recent_depth = abs(state->group->stability->stats.max_depth - state->group->stability->prev_stats.max_depth);
		*recent_files = abs(state->group->stability->stats.tree_files - state->group->stability->prev_stats.tree_files);
		*recent_dirs = abs(state->group->stability->stats.tree_dirs - state->group->stability->prev_stats.tree_dirs);
		*recent_size = labs((ssize_t) state->group->stability->stats.tree_size - (ssize_t) state->group->stability->prev_stats.tree_size);
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

	if (state->group->stability) {
		tree_entries = state->group->stability->stats.tree_files + state->group->stability->stats.tree_dirs;
		tree_depth = state->group->stability->stats.max_depth > 0 ? state->group->stability->stats.max_depth : state->group->stability->stats.depth;
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

	if (state->group->stability) {
		/* Calculate a cumulative magnitude factor to scale the quiet period */
		ssize_t cumulative_size = state->group->stability->delta_size > 0 ? state->group->stability->delta_size : 0;
		int cumulative_size_weight = (int) (cumulative_size / (100 * 1024 * 1024)); /* 1 point per 100MB */

		int cumulative_magnitude = abs(state->group->stability->delta_files) + abs(state->group->stability->delta_dirs) +
								   abs(state->group->stability->delta_depth) + cumulative_size_weight;

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
	if (state->group->stability && state->group->stability->stability_lost) {
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
	int unstable_count = state->group->stability ? state->group->stability->unstable_count : 0;

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
	if (state->node->kind == ENTITY_DIRECTORY) {
		/* Default quiet period */
		required_ms = DIR_QUIET_PERIOD_MS; /* Default 1000ms */

		/* For active directories, use adaptive complexity measurement */
		bool active = state->group->scanner ? state->group->scanner->active : false;
		if (active) {
			/* Extract complexity indicators */
			int tree_entries = 0;
			int tree_depth = 0;
			if (state->group->stability) {
				tree_entries = state->group->stability->stats.tree_files + state->group->stability->stats.tree_dirs;
				tree_depth = state->group->stability->stats.max_depth > 0 ? state->group->stability->stats.max_depth : state->group->stability->stats.depth;
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

			int delta_files = state->group->stability ? state->group->stability->delta_files : 0;
			int delta_dirs = state->group->stability ? state->group->stability->delta_dirs : 0;
			int delta_depth = state->group->stability ? state->group->stability->delta_depth : 0;
			ssize_t delta_size = state->group->stability ? state->group->stability->delta_size : 0;

			log_message(DEBUG, "Quiet period for %s: %ld ms (cumulative: %+d files, %+d dirs, %+d depth, %s size) (total: %d entries, %d depth)",
						state->node->path, required_ms, delta_files, delta_dirs, delta_depth,
						format_size(delta_size, true), tree_entries, tree_depth);
		} else {
			/* For inactive directories, just log the base period with recursive stats */
			int tree_entries = 0;
			int tree_depth = 0;
			int num_subdir = 0;
			if (state->group->stability) {
				tree_entries = state->group->stability->stats.tree_files + state->group->stability->stats.tree_dirs;
				tree_depth = state->group->stability->stats.max_depth > 0 ? state->group->stability->stats.max_depth : state->group->stability->stats.depth;
				num_subdir = state->group->stability->stats.tree_dirs;
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
	if (state->node->kind == ENTITY_DIRECTORY && state_watch && state_watch->recursive) {
		/* For recursive directory watches, always check the root's tree time */
		entity_t *root = stability_root(monitor, state);
		if (root) {
			scanner_time = root->group->scanner ? &root->group->scanner->latest_time : &root->node->last_time;
			source_path = root->node->path;
		} else {
			log_message(WARNING, "Cannot find root state for %s, falling back to local activity", state->node->path);
			/* Fallback: use local activity if root not found */
			if (!state->group->scanner || state->group->scanner->sample_count == 0) return true;
			int latest_idx = (state->group->scanner->sample_index + MAX_SAMPLES - 1) % MAX_SAMPLES;
			scanner_time = &state->group->scanner->samples[latest_idx].timestamp;
		}
	} else {
		/* For files or non-recursive dirs, use local activity time */
		if (!state->group->scanner || state->group->scanner->sample_count == 0) return true;
		int latest_idx = (state->group->scanner->sample_index + MAX_SAMPLES - 1) % MAX_SAMPLES;
		scanner_time = &state->group->scanner->samples[latest_idx].timestamp;
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
char *scanner_newest(const char *dir_path, const watch_t *watch) {
	if (!dir_path) {
		return NULL;
	}

	DIR *dir = opendir(dir_path);
	if (!dir) {
		if (errno != ENOENT) {
			log_message(WARNING, "Cannot open directory %s: %s", dir_path, strerror(errno));
		}
		return NULL;
	}

	char *newest_file = NULL;
	time_t newest_time = 0;
	struct dirent *dirent;

	while ((dirent = readdir(dir))) {
		if (strcmp(dirent->d_name, ".") == 0 || strcmp(dirent->d_name, "..") == 0) {
			continue;
		}

		char path[PATH_MAX];
		int path_len = snprintf(path, sizeof(path), "%s/%s", dir_path, dirent->d_name);

		/* Check for path truncation */
		if (path_len >= (int) sizeof(path)) {
			log_message(WARNING, "Path too long, skipping: %s/%s", dir_path, dirent->d_name);
			continue;
		}

		/* Perform exclusion check early for clarity */
		if (watch && config_exclude_match(watch, path)) {
			continue;
		}

		struct stat info;
		if (stat(path, &info) == 0) {
			/* Use the most recent of modification or status change time */
			time_t latest_time = (info.st_mtime > info.st_ctime) ? info.st_mtime : info.st_ctime;
			if (latest_time > newest_time) {
				newest_time = latest_time;
				free(newest_file);
				newest_file = strdup(path);
				if (!newest_file) {
					log_message(ERROR, "Failed to allocate memory for newest file path");
				}
			}
		}
	}

	closedir(dir);
	return newest_file;
}

/* Find all files modified since a specific time */
char *scanner_modified(const char *base_path, const watch_t *watch, time_t since_time, bool recursive, bool basename) {
	if (!base_path) {
		return NULL;
	}

	DIR *dir = opendir(base_path);
	if (!dir) {
		/* Log the error for better diagnostics, but don't spam for deleted dirs */
		if (errno != ENOENT) {
			log_message(WARNING, "Cannot open directory %s: %s", base_path, strerror(errno));
		}
		return NULL;
	}

	/* Start with a reasonable initial capacity to avoid frequent reallocations */
	size_t result_capacity = 2048;
	char *result = malloc(result_capacity);
	if (!result) {
		log_message(ERROR, "Failed to allocate initial buffer for modified file list");
		closedir(dir);
		return NULL;
	}
	result[0] = '\0';
	size_t result_size = 0;

	struct dirent *dirent;
	while ((dirent = readdir(dir))) {
		/* Always skip current and parent directory entries */
		if (strcmp(dirent->d_name, ".") == 0 || strcmp(dirent->d_name, "..") == 0) {
			continue;
		}

		char path[PATH_MAX];
		int path_len = snprintf(path, sizeof(path), "%s/%s", base_path, dirent->d_name);

		/* Check for path truncation */
		if (path_len >= (int) sizeof(path)) {
			log_message(WARNING, "Path too long, skipping: %s/%s", base_path, dirent->d_name);
			continue;
		}

		/* Perform exclusion check early */
		if (watch && config_exclude_match(watch, path)) {
			continue;
		}

		struct stat info;
		if (stat(path, &info) != 0) {
			/* File could have been deleted between readdir() and stat() */
			continue;
		}

		/* Handle files */
		if (S_ISREG(info.st_mode)) {
			/* Use the most recent of modification or status change time */
			time_t latest_time = (info.st_mtime > info.st_ctime) ? info.st_mtime : info.st_ctime;

			if (latest_time > since_time) {
				const char *output_name = basename ? dirent->d_name : path;
				size_t name_len = strlen(output_name);

				/* Ensure buffer has space for the new path, a newline, and a null terminator */
				size_t required_capacity = result_size + name_len + 2; /* +1 for newline, +1 for null */
				if (required_capacity > result_capacity) {
					/* Grow buffer by doubling, or to the required size if that's larger */
					size_t new_capacity = result_capacity * 2 > required_capacity ? result_capacity * 2 : required_capacity;
					char *new_result = realloc(result, new_capacity);
					if (!new_result) {
						log_message(ERROR, "Failed to reallocate buffer for modified file list");
						free(result);
						closedir(dir);
						return NULL;
					}
					result = new_result;
					result_capacity = new_capacity;
				}

				/* Append the new path, prefixed with a newline if the buffer is not empty */
				if (result_size > 0) {
					result[result_size++] = '\n';
				}
				memcpy(result + result_size, output_name, name_len + 1); /* +1 to copy null terminator */
				result_size += name_len;
			}
		}
		/* Handle directories for recursion */
		else if (S_ISDIR(info.st_mode) && recursive) {
			char *subdir_result = scanner_modified(path, watch, since_time, recursive, basename);

			/* If the recursive call found modified files, append them */
			if (subdir_result && subdir_result[0] != '\0') {
				size_t subdir_len = strlen(subdir_result);
				size_t required_capacity = result_size + subdir_len + 2; /* +2 for newline and null terminator */

				if (required_capacity > result_capacity) {
					size_t new_capacity = result_capacity * 2 > required_capacity ? result_capacity * 2 : required_capacity;
					char *new_result = realloc(result, new_capacity);
					if (!new_result) {
						log_message(ERROR, "Failed to reallocate buffer for recursive modified file list");
						free(result);
						free(subdir_result);
						closedir(dir);
						return NULL;
					}
					result = new_result;
					result_capacity = new_capacity;
				}

				if (result_size > 0) {
					result[result_size++] = '\n';
				}
				memcpy(result + result_size, subdir_result, subdir_len + 1);
				result_size += subdir_len;
			}
			free(subdir_result);
		}
	}

	closedir(dir);
	return result;
}
