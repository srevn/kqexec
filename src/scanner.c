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
#include "logger.h"
#include "monitor.h"

/* Update cumulative changes based on current vs. previous stats */
void scanner_update(entity_state_t *state) {
	if (!state || !state->path_state) return;

	/* Skip if we don't have previous stats yet */
	if (state->prev_stats.file_count == 0 && state->prev_stats.dir_count == 0 &&
	    state->prev_stats.tree_files == 0 && state->prev_stats.tree_dirs == 0 &&
	    state->prev_stats.tree_size == 0) {
		return;
	}

	/* Calculate incremental changes */
	int new_file_change = state->dir_stats.tree_files - state->prev_stats.tree_files;
	int new_dir_change = state->dir_stats.tree_dirs - state->prev_stats.tree_dirs;
	int new_depth_change = state->dir_stats.max_depth - state->prev_stats.max_depth;
	ssize_t new_size_change = (ssize_t)state->dir_stats.tree_size - (ssize_t)state->prev_stats.tree_size;

	/* If significant directory deletion but no depth change reported, infer a depth change */
	if (new_dir_change < -5 && new_depth_change == 0) {
		/* Large structure deletion detected but depth unchanged - likely a bug */
		log_message(DEBUG, "Deletion detected with no depth change for %s, inferring depth reduction",
		            		state->path_state->path);

		/* Calculate inferred depth change proportional to directory removal */
		float deletion_ratio = (float) abs(new_dir_change) /
		                       (state->prev_stats.tree_dirs > 0 ? state->prev_stats.tree_dirs : 10);

		/* Scale depth change based on deletion magnitude */
		if (deletion_ratio > 0.5) {
			new_depth_change = -2; /* Major deletion, likely multiple levels */
		} else {
			new_depth_change = -1; /* Standard deletion, at least one level */
		}
	}

	/* Accumulate changes */
	state->cumulative_file += new_file_change;
	state->cumulative_dirs += new_dir_change;
	state->cumulative_depth += new_depth_change;
	state->cumulative_size += new_size_change;

	/* Set flag indicating stability was lost if we're detecting new changes */
	if (!state->activity_active && (new_file_change != 0 || new_dir_change != 0 || new_depth_change != 0 || new_size_change != 0)) {
		state->stability_lost = true;
	}

	/* Log significant cumulative changes */
	if (new_file_change != 0 || new_dir_change != 0 || new_depth_change != 0 || new_size_change != 0) {
		log_message(DEBUG, "Updated cumulative changes for %s: files=%+d (%+d), dirs=%+d (%+d), depth=%+d (%+d), size=%s (%s)",
		            		state->path_state->path, state->cumulative_file, new_file_change, state->cumulative_dirs,
							new_dir_change, state->cumulative_depth, new_depth_change, format_size(state->cumulative_size, true),
							format_size(new_size_change, true));
	}
}

/* Gather basic directory statistics */
bool scanner_scan(const char *dir_path, dir_stats_t *stats) {
	DIR *dir;
	struct dirent *entry;
	struct stat st;
	char path[PATH_MAX];

	if (!dir_path || !stats) {
		return false;
	}

	/* Initialize stats with recursive fields */
	memset(stats, 0, sizeof(dir_stats_t));

	dir = opendir(dir_path);
	if (!dir) {
		log_message(WARNING, "Failed to open directory for stats gathering: %s", dir_path);
		return false;
	}

	time_t now;
	time(&now);

	while ((entry = readdir(dir))) {
		/* Skip . and .. */
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
			continue;
		}

		snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);

		if (stat(path, &st) != 0) {
			/* Skip files that can't be stat'd but continue processing */
			continue;
		}

		if (S_ISREG(st.st_mode)) {
			stats->file_count++;
			stats->direct_size += st.st_size;

			/* Update latest modification time */
			if (st.st_mtime > stats->last_mtime) {
				stats->last_mtime = st.st_mtime;
			}
		} else if (S_ISDIR(st.st_mode)) {
			stats->dir_count++;

			dir_stats_t subdir_stats;
			if (scanner_scan(path, &subdir_stats)) {
				/* Update maximum tree depth based on subdirectory scan results */
				if (subdir_stats.depth + 1 > stats->depth) {
					stats->depth = subdir_stats.depth + 1;
				}

				/* Calculate and update recursive stats by summing up from subdirectories */
				stats->tree_files += subdir_stats.tree_files;
				stats->tree_dirs += subdir_stats.tree_dirs;
				stats->tree_size += subdir_stats.tree_size;

				/* Update max_depth considering subdirectory's max depth */
				if (subdir_stats.max_depth + 1 > stats->max_depth) {
					stats->max_depth = subdir_stats.max_depth + 1;
				}

				if (subdir_stats.last_mtime > stats->last_mtime) {
					stats->last_mtime = subdir_stats.last_mtime;
				}
			}
		}
	}

	/* Ensure recursive stats include direct stats at this level */
	stats->tree_files += stats->file_count;
	stats->tree_dirs += stats->dir_count;
	stats->tree_size += stats->direct_size;

	/* If max_depth is not set, use depth */
	if (stats->max_depth == 0 && stats->depth > 0) {
		stats->max_depth = stats->depth;
	}

	closedir(dir);
	return true;
}

/* Compare two directory statistics to check for stability */
bool scanner_compare(dir_stats_t *prev, dir_stats_t *current) {
	if (!prev || !current) return false;

	/* Calculate content changes using recursive stats for a complete view of the tree */
	int file_change = current->tree_files - prev->tree_files;
	int dir_change = current->tree_dirs - prev->tree_dirs;
	int depth_change = current->max_depth - prev->max_depth;
	int total_change = abs(file_change) + abs(dir_change);

	/* Log depth changes */
	if (depth_change != 0) {
		log_message(DEBUG, "Directory tree depth changed: %d -> %d (%+d levels)",
		            		prev->max_depth, current->max_depth, depth_change);
	}

	/* Allow small changes for larger directories */
	int prev_total = prev->tree_files + prev->tree_dirs;
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
	      (depth_change == 0 || (abs(depth_change) == 1 && prev->max_depth > 2)))) {
		log_message(DEBUG, "Directory unstable: %d/%d to %d/%d, depth %d to %d (%+d files, %+d dirs, %+d depth, %.1f%% change)",
		            		prev->tree_files, prev->tree_dirs, current->tree_files, current->tree_dirs, prev->max_depth,
							current->max_depth, file_change, dir_change, depth_change, change_percentage);
		is_stable = false;
	}

	/* Check if total size is stable (allowing for small changes) */
	long size_diff = labs((long) prev->tree_size - (long) current->tree_size);
	long threshold = prev->tree_size > 1000000
	                 ? prev->tree_size / 10000
	                 : /* 0.01% for large dirs */
	                 1024; /* 1KB for small dirs */

	if (size_diff > threshold) {
		log_message(DEBUG, "Directory unstable: size changed by %ld bytes (threshold: %ld)", size_diff, threshold);
		is_stable = false;
	}

	/* Check for temporary files */
	if (current->has_temps) {
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

/* Collect statistics about a directory and its contents */
bool scanner_stable(entity_state_t *context_state, const char *dir_path, dir_stats_t *stats) {
	DIR *dir;
	struct dirent *entry;
	struct stat st;
	char path[PATH_MAX];

	if (!dir_path || !stats || !context_state) {
		return false;
	}

	/* Initialize stats including the new recursive fields */
	memset(stats, 0, sizeof(dir_stats_t));

	dir = opendir(dir_path);
	if (!dir) {
		log_message(WARNING, "Failed to open directory for stability check: %s", dir_path);
		return false;
	}

	time_t now;
	time(&now);

	while ((entry = readdir(dir))) {
		/* Skip . and .. */
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
			continue;
		}

		snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);

		if (stat(path, &st) != 0) {
			/* If a file disappears during scan, the directory is not stable */
			log_message(DEBUG, "Directory %s unstable: file disappeared during scan", dir_path);
			closedir(dir);
			return false;
		}

		/* Look for temporary files or recent changes */
		if (S_ISREG(st.st_mode)) {
			stats->file_count++;
			stats->direct_size += st.st_size;

			/* Update latest modification time */
			if (st.st_mtime > stats->last_mtime) {
				stats->last_mtime = st.st_mtime;
			}

			/* Check for very recent file modifications (< 1 seconds) */
			if (difftime(now, st.st_mtime) < 1.0) {
				log_message(DEBUG, "Directory %s unstable: recent file modification (%s, %.1f seconds ago)",
				        			dir_path, entry->d_name, difftime(now, st.st_mtime));
				stats->has_temps = true;
				closedir(dir);
				return false;
			}
		} else if (S_ISDIR(st.st_mode)) {
			stats->dir_count++;

			/* Skip hidden directories if configured */
			if (!context_state->watch->hidden && entry->d_name[0] == '.') {
				continue;
			}

			dir_stats_t subdir_stats;
			if (!scanner_stable(context_state, path, &subdir_stats)) {
				closedir(dir);
				return false;
			}

			/* Update maximum tree depth based on subdirectory scan results */
			if (subdir_stats.depth + 1 > stats->depth) {
				stats->depth = subdir_stats.depth + 1;
			}

			/* Check for temp files */
			stats->has_temps |= subdir_stats.has_temps;

			/* Update recursive stats by summing up from subdirectories */
			stats->tree_files += subdir_stats.tree_files;
			stats->tree_dirs += subdir_stats.tree_dirs;
			stats->tree_size += subdir_stats.tree_size;

			/* Update max_depth considering subdirectory's max depth */
			if (subdir_stats.max_depth + 1 > stats->max_depth) {
				stats->max_depth = subdir_stats.max_depth + 1;
			}

			if (subdir_stats.last_mtime > stats->last_mtime) {
				stats->last_mtime = subdir_stats.last_mtime;
			}
		}
	}

	/* Ensure recursive stats include direct stats at this level */
	stats->tree_files += stats->file_count;
	stats->tree_dirs += stats->dir_count;
	stats->tree_size += stats->direct_size;

	/* If max_depth is not set, use depth */
	if (stats->max_depth == 0 && stats->depth > 0) {
		stats->max_depth = stats->depth;
	}

	closedir(dir);
	return !stats->has_temps;
}

/* Synchronize activity states for all watches on a given path */
void scanner_sync(path_state_t *path_state, entity_state_t *trigger_state) {
	if (!path_state || !trigger_state || states_corrupted(trigger_state)) {
		if (trigger_state && states_corrupted(trigger_state)) {
			log_message(WARNING, "Skipping synchronization due to corrupted trigger state");
		}
		return;
	}

	pthread_mutex_lock(&states_mutex);

	struct timespec sync_time = trigger_state->tree_activity;
	bool watch_active = trigger_state->activity_active;
	int max_unstable_count = trigger_state->unstable_count;

	/* First pass: Find the most recent activity time and active status */
	for (entity_state_t *state = path_state->entity_head; state; state = state->path_next) {
		if (states_corrupted(state) || state == trigger_state) continue;

		if (state->tree_activity.tv_sec > sync_time.tv_sec ||
		    (state->tree_activity.tv_sec == sync_time.tv_sec &&
		     state->tree_activity.tv_nsec > sync_time.tv_nsec)) {
			sync_time = state->tree_activity;
		}

		/* If trigger state is active, merge values from other states.
		 * Otherwise, we are resetting, so we don't merge. */
		if (trigger_state->activity_active) {
			watch_active = watch_active || state->activity_active;
			if (state->unstable_count > max_unstable_count) {
				max_unstable_count = state->unstable_count;
			}
		}
	}

	/* Also update the trigger state's instability count to the max value */
	trigger_state->unstable_count = max_unstable_count;

	/* Second pass: Update all states with consistent values */
	for (entity_state_t *state = path_state->entity_head; state; state = state->path_next) {
		if (states_corrupted(state)) continue;

		if (state != trigger_state) {
			log_message(DEBUG, "Synchronizing state for watch %s", state->watch->name);

			bool fully_compatible = (state->watch->recursive == trigger_state->watch->recursive &&
			                         state->watch->events == trigger_state->watch->events &&
			                         state->watch->hidden == trigger_state->watch->hidden);

			state->exists = trigger_state->exists;
			state->last_update = trigger_state->last_update;
			state->wall_time = trigger_state->wall_time;
			state->tree_activity = sync_time;
			state->activity_active = watch_active;

			if (fully_compatible && state->type == ENTITY_DIRECTORY && trigger_state->type == ENTITY_DIRECTORY) {
				state->dir_stats = trigger_state->dir_stats;
				state->prev_stats = trigger_state->prev_stats;
				state->checks_count = trigger_state->checks_count;
				state->checks_failed = trigger_state->checks_failed;
				state->cumulative_file = trigger_state->cumulative_file;
				state->cumulative_dirs = trigger_state->cumulative_dirs;
				state->cumulative_depth = trigger_state->cumulative_depth;
				state->cumulative_size = trigger_state->cumulative_size;
				state->stability_lost = trigger_state->stability_lost;
				state->unstable_count = max_unstable_count;
			}
		}
	}

	pthread_mutex_unlock(&states_mutex);
}

/* Record basic activity in circular buffer and update state */
static void scanner_record(entity_state_t *state, operation_type_t op) {
	/* Store in circular buffer */
	state->recent_activity[state->activity_index].timestamp = state->last_update;
	state->recent_activity[state->activity_index].operation = op;
	state->activity_index = (state->activity_index + 1) % MAX_SAMPLES;
	if (state->activity_count < MAX_SAMPLES) {
		state->activity_count++;
	}

	/* Reset stability check counter when new activity occurs */
	state->checks_count = 0;

	/* Update activity timestamp for this state, which is the basis for tree activity time */
	state->tree_activity = state->last_update;

	/* Update the last activity path */
	free(state->active_path);
	state->active_path = strdup(state->path_state->path);
}

/* Update directory stats when content changes */
static void scanner_update_stats(entity_state_t *state, operation_type_t op) {
	if (op == OP_DIR_CONTENT_CHANGED && state->type == ENTITY_DIRECTORY) {
		dir_stats_t new_stats;
		if (scanner_scan(state->path_state->path, &new_stats)) {
			/* Save previous stats for comparison */
			state->prev_stats = state->dir_stats;
			/* Update with new stats */
			state->dir_stats = new_stats;

			/* Update cumulative changes */
			scanner_update(state);

			log_message(DEBUG, "Directory stats for %s: files=%d, dirs=%d, max_depth=%d (was: files=%d, dirs=%d, max_depth=%d)",
			            		state->path_state->path, state->dir_stats.tree_files, state->dir_stats.tree_dirs,
			            		state->dir_stats.max_depth, state->prev_stats.tree_files, state->prev_stats.tree_dirs,
			            		state->prev_stats.max_depth);
		}
	}
}

/* Propagate activity to all parent directories between entity and root */
static void scanner_propagate(entity_state_t *state, entity_state_t *root, operation_type_t op, dir_stats_t *root_stats) {
	char *path_copy = strdup(state->path_state->path);
	if (path_copy) {
		/* Get parent directory path */
		char *last_slash = strrchr(path_copy, '/');
		while (last_slash && last_slash > path_copy) {
			*last_slash = '\0'; /* Truncate to get parent directory */

			/* Skip if we've reached or gone beyond the root watch path */
			if (strlen(path_copy) < strlen(root->watch->path)) {
				break;
			}

			/* Update state for this parent directory */
			entity_state_t *parent_state = states_get(path_copy, ENTITY_DIRECTORY, state->watch);
			if (parent_state) {
				parent_state->tree_activity = state->last_update;
				free(parent_state->active_path);
				parent_state->active_path = strdup(state->path_state->path);
				parent_state->activity_active = true;
				parent_state->checks_count = 0;

				/* Reset stability_lost flag when activity becomes active to prevent repeated penalties */
				parent_state->stability_lost = false;

				/* Update directory stats for parent if this is a content change */
				if (op == OP_DIR_CONTENT_CHANGED && parent_state->type == ENTITY_DIRECTORY) {
					/* Optimization: For recursive watches within the same scope, reuse root stats */
					bool within_recursive_scope = (root_stats && 
					                               parent_state->watch->recursive &&
					                               parent_state->watch == root->watch &&
					                               strlen(path_copy) >= strlen(root->watch->path));
					
					if (within_recursive_scope) {
						/* Use pre-calculated root stats - no redundant scanning */
						parent_state->prev_stats = parent_state->dir_stats;
						parent_state->dir_stats = *root_stats;
						
						/* Update cumulative changes */
						scanner_update(parent_state);
					} else {
						/* Fall back to scanning for non-recursive or cross-scope parents */
						dir_stats_t parent_new_stats;
						if (scanner_scan(parent_state->path_state->path, &parent_new_stats)) {
							parent_state->prev_stats = parent_state->dir_stats;
							parent_state->dir_stats = parent_new_stats;

							/* Update cumulative changes */
							scanner_update(parent_state);
						}
					}
				}

				scanner_sync(parent_state->path_state, parent_state);
			}

			/* Move to next parent directory */
			last_slash = strrchr(path_copy, '/');
		}
		free(path_copy);
	}
}

/* Handle activity recording for recursive watches */
static void scanner_handle_recursive(entity_state_t *state, operation_type_t op) {
	/* First, find the root state */
	entity_state_t *root = stability_root(state);
	if (root) {
		/* Update the root's tree activity time and path */
		root->tree_activity = state->last_update;
		free(root->active_path);
		root->active_path = strdup(state->path_state->path);
		root->activity_active = true;

		/* Reset stability_lost flag when activity becomes active to prevent repeated penalties */
		root->stability_lost = false;

		/* Reset root's stability checks */
		root->checks_count = 0;

		/* For directory operations, update directory stats immediately */
		scanner_update_stats(root, op);

		/* Synchronize with other watches for the same path */
		scanner_sync(root->path_state, root);

		/* Now propagate activity to all parent directories between this entity and root */
		/* Pass root stats to avoid redundant scanning within the same recursive scope */
		scanner_propagate(state, root, op, &root->dir_stats);
	}
}

/* Handle activity when state is the root path itself */
static void scanner_handle_root(entity_state_t *state, operation_type_t op) {
	/* This is the root itself */
	state->tree_activity = state->last_update;
	free(state->active_path);
	state->active_path = strdup(state->path_state->path);

	/* Update directory stats immediately for content changes to root */
	if (op == OP_DIR_CONTENT_CHANGED && state->type == ENTITY_DIRECTORY) {
		dir_stats_t new_stats;
		if (scanner_scan(state->path_state->path, &new_stats)) {
			/* Save previous stats for comparison */
			state->prev_stats = state->dir_stats;
			/* Update with new stats */
			state->dir_stats = new_stats;

			/* Update cumulative changes */
			scanner_update(state);

			log_message(DEBUG, "Updated directory stats for root %s after change: files=%d, dirs=%d, depth=%d",
			        			state->path_state->path, state->dir_stats.file_count, state->dir_stats.dir_count,
			            		state->dir_stats.depth);
		}
	}

	scanner_sync(state->path_state, state);
}

/* Record a new activity event in the entity's history */
void scanner_track(entity_state_t *state, operation_type_t op) {
	if (!state) return;

	/* Record basic activity in circular buffer */
	scanner_record(state, op);

	/* Handle recursive watches and root paths */
	if (state->watch && state->watch->recursive) {
		if (strcmp(state->path_state->path, state->watch->path) == 0) {
			/* Handle when state is the root path itself */
			scanner_handle_root(state, op);
		} else {
			/* Handle recursive watch activity */
			scanner_handle_recursive(state, op);
		}
	}

	/* Always sync the current state */
	scanner_sync(state->path_state, state);
}

/* Calculate base quiet period based on change magnitude */
static long scanner_base_period(entity_state_t *state) {
	/* Use cumulative change counters instead of just prev/current comparison */
	int abs_file_change = abs(state->cumulative_file);
	int abs_dir_change = abs(state->cumulative_dirs);
	int abs_depth_change = abs(state->cumulative_depth);
	ssize_t abs_size_change = state->cumulative_size < 0 ? -state->cumulative_size : state->cumulative_size;
	int total_change = abs_file_change + abs_dir_change;

	/* Prioritize operation complexity */
	/* Start with a base quiet period based primarily on change magnitude */
	if (total_change == 0 && abs_depth_change == 0 && abs_size_change == 0) {
		/* No change - minimal quiet period */
		return 250;
	} else if (total_change < 5 && abs_depth_change == 0 && abs_size_change < 1024 * 1024) {
		/* Few files change with no structural changes and small size changes - short quiet period */
		return 500;
	} else if (total_change < 10 && abs_depth_change == 0 && abs_size_change < 10 * 1024 * 1024) {
		/* Several files changed, no structural changes, moderate size changes - modest quiet period */
		return 1000;
	} else if (abs_depth_change > 0 || abs_size_change > 100 * 1024 * 1024) {
		/* Structural depth changes or large size changes - significant quiet period */
		int size_factor = (abs_size_change > 100 * 1024 * 1024) ? (abs_size_change / (100 * 1024 * 1024)) : 0;
		return 1500 + (abs_depth_change * 500) + (size_factor * 250);
	} else if (total_change < 10) {
		/* Moderate changes - medium quiet period */
		return 1200;
	} else {
		/* Many changes - longer quiet period */
		return 1500 + (total_change / 10) * 250;
	}
}

/* Calculate current activity magnitude (changes from reference state) for responsive adjustments */
static void calculate_recent_activity(entity_state_t *state, int *recent_files, int *recent_dirs, int *recent_depth, ssize_t *recent_size) {
	if (state->prev_stats.tree_files == 0 && state->prev_stats.tree_dirs == 0 && state->prev_stats.tree_size == 0) {
		/* No previous state - use minimal values */
		*recent_files = *recent_dirs = *recent_depth = 0;
		*recent_size = 0;
		return;
	}

	/* Calculate changes from the previous scan state to measure the current rate of change */
	*recent_files = abs(state->dir_stats.tree_files - state->prev_stats.tree_files);
	*recent_dirs = abs(state->dir_stats.tree_dirs - state->prev_stats.tree_dirs);
	*recent_depth = abs(state->dir_stats.max_depth - state->prev_stats.max_depth);
	*recent_size = labs((ssize_t)state->dir_stats.tree_size - (ssize_t)state->prev_stats.tree_size);
}

/* Apply stability, depth, and size adjustments to quiet period */
static long scanner_adjust(entity_state_t *state, long base_ms) {
	long required_ms = base_ms;
	int total_entries = state->dir_stats.tree_files + state->dir_stats.tree_dirs;
	int tree_depth = state->dir_stats.max_depth > 0 ? state->dir_stats.max_depth : state->dir_stats.depth;
	
	/* Use current activity magnitude (changes from reference state) for responsiveness */
	int recent_files, recent_dirs, recent_depth;
	ssize_t recent_size;
	calculate_recent_activity(state, &recent_files, &recent_dirs, &recent_depth, &recent_size);
	int recent_change = recent_files + recent_dirs;

	/* If stability was previously achieved and then lost, increase quiet period */
	if (state->stability_lost) {
		/* We need a more careful check for resumed activity */
		required_ms = (long) (required_ms * 1.25); /* 25% increase */
		log_message(DEBUG, "Stability previously achieved and lost, increasing quiet period by 25%%");
	}

	/* Tree depth multiplier - based on recent activity rate */
	if (tree_depth > 0) {
		/* Scale down the depth impact for simple operations */
		float depth_factor = (recent_change <= 1) ? 0.5 : 1.0;
		required_ms += tree_depth * 150 * depth_factor; /* Reduced from 250ms to 150ms per level */
	}

	/* Directory size complexity factor - based on recent activity */
	if (total_entries > 100) {
		float size_factor = (recent_change <= 3) ? 0.3 : 0.7;
		int size_addition = (int) (250 * size_factor * (total_entries / 200.0));
		/* Cap the size adjustment for small operations */
		if (recent_change <= 1 && size_addition > 300) size_addition = 300;
		required_ms += size_addition;
	}

	return required_ms;
}

/* Apply exponential backoff for consecutive instability */
static long scanner_backoff(entity_state_t *state, long required_ms) {
	if (state->unstable_count < 3) {  /* Only apply backoff after 3 consecutive unstable counts */
		return required_ms;
	}

	/* Start with a base multiplier */
	double backoff_factor = 1.0;

	/* Increase backoff factor for repeated instability after 3 consecutive unstable counts */
	for (int i = 3; i <= state->unstable_count; i++) {
		backoff_factor *= 1.25;
	}

	/* Apply a cap to the backoff factor to prevent excessive delays */
	if (backoff_factor > 5.0) {
		backoff_factor = 5.0;
	}

	long adjusted_ms = (long) (required_ms * backoff_factor);
	log_message(DEBUG, "Applying instability backoff factor of %.2f, new quiet period: %ld ms",
						backoff_factor, adjusted_ms);

	return adjusted_ms;
}

/* Apply final limits and complexity multiplier */
static long scanner_limit_period(entity_state_t *state, long required_ms) {
	/* Set reasonable limits */
	if (required_ms < 100) required_ms = 100;

	/* Dynamic cap based on operation characteristics */
	long max_period = 30000; /* Default 30 seconds */

	if (required_ms > max_period) {
		log_message(DEBUG, "Capping quiet period for %s from %ld ms to %ld ms", state->path_state->path, required_ms, max_period);
		required_ms = max_period;
	}

	/* Apply complexity multiplier from watch config */
	if (state->watch && state->watch->complexity > 0) {
		long pre_multiplier = required_ms;
		required_ms = (long) (required_ms * state->watch->complexity);
		log_message(DEBUG, "Applied complexity multiplier %.2f to %s: %ld ms -> %ld ms",
							state->watch->complexity, state->path_state->path, pre_multiplier, required_ms);
	}

	return required_ms;
}

/* Determine the required quiet period based on state type and activity */
long scanner_delay(entity_state_t *state) {
	if (!state) return QUIET_PERIOD_MS;

	long required_ms = QUIET_PERIOD_MS;

	/* Use a longer base period for directories */
	if (state->type == ENTITY_DIRECTORY) {
		/* Default quiet period */
		required_ms = DIR_QUIET_PERIOD_MS; /* Default 1000ms */

		/* For active directories, use adaptive complexity measurement */
		if (state->activity_active) {
			/* Extract complexity indicators */
			int total_entries = state->dir_stats.tree_files + state->dir_stats.tree_dirs;
			int tree_depth = state->dir_stats.max_depth > 0 ? state->dir_stats.max_depth : state->dir_stats.depth;

			/* Calculate base period from change magnitude */
			required_ms = scanner_base_period(state);

			/* Apply stability adjustments (depth, size, stability loss) */
			required_ms = scanner_adjust(state, required_ms);

			/* Apply exponential backoff for consecutive instability */
			required_ms = scanner_backoff(state, required_ms);

			log_message(DEBUG, "Quiet period for %s: %ld ms (changes: %+d files, %+d dirs, %+d depth, %s size, total: entries %d, depth %d)",
			        			state->path_state->path, required_ms, state->cumulative_file, state->cumulative_dirs,
								state->cumulative_depth, format_size(state->cumulative_size, true), total_entries, tree_depth);
		} else {
			/* For inactive directories, just log the base period with recursive stats */
			int total_entries = state->dir_stats.tree_files + state->dir_stats.tree_dirs;
			int tree_depth = state->dir_stats.max_depth > 0 ? state->dir_stats.max_depth : state->dir_stats.depth;
			int subdir_count = state->dir_stats.tree_dirs;

			log_message(DEBUG, "Using base quiet period for %s: %ld ms (recursive entries: %d, depth: %d, subdirs: %d)",
			    				state->path_state->path, required_ms, total_entries, tree_depth, subdir_count);
		}
	}

	/* Apply final limits and complexity multiplier */
	return scanner_limit_period(state, required_ms);
}

/* Check if enough quiet time has passed since the last activity */
bool scanner_ready(entity_state_t *state, struct timespec *now, long required_quiet) {
	if (!state || !now) return true; /* Cannot check, assume elapsed */

	struct timespec *activity_time = NULL;
	const char *source_path = state->path_state->path;

	/* Determine which timestamp to check against */
	if (state->type == ENTITY_DIRECTORY && state->watch && state->watch->recursive) {
		/* For recursive directory watches, always check the root's tree time */
		entity_state_t *root = stability_root(state);
		if (root) {
			activity_time = &root->tree_activity;
			source_path = root->path_state->path;
		} else {
			log_message(WARNING, "Cannot find root state for %s, falling back to local activity", state->path_state->path);
			/* Fallback: use local activity if root not found */
			if (state->activity_count == 0) return true;
			int latest_idx = (state->activity_index + MAX_SAMPLES - 1) % MAX_SAMPLES;
			activity_time = &state->recent_activity[latest_idx].timestamp;
		}
	} else {
		/* For files or non-recursive dirs, use local activity time */
		if (state->activity_count == 0) return true;
		int latest_idx = (state->activity_index + MAX_SAMPLES - 1) % MAX_SAMPLES;
		activity_time = &state->recent_activity[latest_idx].timestamp;
	}

	/* Check for valid timestamp */
	if (!activity_time || (activity_time->tv_sec == 0 && activity_time->tv_nsec == 0)) {
		log_message(DEBUG, "No valid activity timestamp for %s, quiet period assumed elapsed", state->path_state->path);
		return true;
	}

	/* Calculate elapsed time */
	long elapsed_ms;
	if (now->tv_sec < activity_time->tv_sec ||
	    (now->tv_sec == activity_time->tv_sec && now->tv_nsec < activity_time->tv_nsec)) {
		elapsed_ms = -1; /* Clock went backwards */
	} else {
		struct timespec diff;
		diff.tv_sec = now->tv_sec - activity_time->tv_sec;
		if (now->tv_nsec >= activity_time->tv_nsec) {
			diff.tv_nsec = now->tv_nsec - activity_time->tv_nsec;
		} else {
			diff.tv_sec--;
			diff.tv_nsec = 1000000000 + now->tv_nsec - activity_time->tv_nsec;
		}
		elapsed_ms = diff.tv_sec * 1000 + diff.tv_nsec / 1000000;
	}

	if (elapsed_ms < 0) {
		log_message(WARNING, "Clock appears to have moved backwards for %s, assuming quiet period elapsed",
		            		  state->path_state->path);
		return true;
	}

	bool elapsed = elapsed_ms >= required_quiet;

	if (!elapsed) {
		log_message(DEBUG, "Quiet period check for %s: %ld ms elapsed < %ld ms required (using time from %s)",
		            		state->path_state->path, elapsed_ms, required_quiet, source_path);
	} else {
		log_message(DEBUG, "Quiet period elapsed for %s: %ld ms >= %ld ms required",
		        			state->path_state->path, elapsed_ms, required_quiet);
	}

	return elapsed;
}

/* Find the most recently modified file in a directory */
char *scanner_newest(const char *dir_path) {
	DIR *dir;
	struct dirent *entry;
	struct stat st;
	char path[PATH_MAX];
	char *newest_file = NULL;
	time_t newest_time = 0;

	dir = opendir(dir_path);
	if (!dir) {
		return NULL;
	}

	while ((entry = readdir(dir))) {
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
			continue;
		}
		
		/* Skip .DS_Store files created by macOS */
		if (strcmp(entry->d_name, ".DS_Store") == 0) {
			continue;
		}

		snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);
		if (stat(path, &st) == 0) {
			/* Consider both modification time and change time */
			time_t latest_time = (st.st_mtime > st.st_ctime) ? st.st_mtime : st.st_ctime;
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
	struct dirent *entry;
	struct stat st;
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

	while ((entry = readdir(dir))) {
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
			continue;
		}
		
		/* Skip .DS_Store files created by macOS */
		if (strcmp(entry->d_name, ".DS_Store") == 0) {
			continue;
		}

		snprintf(path, sizeof(path), "%s/%s", base_path, entry->d_name);
		if (stat(path, &st) != 0) {
			continue;
		}

		if (S_ISREG(st.st_mode)) {
			/* Consider both modification time and change time */
			time_t latest_time = (st.st_mtime > st.st_ctime) ? st.st_mtime : st.st_ctime;
			if (latest_time > since_time) {
				/* Add this file to the result */
				const char *output_name = basename ? entry->d_name : path;
				size_t name_len = strlen(output_name);
				size_t needed = result_size + name_len + 2; /* +2 for newline and null terminator */
				
				if (needed > result_capacity) {
					result_capacity = needed * 2;
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
		} else if (S_ISDIR(st.st_mode) && recursive) {
			/* Recursively scan subdirectory */
			char *subdir_result = scanner_modified(path, since_time, recursive, basename);
			if (subdir_result && strlen(subdir_result) > 0) {
				size_t subdir_len = strlen(subdir_result);
				size_t needed = result_size + subdir_len + 2; /* +2 for newline and null terminator */
				
				if (needed > result_capacity) {
					result_capacity = needed * 2;
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
