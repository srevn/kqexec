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
#include "resource.h"
#include "stability.h"
#include "utilities.h"

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
void scanner_update(profile_t *profile, const char *path) {
	if (!profile || !profile->stability) return;

	/* Calculate incremental changes */
	int new_files, new_dirs, new_depth;
	ssize_t new_size;

	/* Calculate the difference from previous stats */
	new_files = profile->stability->stats.tree_files - profile->stability->prev_stats.tree_files;
	new_dirs = profile->stability->stats.tree_dirs - profile->stability->prev_stats.tree_dirs;
	new_depth = profile->stability->stats.max_depth - profile->stability->prev_stats.max_depth;
	new_size = (ssize_t) profile->stability->stats.tree_size - (ssize_t) profile->stability->prev_stats.tree_size;

	/* Accumulate changes */
	profile->stability->delta_files += new_files;
	profile->stability->delta_dirs += new_dirs;
	profile->stability->delta_depth += new_depth;
	profile->stability->delta_size += new_size;

	/* Set flag indicating stability was lost if we're detecting new changes */
	bool active = profile->scanner ? profile->scanner->active : false;
	if (!active && (new_files != 0 || new_dirs != 0 || new_depth != 0 || new_size != 0)) {
		profile->stability->stability_lost = true;
	}

	/* Log significant cumulative changes */
	if (new_files != 0 || new_dirs != 0 || new_depth != 0 || new_size != 0) {
		log_message(DEBUG, "Updated cumulative changes for %s: files=%+d (%+d), dirs=%+d (%+d), depth=%+d (%+d), size=%s (%s)",
					path, profile->stability->delta_files, new_files, profile->stability->delta_dirs, new_dirs,
					profile->stability->delta_depth, new_depth, format_size(profile->stability->delta_size, true),
					format_size(new_size, true));
	}
}

/* Gather basic directory statistics */
bool scanner_scan(const char *dir_path, const watch_t *watch, stats_t *stats) {
	DIR *dir;
	struct dirent *dirent;
	struct stat info;
	char path[PATH_MAX];

	if (!dir_path || !stats) return false;

	/* Extract flags from watch with sensible defaults */
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

		int path_len = snprintf(path, sizeof(path), "%s/%s", dir_path, dirent->d_name);

		/* Check for path truncation */
		if (path_len >= (int) sizeof(path)) {
			log_message(WARNING, "Path too long, skipping: %s/%s", dir_path, dirent->d_name);
			continue;
		}

		/* Check if item is hidden when not requested */
		bool hidden_item = false;
		if (!hidden) {
			const char *basename = strrchr(path, '/');
			if ((basename ? basename + 1 : path)[0] == '.') {
				hidden_item = true;
			}
		}

		if (stat(path, &info) != 0) {
			/* Skip files that can't be stat'd but continue processing */
			continue;
		}

		if (S_ISREG(info.st_mode)) {
			/* Check if file is excluded (by pattern or hidden status) */
			if (hidden_item || (watch && exclude_match(watch, path))) {
				/* Excluded file, update the counters and checksums */
				stats->excluded_files++;
				stats->excluded_size += info.st_size;
				/* Track latest mtime of excluded files for change detection */
				if (info.st_mtime > stats->excluded_mtime) {
					stats->excluded_mtime = info.st_mtime;
				}
				continue;
			}

			/* Included file, increment the existing counter */
			stats->local_files++;
			stats->local_size += info.st_size;

			/* Update latest modification time */
			if (info.st_mtime > stats->last_mtime) {
				stats->last_mtime = info.st_mtime;
			}
		} else if (S_ISDIR(info.st_mode)) {
			/* Check if directory is excluded (by pattern or hidden status) */
			if (hidden_item || (watch && exclude_match(watch, path))) {
				/* Excluded directory, update the counter */
				stats->excluded_dirs++;
				continue;
			}

			stats->local_dirs++;

			/* If not recursive, skip subdirectory scanning */
			if (!recursive) continue;

			stats_t sub_stats;
			if (!scanner_scan(path, watch, &sub_stats)) continue;

			/* Update maximum tree depth based on subdirectory scan results */
			if (sub_stats.depth + 1 > stats->depth) {
				stats->depth = sub_stats.depth + 1;
			}

			/* Calculate and update recursive stats by summing up subdirectories */
			stats->tree_files += sub_stats.tree_files;
			stats->tree_dirs += sub_stats.tree_dirs;
			stats->tree_size += sub_stats.tree_size;

			/* Aggregate the excluded file/dir stats from the recursive call */
			stats->excluded_files += sub_stats.excluded_files;
			stats->excluded_size += sub_stats.excluded_size;
			stats->excluded_dirs += sub_stats.excluded_dirs;
			/* Use latest mtime across all excluded files in the tree */
			if (sub_stats.excluded_mtime > stats->excluded_mtime) {
				stats->excluded_mtime = sub_stats.excluded_mtime;
			}

			/* Update max_depth considering subdirectory's max depth */
			if (sub_stats.max_depth + 1 > stats->max_depth) {
				stats->max_depth = sub_stats.max_depth + 1;
			}

			if (sub_stats.last_mtime > stats->last_mtime) {
				stats->last_mtime = sub_stats.last_mtime;
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
bool scanner_stable(monitor_t *monitor, const watch_t *watch, const char *dir_path, stats_t *stats) {
	DIR *dir;
	struct dirent *dirent;
	struct stat info;
	char path[PATH_MAX];
	bool is_stable = true; /* Assume stable until proven otherwise */

	if (!dir_path || !stats) return false;

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

	while ((dirent = readdir(dir))) {
		/* Get a fresh timestamp for each entry */
		time(&current_time);
		/* Skip . and .. */
		if (strcmp(dirent->d_name, ".") == 0 || strcmp(dirent->d_name, "..") == 0) {
			continue;
		}

		int path_len = snprintf(path, sizeof(path), "%s/%s", dir_path, dirent->d_name);

		/* Check for path truncation */
		if (path_len >= (int) sizeof(path)) {
			log_message(WARNING, "Path too long, skipping: %s/%s", dir_path, dirent->d_name);
			continue;
		}

		/* Check if item is hidden when not requested */
		bool hidden_item = false;
		if (!hidden) {
			const char *basename = strrchr(path, '/');
			if ((basename ? basename + 1 : path)[0] == '.') {
				hidden_item = true;
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
			/* Check if file is excluded (by pattern or hidden status) */
			if (hidden_item || (watch && exclude_match(watch, path))) {
				/* Excluded file, update the counters and checksums */
				stats->excluded_files++;
				stats->excluded_size += info.st_size;
				/* Track latest mtime of excluded files for change detection */
				if (info.st_mtime > stats->excluded_mtime) {
					stats->excluded_mtime = info.st_mtime;
				}
				continue;
			}

			/* Included file, process normally */
			stats->local_files++;
			stats->local_size += info.st_size; /* Always accumulate size */

			/* Update latest modification time */
			if (info.st_mtime > stats->last_mtime) {
				stats->last_mtime = info.st_mtime;
			}

			/* Check for very recent file modifications using complexity-based threshold */
			double temp_threshold = complexity_temporary(watch ? watch->complexity : 1.0);
			double file_age = difftime(current_time, info.st_mtime);
			if (file_age < temp_threshold) {
				log_message(DEBUG, "Directory %s unstable: recent file modification (%s, %.1f seconds ago, threshold: %.2fs)",
							dir_path, dirent->d_name, file_age, temp_threshold);
				stats->temp_files = true;
				is_stable = false; /* Mark as unstable but continue scanning */
			}
		} else if (S_ISDIR(info.st_mode)) {
			/* Check if directory is excluded (by pattern or hidden status) */
			if (hidden_item || (watch && exclude_match(watch, path))) {
				/* Excluded directory, update the counter */
				stats->excluded_dirs++;
				continue;
			}

			stats->local_dirs++;

			/* If not recursive, skip subdirectory processing */
			if (!recursive) continue;

			stats_t sub_stats;
			if (!scanner_stable(monitor, watch, path, &sub_stats)) {
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

			/* Aggregate the excluded file/dir stats from the recursive call */
			stats->excluded_files += sub_stats.excluded_files;
			stats->excluded_size += sub_stats.excluded_size;
			stats->excluded_dirs += sub_stats.excluded_dirs;
			/* Use latest mtime across all excluded files in the tree */
			if (sub_stats.excluded_mtime > stats->excluded_mtime) {
				stats->excluded_mtime = sub_stats.excluded_mtime;
			}

			/* Update max_depth considering subdirectory's max depth */
			if (sub_stats.max_depth + 1 > stats->max_depth) {
				stats->max_depth = sub_stats.max_depth + 1;
			}

			if (sub_stats.last_mtime > stats->last_mtime) {
				stats->last_mtime = sub_stats.last_mtime;
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
static void scanner_record(profile_t *profile, struct timespec timestamp, const char *path, optype_t optype) {
	/* Create activity state if needed */
	if (!profile->scanner) {
		profile->scanner = scanner_create(path);
		if (!profile->scanner) return;
	}

	/* Store in circular buffer */
	profile->scanner->samples[profile->scanner->sample_index].timestamp = timestamp;
	profile->scanner->samples[profile->scanner->sample_index].operation = optype;
	profile->scanner->sample_index = (profile->scanner->sample_index + 1) % MAX_SAMPLES;
	if (profile->scanner->sample_count < MAX_SAMPLES) {
		profile->scanner->sample_count++;
	}

	/* Reset stability check counter when new activity occurs */
	if (profile->stability) {
		profile->stability->checks_count = 0;
	}

	/* Update activity timestamp for this profile, which is the basis for tree activity time */
	profile->scanner->latest_time = timestamp;

	/* Update the last activity path */
	free(profile->scanner->active_path);
	profile->scanner->active_path = strdup(path);
}

/* Update directory stats when content changes */
static void scanner_stats(monitor_t *monitor, subscription_t *subscription, optype_t optype) {
	if (optype == OP_DIR_CONTENT_CHANGED && subscription->resource->kind == ENTITY_DIRECTORY) {
		/* Update directory stats immediately to reflect the change */
		stats_t new_stats;
		watch_t *watch = registry_get(monitor->registry, subscription->watchref);
		if (watch && scanner_scan(subscription->resource->path, watch, &new_stats)) {
			/* Create stability state if needed */
			if (!subscription->profile->stability) {
				subscription->profile->stability = stability_create();
				if (!subscription->profile->stability) return;
			}

			/* Save previous stats for comparison */
			subscription->profile->stability->prev_stats = subscription->profile->stability->stats;
			/* Update with new stats */
			subscription->profile->stability->stats = new_stats;

			/* Update cumulative changes */
			scanner_update(subscription->profile, subscription->resource->path);
		}

		if (subscription->profile->stability) {
			log_message(DEBUG, "Directory stats for %s: files=%d, dirs=%d, max_depth=%d (was: files=%d, dirs=%d, max_depth=%d)",
						subscription->resource->path, subscription->profile->stability->stats.tree_files,
						subscription->profile->stability->stats.tree_dirs, subscription->profile->stability->stats.max_depth,
						subscription->profile->stability->prev_stats.tree_files, subscription->profile->stability->prev_stats.tree_dirs,
						subscription->profile->stability->prev_stats.max_depth);
		}
	}
}

/* Propagate activity to all parent directories between entity and root */
static void scanner_propagate(monitor_t *monitor, subscription_t *subscription, subscription_t *root, optype_t optype, stats_t *root_stats) {
	/* Get watches for subscription and root */
	watch_t *root_watch = registry_get(monitor->registry, root->watchref);
	if (!root_watch) {
		log_message(WARNING, "Cannot get root watch for scanner propagation");
		return;
	}

	char *path_copy = strdup(subscription->resource->path);
	if (!path_copy) return;

	/* Get parent directory path */
	char *last_slash = strrchr(path_copy, '/');
	while (last_slash && last_slash > path_copy) {
		*last_slash = '\0'; /* Truncate to get parent directory */

		/* Skip if we've reached or gone beyond the root watch path */
		if (strlen(path_copy) < strlen(root_watch->path)) break;

		/* Update subscription for this parent directory */
		subscription_t *parent = resources_subscription(monitor->resources, monitor->registry, path_copy, subscription->watchref, ENTITY_DIRECTORY);
		if (!parent) {
			last_slash = strrchr(path_copy, '/');
			continue;
		}

		/* Create activity state if needed */
		if (!parent->profile->scanner) {
			parent->profile->scanner = scanner_create(parent->resource->path);
		}
		if (parent->profile->scanner) {
			parent->profile->scanner->latest_time = subscription->resource->last_time;
			free(parent->profile->scanner->active_path);
			parent->profile->scanner->active_path = strdup(subscription->resource->path);
			parent->profile->scanner->active = true;
		}

		/* Create stability state if needed */
		if (!parent->profile->stability) {
			parent->profile->stability = stability_create();
		}
		if (parent->profile->stability) {
			parent->profile->stability->checks_count = 0;
			parent->profile->stability->stability_lost = false;
		}

		/* Update directory stats for parent if this is a content change */
		if (optype != OP_DIR_CONTENT_CHANGED || parent->resource->kind != ENTITY_DIRECTORY) {
			last_slash = strrchr(path_copy, '/');
			continue;
		}

		/* For recursive watches within the same scope, propagate incremental changes */
		watch_t *parent_watch = registry_get(monitor->registry, parent->watchref);
		watch_t *root_scope = registry_get(monitor->registry, root->watchref);
		bool in_scope = (root_stats && parent_watch && root_scope && parent_watch->recursive &&
						 parent_watch == root_scope && strlen(path_copy) >= strlen(root_scope->path));

		if (!in_scope || !root->profile->stability || !parent->profile->stability) {
			/* Fall back to scanning for non-recursive or cross-scope parents */
			stats_t parent_new_stats;
			if (parent_watch && scanner_scan(parent->resource->path, parent_watch, &parent_new_stats)) {
				if (!parent->profile->stability) {
					parent->profile->stability = stability_create();
				}
				if (parent->profile->stability) {
					parent->profile->stability->prev_stats = parent->profile->stability->stats;
					parent->profile->stability->stats = parent_new_stats;
					scanner_update(parent->profile, parent->resource->path);
				}
			}
			last_slash = strrchr(path_copy, '/');
			continue;
		}

		if (parent == root) {
			last_slash = strrchr(path_copy, '/');
			continue;
		}

		/* Calculate incremental changes from root's current update */
		int root_files = root->profile->stability->stats.tree_files - root->profile->stability->prev_stats.tree_files;
		int root_dirs = root->profile->stability->stats.tree_dirs - root->profile->stability->prev_stats.tree_dirs;
		int root_depth = root->profile->stability->stats.max_depth - root->profile->stability->prev_stats.max_depth;
		ssize_t root_size = (ssize_t) root->profile->stability->stats.tree_size -
							(ssize_t) root->profile->stability->prev_stats.tree_size;

		/* Apply incremental changes to parent while preserving its absolute state */
		parent->profile->stability->prev_stats = parent->profile->stability->stats;
		parent->profile->stability->stats.tree_files += root_files;
		parent->profile->stability->stats.tree_dirs += root_dirs;
		parent->profile->stability->stats.max_depth = (root_depth > 0) ?
														  parent->profile->stability->stats.max_depth + root_depth :
														  parent->profile->stability->stats.max_depth;
		parent->profile->stability->stats.tree_size += root_size;

		/* Update cumulative changes */
		scanner_update(parent->profile, parent->resource->path);

		/* Move to next parent directory */
		last_slash = strrchr(path_copy, '/');
	}
	free(path_copy);
}

/* Handle activity recording for recursive watches */
static void scanner_recursive(monitor_t *monitor, subscription_t *subscription, optype_t optype) {
	/* First, find the root subscription */
	subscription_t *root = stability_root(monitor, subscription);
	if (root) {
		/* Update the root's tree activity time and path */
		if (!root->profile->scanner) {
			root->profile->scanner = scanner_create(root->resource->path);
		}
		if (root->profile->scanner) {
			root->profile->scanner->latest_time = subscription->resource->last_time;
			free(root->profile->scanner->active_path);
			root->profile->scanner->active_path = strdup(subscription->resource->path);
			root->profile->scanner->active = true;
		}

		/* Reset stability_lost flag when activity becomes active to prevent repeated penalties */
		if (!root->profile->stability) {
			root->profile->stability = stability_create();
		}
		if (root->profile->stability) {
			root->profile->stability->checks_count = 0;
			root->profile->stability->stability_lost = false;
		}

		/* For directory operations, update directory stats immediately */
		scanner_stats(monitor, root, optype);

		/* Now propagate activity to all parent directories between this subscription and root */
		stats_t *root_stats = root->profile->stability ? &root->profile->stability->stats : NULL;
		scanner_propagate(monitor, subscription, root, optype, root_stats);
	}
}

/* Handle activity when subscription is the root path itself */
static void scanner_root(monitor_t *monitor, subscription_t *subscription, optype_t optype) {
	/* This is the root itself */
	if (!subscription->profile->scanner) {
		subscription->profile->scanner = scanner_create(subscription->resource->path);
	}
	if (subscription->profile->scanner) {
		subscription->profile->scanner->latest_time = subscription->resource->last_time;
		free(subscription->profile->scanner->active_path);
		subscription->profile->scanner->active_path = strdup(subscription->resource->path);
	}

	/* Update directory stats immediately for content changes to root */
	scanner_stats(monitor, subscription, optype);
}

/* Record a new activity event in the subscription's history */
void scanner_track(monitor_t *monitor, subscription_t *subscription, optype_t optype) {
	if (!subscription || !subscription->profile) return;

	/* Check for duplicate tracking to avoid re-processing the same event */
	if (subscription->resource->op_time.tv_sec == subscription->resource->last_time.tv_sec &&
		subscription->resource->op_time.tv_nsec == subscription->resource->last_time.tv_nsec) {
		log_message(DEBUG, "Skipping duplicate track for %s (optype=%d)", subscription->resource->path, optype);
		return;
	}

	/* Lock the resource mutex to protect shared state */
	pthread_mutex_lock(&subscription->resource->mutex);

	/* Record basic activity in circular buffer */
	scanner_record(subscription->profile, subscription->resource->last_time, subscription->resource->path, optype);

	/* Get the watch for this subscription */
	watch_t *subscription_watch = registry_get(monitor->registry, subscription->watchref);
	if (!subscription_watch) {
		log_message(WARNING, "Cannot get watch for subscription %s in scanner_track", subscription->resource->path);
		pthread_mutex_unlock(&subscription->resource->mutex);
		return;
	}

	/* If the event is on a directory that is the root of any watch, handle it */
	if (subscription->resource->kind == ENTITY_DIRECTORY && strcmp(subscription->resource->path, subscription_watch->path) == 0) {
		scanner_root(monitor, subscription, optype);
	}
	/* Otherwise, if it's a recursive watch, it must be a sub-path event */
	else if (subscription_watch->recursive) {
		scanner_recursive(monitor, subscription, optype);
	}

	/* Record the timestamp of this operation to prevent duplicates */
	subscription->resource->op_time = subscription->resource->last_time;

	/* Unlock the profile mutex */
	pthread_mutex_unlock(&subscription->resource->mutex);
}

/* Calculate base quiet period based on recent change magnitude */
static long scanner_base(int recent_files, int recent_dirs, int recent_depth, ssize_t recent_size, bool temp_files) {
	int total_change = recent_files + recent_dirs;

	/* Start with a base quiet period based primarily on change magnitude */
	if (total_change == 0 && recent_depth == 0 && recent_size == 0) {
		/* No change - minimal quiet period, unless temp files were detected */
		return temp_files ? 1000 : 250;
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

/* Calculate current activity magnitude (changes from reference state) */
static void scanner_recent(subscription_t *subscription, int *recent_files, int *recent_dirs, int *recent_depth, ssize_t *recent_size) {
	/* Calculate changes from the previous scan state to measure the current rate of change */
	if (subscription->profile->stability) {
		*recent_depth = abs(subscription->profile->stability->stats.max_depth - subscription->profile->stability->prev_stats.max_depth);
		*recent_files = abs(subscription->profile->stability->stats.tree_files - subscription->profile->stability->prev_stats.tree_files);
		*recent_dirs = abs(subscription->profile->stability->stats.tree_dirs - subscription->profile->stability->prev_stats.tree_dirs);
		*recent_size = labs((ssize_t) subscription->profile->stability->stats.tree_size -
							(ssize_t) subscription->profile->stability->prev_stats.tree_size);
	} else {
		*recent_depth = 0;
		*recent_files = 0;
		*recent_dirs = 0;
		*recent_size = 0;
	}
}

/* Apply stability, depth, and size adjustments to quiet period */
static long scanner_adjust(monitor_t *monitor, subscription_t *subscription, long base_ms, int recent_change) {
	long required_ms = base_ms;
	int tree_entries = 0;
	int tree_depth = 0;

	if (subscription->profile->stability) {
		tree_entries = subscription->profile->stability->stats.tree_files + subscription->profile->stability->stats.tree_dirs;
		tree_depth = subscription->profile->stability->stats.max_depth > 0 ? subscription->profile->stability->stats.max_depth :
																			 subscription->profile->stability->stats.depth;
	}

	/* If stability was previously achieved and then lost, increase quiet period */
	if (subscription->profile->stability && subscription->profile->stability->stability_lost) {
		/* We need a more careful check for resumed activity */
		long pre_stability = required_ms;
		required_ms = (long) (required_ms * 1.25); /* 25% increase */
		log_message(DEBUG, "Applied stability loss penalty: %ld ms -> %ld ms", pre_stability, required_ms);
	}

	/* Get complexity from watch for sensitivity calculations */
	watch_t *watch = registry_get(monitor->registry, subscription->watchref);
	double complexity = watch ? watch->complexity : 1.0;

	/* Tree depth multiplier, based on recent activity rate and complexity */
	if (tree_depth > 0) {
		/* Use complexity-based sensitivity factor */
		int change_level = (recent_change <= 1) ? 0 : 1;
		float depth_factor = (float) complexity_sensitivity(complexity, change_level);
		required_ms += tree_depth * 150 * depth_factor; /* 150ms per level */
	}

	/* Directory size complexity factor, based on recent activity and complexity */
	if (tree_entries > 100) {
		/* Use complexity-based sensitivity factor */
		int change_level = (recent_change <= 3) ? 0 : 1;
		float size_factor = (float) complexity_sensitivity(complexity, change_level);
		int size_addition = (int) (250 * size_factor * (tree_entries / 200.0));
		/* Cap the size adjustment for small operations */
		if (recent_change <= 1 && size_addition > 300) size_addition = 300;
		required_ms += size_addition;
	}

	if (subscription->profile->stability) {
		/* Calculate a cumulative magnitude factor to scale the quiet period */
		ssize_t cumulative_size = subscription->profile->stability->delta_size > 0 ? subscription->profile->stability->delta_size : 0;
		int cumulative_size_weight = (int) (cumulative_size / (100 * 1024 * 1024)); /* 1 point per 100MB */

		int cumulative_magnitude = abs(subscription->profile->stability->delta_files) + abs(subscription->profile->stability->delta_dirs) +
								   abs(subscription->profile->stability->delta_depth) + cumulative_size_weight;

		/* Only apply the multiplier if the cumulative change is significant */
		if (cumulative_magnitude > 100) {
			float magnitude_factor = 1.0 + (cumulative_magnitude / 50.0);

			/* Cap the factor to prevent excessively long quiet periods */
			if (magnitude_factor > 5.0) {
				magnitude_factor = 5.0;
			}

			long pre_magnitude = required_ms;
			required_ms = (long) (required_ms * magnitude_factor);
			log_message(DEBUG, "Applied magnitude factor %.2f: %ld ms -> %ld ms", magnitude_factor, pre_magnitude, required_ms);
		}
	}

	return required_ms;
}

/* Apply exponential backoff for registered instability */
static long scanner_backoff(monitor_t *monitor, subscription_t *subscription, long required_ms) {
	int unstable_count = subscription->profile->stability ? subscription->profile->stability->unstable_count : 0;

	if (unstable_count == 0) {
		return required_ms;
	}

	/* Get watch complexity for backoff calculation */
	watch_t *watch = registry_get(monitor->registry, subscription->watchref);
	double complexity = watch ? watch->complexity : 1.0;
	double complexity_multiplier = complexity_backoff(complexity);

	/* Start with a base multiplier */
	double backoff_factor = 1.0;

	/* Increase backoff factor for each instability occurrence using complexity-based multiplier */
	for (int i = 1; i <= unstable_count; i++) {
		backoff_factor *= complexity_multiplier;
	}

	/* Apply a cap to the backoff factor to prevent excessive delays */
	if (backoff_factor > 10.0) {
		backoff_factor = 10.0;
	}

	long adjusted_ms = (long) (required_ms * backoff_factor);
	log_message(DEBUG, "Applied backoff factor %.2f: %ld ms -> %ld ms", backoff_factor,
				required_ms, adjusted_ms);

	return adjusted_ms;
}

/* Apply final limits and complexity multiplier */
static long scanner_limit(monitor_t *monitor, subscription_t *subscription, long required_ms) {
	/* Set reasonable limits */
	if (required_ms < 100) required_ms = 100;

	/* Dynamic cap based on operation characteristics */
	long maximum_ms = 120000; /* Default 120 seconds */

	if (required_ms > maximum_ms) {
		log_message(DEBUG, "Capping quiet period for %s from %ld ms to %ld ms", subscription->resource->path,
					required_ms, maximum_ms);
		required_ms = maximum_ms;
	}

	/* Apply complexity-based stability factor from watch config */
	watch_t *subscription_watch = registry_get(monitor->registry, subscription->watchref);
	if (subscription_watch && subscription_watch->complexity > 0) {
		long pre_multiplier = required_ms;
		double stability_factor = complexity_stability(subscription_watch->complexity);
		required_ms = (long) (required_ms * stability_factor);
		log_message(DEBUG, "Applied stability factor %.2f to %s: %ld ms -> %ld ms", stability_factor,
					subscription->resource->path, pre_multiplier, required_ms);
	}

	return required_ms;
}

/* Determine the required quiet period based on state type and activity */
long scanner_delay(monitor_t *monitor, subscription_t *subscription) {
	if (!subscription) return QUIET_PERIOD_MS;

	long required_ms = QUIET_PERIOD_MS;

	/* For non-directories, use default period */
	if (subscription->resource->kind != ENTITY_DIRECTORY) {
		return scanner_limit(monitor, subscription, required_ms);
	}

	/* Use a longer base period for directories */
	required_ms = DIR_QUIET_PERIOD_MS; /* Default 1000ms */

	/* For inactive directories, just log the base period with recursive stats */
	bool active = subscription->profile->scanner ? subscription->profile->scanner->active : false;
	if (!active) {
		int tree_entries = 0;
		int tree_depth = 0;
		int num_subdir = 0;
		if (subscription->profile->stability) {
			tree_entries = subscription->profile->stability->stats.tree_files + subscription->profile->stability->stats.tree_dirs;
			tree_depth = subscription->profile->stability->stats.max_depth > 0 ? subscription->profile->stability->stats.max_depth :
																				 subscription->profile->stability->stats.depth;
			num_subdir = subscription->profile->stability->stats.tree_dirs;
		}

		log_message(DEBUG, "Using base quiet period for %s: %ld ms (recursive entries: %d, depth: %d, subdirs: %d)",
					subscription->resource->path, required_ms, tree_entries, tree_depth, num_subdir);
		return scanner_limit(monitor, subscription, required_ms);
	}

	/* For active directories, use adaptive complexity measurement */
	int tree_entries = 0;
	int tree_depth = 0;
	if (subscription->profile->stability) {
		tree_entries = subscription->profile->stability->stats.tree_files + subscription->profile->stability->stats.tree_dirs;
		tree_depth = subscription->profile->stability->stats.max_depth > 0 ? subscription->profile->stability->stats.max_depth :
																			 subscription->profile->stability->stats.depth;
	}

	/* Get recent activity to drive the base period calculation */
	int recent_files, recent_dirs, recent_depth;
	ssize_t recent_size;
	scanner_recent(subscription, &recent_files, &recent_dirs, &recent_depth, &recent_size);

	/* No recent activity, consider cumulative changes to maintain a stable quiet period */
	bool has_recent_activity = (recent_files > 0 || recent_dirs > 0 || recent_depth > 0 || recent_size > 0);
	if (!has_recent_activity && subscription->profile->stability) {
		log_message(DEBUG, "No recent activity detected, using cumulative changes for quiet period base");
		recent_files = abs(subscription->profile->stability->delta_files);
		recent_dirs = abs(subscription->profile->stability->delta_dirs);
		recent_depth = abs(subscription->profile->stability->delta_depth);
		recent_size = subscription->profile->stability->delta_size > 0 ? subscription->profile->stability->delta_size : 0;
	}

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
				subscription->resource->path, recent_files, recent_dirs, recent_depth, format_size(recent_size, true),
				size_weight, recent_change);

	/* Check for temporary files that indicate instability */
	bool temp_files = subscription->profile->stability ? subscription->profile->stability->stats.temp_files : false;

	/* Calculate base period from recent change magnitude */
	required_ms = scanner_base(recent_files, recent_dirs, recent_depth, recent_size, temp_files);

	/* Apply stability adjustments (depth, size, stability loss) */
	required_ms = scanner_adjust(monitor, subscription, required_ms, recent_change);

	/* Apply exponential backoff for consecutive instability */
	required_ms = scanner_backoff(monitor, subscription, required_ms);

	int delta_files = subscription->profile->stability ? subscription->profile->stability->delta_files : 0;
	int delta_dirs = subscription->profile->stability ? subscription->profile->stability->delta_dirs : 0;
	int delta_depth = subscription->profile->stability ? subscription->profile->stability->delta_depth : 0;
	ssize_t delta_size = subscription->profile->stability ? subscription->profile->stability->delta_size : 0;

	log_message(DEBUG, "Quiet for %s: %ld ms (cumulative: %+d files, %+d dirs, %+d depth, %s size) (total: %d entries, %d depth)",
				subscription->resource->path, required_ms, delta_files, delta_dirs, delta_depth, format_size(delta_size, true),
				tree_entries, tree_depth);

	/* Apply final limits and complexity multiplier */
	return scanner_limit(monitor, subscription, required_ms);
}

/* Check if enough quiet time has passed since the last activity */
bool scanner_ready(monitor_t *monitor, subscription_t *subscription, struct timespec *current_time, long required_quiet) {
	if (!subscription || !current_time) return true; /* Cannot check, assume elapsed */

	struct timespec *scanner_time = NULL;
	const char *source_path = subscription->resource->path;

	/* Get the watch for timestamp checking */
	watch_t *subscription_watch = registry_get(monitor->registry, subscription->watchref);

	/* Determine which timestamp to check against */
	if (subscription->resource->kind == ENTITY_DIRECTORY && subscription_watch && subscription_watch->recursive) {
		/* For recursive directory watches, always check the root's tree time */
		subscription_t *root = stability_root(monitor, subscription);
		if (root) {
			scanner_time = root->profile->scanner ? &root->profile->scanner->latest_time : &root->resource->last_time;
			source_path = root->resource->path;
		} else {
			log_message(WARNING, "Cannot find root subscription for %s, falling back to local activity", subscription->resource->path);
			/* Fallback: use local activity if root not found */
			if (!subscription->profile->scanner || subscription->profile->scanner->sample_count == 0) return true;
			int latest_idx = (subscription->profile->scanner->sample_index + MAX_SAMPLES - 1) % MAX_SAMPLES;
			scanner_time = &subscription->profile->scanner->samples[latest_idx].timestamp;
		}
	} else {
		/* For files or non-recursive dirs, use local activity time */
		if (!subscription->profile->scanner || subscription->profile->scanner->sample_count == 0) return true;
		int latest_idx = (subscription->profile->scanner->sample_index + MAX_SAMPLES - 1) % MAX_SAMPLES;
		scanner_time = &subscription->profile->scanner->samples[latest_idx].timestamp;
	}

	/* Check for valid timestamp */
	if (!scanner_time || (scanner_time->tv_sec == 0 && scanner_time->tv_nsec == 0)) {
		log_message(DEBUG, "No valid activity timestamp for %s, quiet period assumed elapsed", subscription->resource->path);
		return true;
	}

	/* Calculate elapsed time */
	long elapsed_ms;
	if (timespec_before(current_time, scanner_time)) {
		elapsed_ms = -1; /* Clock went backwards */
	} else {
		elapsed_ms = timespec_diff(current_time, scanner_time);
	}

	if (elapsed_ms < 0) {
		log_message(WARNING, "Clock appears to have moved backwards for %s, assuming quiet period elapsed",
					subscription->resource->path);
		return true;
	}

	bool elapsed = elapsed_ms >= required_quiet;

	if (!elapsed) {
		log_message(DEBUG, "Quiet period check for %s: %ld ms elapsed < %ld ms required (using time from %s)",
					subscription->resource->path, elapsed_ms, required_quiet, source_path);
	} else {
		log_message(DEBUG, "Quiet period elapsed for %s: %ld ms >= %ld ms required",
					subscription->resource->path, elapsed_ms, required_quiet);
	}

	return elapsed;
}
