#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <sys/stat.h>
#include <libgen.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <dirent.h>

#include "states.h"
#include "command.h"
#include "logger.h"
#include "monitor.h"

/* Hash table size for storing entity states */
#define ENTITY_HASH_SIZE 1024

/* External reference to the current monitor instance */
extern monitor_t *g_current_monitor;

/* Hash table of entity states */
static entity_state_t **entity_states = NULL;

/* Initialize the entity state system */
bool entity_state_init(void) {
	entity_states = calloc(ENTITY_HASH_SIZE, sizeof(entity_state_t *));
	if (entity_states == NULL) {
		log_message(LOG_LEVEL_ERR, "Failed to allocate memory for entity states");
		return false;
	}
	
	log_message(LOG_LEVEL_DEBUG, "Entity state system initialized");
	return true;
}

/* Free resources used by an entity state */
static void free_entity_state(entity_state_t *state) {
	if (state) {
		free(state->path);
		/* watch_entry_t *watch is owned by config, do not free here */
		free(state);
	}
}

/* Clean up the entity state system */
void entity_state_cleanup(void) {
	if (entity_states == NULL) return;
	
	/* Free all entity states */
	for (int i = 0; i < ENTITY_HASH_SIZE; i++) {
		entity_state_t *state = entity_states[i];
		while (state) {
			entity_state_t *next = state->next;
			free_entity_state(state);
			state = next;
		}
		entity_states[i] = NULL;
	}
	free(entity_states);
	entity_states = NULL;
	log_message(LOG_LEVEL_DEBUG, "Entity state system cleanup complete");
}

/* Calculate a hash value for a path and watch combination */
static unsigned int hash_path_watch(const char *path, watch_entry_t *watch) {
	unsigned int hash = 5381; /* djb2 hash initial value */
	if (!path || !watch || !watch->name) return 0;
	
	/* djb2 hash algorithm for better distribution */
	for (const char *p = path; *p; p++) {
		hash = ((hash << 5) + hash) + (unsigned char)*p;
	}
	
	/* Add separator to distinguish path from watch name */
	hash = ((hash << 5) + hash) + '|';
	
	for (const char *p = watch->name; *p; p++) {
		hash = ((hash << 5) + hash) + (unsigned char)*p;
	}
	
	return hash % ENTITY_HASH_SIZE;
}

/* Check if an entity state is corrupted */
static bool is_entity_state_corrupted(entity_state_t *state) {
	if (!state) return true;
	
	/* Basic sanity check - try to detect completely invalid pointers */
	if ((uintptr_t)state < 0x1000 || ((uintptr_t)state & 0x7) != 0) {
		log_message(LOG_LEVEL_WARNING, "Entity state appears to be invalid pointer: %p", state);
		return true;
	}
	
	if (state->magic != ENTITY_STATE_MAGIC) {
		log_message(LOG_LEVEL_WARNING, "Entity state corruption detected: magic=0x%x, expected=0x%x", 
				   state->magic, ENTITY_STATE_MAGIC);
		return true;
	}
	return false;
}

/* Initialize activity tracking for a new entity state */
static void init_activity_tracking(entity_state_t *state, watch_entry_t *watch) {
	if (!state) return;
	
	state->activity_sample_count = 0;
	state->activity_index = 0;
	state->activity_in_progress = false;
	state->watch = watch;

	/* Initialize tree time. Use last_update as a reasonable starting point. */
	state->last_activity_in_tree = state->last_update;
}

/* Initialize change tracking fields for a new entity state */
void init_change_tracking(entity_state_t *state) {
	if (!state) return;
	
	/* Initialize stable reference stats with current stats */
	state->stable_reference_stats = state->dir_stats;
	state->reference_stats_initialized = true;
	
	/* Reset all cumulative change counters */
	state->cumulative_file_change = 0;
	state->cumulative_dir_change = 0;
	state->cumulative_depth_change = 0;
	state->stability_lost = false;
	
	log_message(LOG_LEVEL_DEBUG, 
			  "Initialized change tracking for %s with reference stats: files=%d, dirs=%d, depth=%d",
			  state->path, state->stable_reference_stats.file_count, 
			  state->stable_reference_stats.dir_count, state->stable_reference_stats.depth);
}

/* Update cumulative changes based on current vs. previous stats */
void update_cumulative_changes(entity_state_t *state) {
	if (!state) return;
	
	/* Skip if we don't have previous stats yet */
	if (state->prev_stats.file_count == 0 && state->prev_stats.dir_count == 0 && 
		state->prev_stats.recursive_file_count == 0 && state->prev_stats.recursive_dir_count == 0) {
		return;
	}
	
	/* Calculate incremental changes */
	int new_file_change = state->dir_stats.recursive_file_count - state->prev_stats.recursive_file_count;
	int new_dir_change = state->dir_stats.recursive_dir_count - state->prev_stats.recursive_dir_count;
	int new_depth_change = state->dir_stats.max_depth - state->prev_stats.max_depth;
	
	/* Fix for deletion depth tracking: If significant directory deletion 
	   but no depth change reported, infer a depth change */
	if (new_dir_change < -5 && new_depth_change == 0) {
		/* Large structure deletion detected but depth unchanged - likely a bug */
		log_message(LOG_LEVEL_DEBUG, 
				  "Deletion detected with no depth change for %s - inferring depth reduction",
				  state->path);
		
		/* Calculate inferred depth change proportional to directory removal */
		float deletion_ratio = (float)abs(new_dir_change) / 
							  (state->prev_stats.recursive_dir_count > 0 ? 
							   state->prev_stats.recursive_dir_count : 10);
		
		/* Scale depth change based on deletion magnitude */
		if (deletion_ratio > 0.5) {
			new_depth_change = -2; /* Major deletion, likely multiple levels */
		} else {
			new_depth_change = -1; /* Standard deletion, at least one level */
		}
	}
	
	/* Accumulate changes */
	state->cumulative_file_change += new_file_change;
	state->cumulative_dir_change += new_dir_change;
	state->cumulative_depth_change += new_depth_change;
	
	/* Set flag indicating stability was lost if we're detecting new changes
	   after activity was previously not in progress */
	if (!state->activity_in_progress && (new_file_change != 0 || new_dir_change != 0 || new_depth_change != 0)) {
		state->stability_lost = true;
	}
	
	/* Log significant cumulative changes */
	if (new_file_change != 0 || new_dir_change != 0 || new_depth_change != 0) {
		log_message(LOG_LEVEL_DEBUG, 
				  "Updated cumulative changes for %s: files=%+d (%+d), dirs=%+d (%+d), depth=%+d (%+d)",
				  state->path, 
				  state->cumulative_file_change, new_file_change,
				  state->cumulative_dir_change, new_dir_change,
				  state->cumulative_depth_change, new_depth_change);
	}
}

/* Gather basic directory statistics */
bool gather_basic_directory_stats(const char *dir_path, dir_stats_t *stats, int recursion_depth) {
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
		log_message(LOG_LEVEL_WARNING, "Failed to open directory for stats gathering: %s", dir_path);
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
			stats->total_size += st.st_size;
			
			/* Update latest modification time */
			if (st.st_mtime > stats->latest_mtime) {
				stats->latest_mtime = st.st_mtime;
			}
		
		} else if (S_ISDIR(st.st_mode)) {
			stats->dir_count++;
			
			dir_stats_t subdir_stats;
			if (gather_basic_directory_stats(path, &subdir_stats, recursion_depth + 1)) {
				/* Update maximum tree depth based on subdirectory scan results */
				if (subdir_stats.depth + 1 > stats->depth) {
					stats->depth = subdir_stats.depth + 1;
				}
				
				/* Incorporate subdirectory size */
				stats->total_size += subdir_stats.total_size;
				
				/* Calculate and update recursive stats */
				if (subdir_stats.recursive_file_count > 0 || subdir_stats.recursive_dir_count > 0) {
					/* Subdirectory already has recursive stats, use them */
					stats->recursive_file_count += subdir_stats.recursive_file_count;
					stats->recursive_dir_count += subdir_stats.recursive_dir_count;
					stats->recursive_total_size += subdir_stats.recursive_total_size;
					
					/* Update max_depth considering subdirectory's max depth */
					if (subdir_stats.max_depth + 1 > stats->max_depth) {
						stats->max_depth = subdir_stats.max_depth + 1;
					}
				} else {
					/* Subdirectory doesn't have recursive stats, use direct stats */
					stats->recursive_file_count += subdir_stats.file_count;
					stats->recursive_dir_count += subdir_stats.dir_count;
					stats->recursive_total_size += subdir_stats.total_size;
					
					/* Update max_depth considering subdirectory's depth */
					if (subdir_stats.depth + 1 > stats->max_depth) {
						stats->max_depth = subdir_stats.depth + 1;
					}
				}
				
				if (subdir_stats.latest_mtime > stats->latest_mtime) {
					stats->latest_mtime = subdir_stats.latest_mtime;
				}
			}
		}
	}
	
	/* Ensure recursive stats include direct stats at this level */
	stats->recursive_file_count += stats->file_count;
	stats->recursive_dir_count += stats->dir_count;
	stats->recursive_total_size += stats->total_size;
	
	/* If max_depth is not set, use depth */
	if (stats->max_depth == 0 && stats->depth > 0) {
		stats->max_depth = stats->depth;
	}
	
	closedir(dir);
	return true;
}

/* Compare two directory statistics to check for stability */
bool compare_dir_stats(dir_stats_t *prev, dir_stats_t *current) {
	if (!prev || !current) return false;
	
	/* Calculate content changes */
	int file_change = current->file_count - prev->file_count;
	int dir_change = current->dir_count - prev->dir_count;
	int depth_change = current->depth - prev->depth;
	int total_change = abs(file_change) + abs(dir_change);
	
	/* Log depth changes */
	if (depth_change != 0) {
		log_message(LOG_LEVEL_DEBUG, "Directory tree depth changed: %d -> %d (%+d levels)",
						  prev->depth, current->depth, depth_change);
	}
	
	/* Allow small changes for larger directories */
	int prev_total = prev->file_count + prev->dir_count;
	float change_percentage = (prev_total > 0) ? ((float)total_change / prev_total) * 100.0 : 0;
	
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
	
	/* Always consider unstable if tree depth changes significantly */
	if (abs(depth_change) > 1) {
		log_message(LOG_LEVEL_DEBUG, "Directory unstable: significant tree depth change (%+d levels)",
						  depth_change);
		return false;
	}
	
	/* Consider stable if changes are within allowances and depth stable or minimal change */
	if ((total_change <= max_allowed_change || change_percentage <= max_allowed_percent) &&
		(depth_change == 0 || (abs(depth_change) == 1 && prev->depth > 2))) {
		/* Changes within threshold - considered stable */
		if (total_change > 0 || depth_change != 0) {
			log_message(LOG_LEVEL_DEBUG, 
					  "Directory considered stable despite small changes: %+d files, %+d dirs, %+d depth (%.1f%% change)",
						  file_change, dir_change, depth_change, change_percentage);
		}
		return true;
	}
	
	/* Too many changes - unstable */
	log_message(LOG_LEVEL_DEBUG, 
			  "Directory unstable: %d/%d to %d/%d, depth %d to %d (%+d files, %+d dirs, %+d depth, %.1f%% change)",
						prev->file_count, prev->dir_count, 
						current->file_count, current->dir_count,
						prev->depth, current->depth,
						file_change, dir_change, depth_change, change_percentage);
	return false;
	
	/* Keep existing size and temp file checks */
	/* Check if total size is stable (allowing for small changes) */
	long size_diff = labs((long)prev->total_size - (long)current->total_size);
	long threshold = prev->total_size > 1000000 ? 
					 prev->total_size / 10000 : /* 0.01% for large dirs */
					 1024;                      /* 1KB for small dirs */
	
	if (size_diff > threshold) {
		log_message(LOG_LEVEL_DEBUG, "Directory unstable: size changed by %ld bytes (threshold: %ld)",
				   size_diff, threshold);
		return false;
	}
	
	/* Check for temporary files */
	if (current->has_temp_files) {
		log_message(LOG_LEVEL_DEBUG, "Directory unstable: temporary files detected");
		return false;
	}
	
	return true;
}

/* Function to check if a file should be ignored in stability checks */
bool is_system_file_to_ignore(const char *filename) {
	/* List of known system files that should not be treated as temporary */
	static const char *system_files[] = {
		".localized",        /* macOS localization file */
		".DS_Store",         /* macOS folder metadata */
		"desktop.ini",       /* Windows folder customization */
		"Thumbs.db",         /* Windows thumbnail cache */
		".directory",        /* KDE folder metadata */
		"folder.jpg",        /* Folder image for media folders */
		".hidden",           /* Hidden file marker on some systems */
		"Icon\r",            /* macOS custom folder icon marker */
		NULL                 /* End of list marker */
	};
	
	/* Check against our list of known system files */
	for (int i = 0; system_files[i] != NULL; i++) {
		if (strcmp(filename, system_files[i]) == 0) {
			return true;
		}
	}
	
	return false;
}

/* Collect statistics about a directory and its contents */
bool verify_directory_stability(const char *dir_path, dir_stats_t *stats, int recursion_depth) {
	DIR *dir;
	struct dirent *entry;
	struct stat st;
	char path[PATH_MAX];
	
	if (!dir_path || !stats) {
		return false;
	}
	
	/* Check if we should use an existing directory state's statistics as a baseline */
	bool use_existing_stats = false;
	entity_state_t *existing_state = NULL;
	
	/* Look through all hash buckets for an existing state for this path */
	if (entity_states) {
		for (int i = 0; i < ENTITY_HASH_SIZE; i++) {
			entity_state_t *state = entity_states[i];
			while (state) {
				if (strcmp(state->path, dir_path) == 0) {
					/* Found an existing state for this path */
					existing_state = state;
					
					/* If the existing state has valid stats, consider using them 
					 * Check if we have more than just default values */
					if (state->dir_stats.file_count > 0 || 
						state->dir_stats.dir_count > 0 ||
						state->dir_stats.depth > 0 ||
						state->dir_stats.recursive_file_count > 0 ||
						state->dir_stats.recursive_dir_count > 0 ||
						state->dir_stats.max_depth > 0) {
						use_existing_stats = true;
						break;
					}
				}
				state = state->next;
			}
			if (use_existing_stats) break;
		}
	}
	
	/* If we found an existing state with valid stats, use that for verification */
	if (use_existing_stats && existing_state) {
		log_message(LOG_LEVEL_DEBUG, 
				  "Using existing stats for stability verification of %s: files=%d, dirs=%d, depth=%d, recursive_files=%d, recursive_dirs=%d, max_depth=%d",
				  dir_path, existing_state->dir_stats.file_count, 
				  existing_state->dir_stats.dir_count, existing_state->dir_stats.depth,
				  existing_state->dir_stats.recursive_file_count,
				  existing_state->dir_stats.recursive_dir_count,
				  existing_state->dir_stats.max_depth);
		
		/* Make a copy of the existing stats */
		*stats = existing_state->dir_stats;
		
		/* Still scan the directory, but only to check for temporary files */
		dir = opendir(dir_path);
		if (!dir) {
			log_message(LOG_LEVEL_WARNING, "Failed to open directory for stability check: %s", dir_path);
			return false;
		}
		
		time_t now;
		time(&now);
		
		/* Just check for temporary files without recounting everything */
		stats->has_temp_files = false;
		
		while ((entry = readdir(dir))) {
			/* Skip . and .. */
			if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
				continue;
			}
			
			snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);
			
			if (stat(path, &st) != 0) {
				/* If a file disappears during scan, the directory is not stable */
				log_message(LOG_LEVEL_DEBUG, "Directory %s unstable: file disappeared during scan", dir_path);
				closedir(dir);
				return false;
			}
			
			/* Check only for temporary files or very recent changes */
			if (S_ISREG(st.st_mode)) {
				/* Skip known system files */
				if (is_system_file_to_ignore(entry->d_name)) {
					continue;
				}
				
				/* Check for very recent file modifications (< 1 second) */
				if (difftime(now, st.st_mtime) < 1.0) {
					log_message(LOG_LEVEL_DEBUG, "Directory %s unstable: recent file modification (%s, %.1f seconds ago)", 
							  dir_path, entry->d_name, difftime(now, st.st_mtime));
					stats->has_temp_files = true;
					closedir(dir);
					return false;
				}
				
				/* Check for temporary files */
				if ((st.st_size == 0 && difftime(now, st.st_mtime) < 5.0) || 
					strstr(entry->d_name, ".tmp") != NULL || 
					strstr(entry->d_name, ".part") != NULL || 
					strstr(entry->d_name, ".~") != NULL ||
					strstr(entry->d_name, ".crdownload") != NULL ||
					strstr(entry->d_name, ".download") != NULL) {
					log_message(LOG_LEVEL_DEBUG, "Directory %s unstable: temp file detected (%s)", dir_path, entry->d_name);
					stats->has_temp_files = true;
					closedir(dir);
					return false;
				}
			} else if (S_ISDIR(st.st_mode) && recursion_depth <= 5) {
				/* Quick check of subdirectories but only to limited depth */
				dir_stats_t subdir_stats;
				memset(&subdir_stats, 0, sizeof(dir_stats_t));
				
				if (!verify_directory_stability(path, &subdir_stats, recursion_depth + 1)) {
					closedir(dir);
					return false;
				}
				
				if (subdir_stats.has_temp_files) {
					stats->has_temp_files = true;
					closedir(dir);
					return false;
				}
			}
		}
		
		closedir(dir);
		return !stats->has_temp_files;
	}
	
	/* Initialize stats including the new recursive fields */
	memset(stats, 0, sizeof(dir_stats_t));
	
	dir = opendir(dir_path);
	if (!dir) {
		log_message(LOG_LEVEL_WARNING, "Failed to open directory for stability check: %s", dir_path);
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
			log_message(LOG_LEVEL_DEBUG, "Directory %s unstable: file disappeared during scan", dir_path);
			closedir(dir);
			return false;
		}
		
		/* Look for temporary files or recent changes */
		if (S_ISREG(st.st_mode)) {
			stats->file_count++;
			stats->total_size += st.st_size;
			
			/* Update latest modification time */
			if (st.st_mtime > stats->latest_mtime) {
				stats->latest_mtime = st.st_mtime;
			}
			
			/* Skip known system files */
			if (is_system_file_to_ignore(entry->d_name)) {
				continue;
			}
			
			/* Check for very recent file modifications (< 1 seconds) */
			if (difftime(now, st.st_mtime) < 1.0) {
				log_message(LOG_LEVEL_DEBUG, "Directory %s unstable: recent file modification (%s, %.1f seconds ago)", 
						  dir_path, entry->d_name, difftime(now, st.st_mtime));
				stats->has_temp_files = true;
				closedir(dir);
				return false;
			}
			
			/* Check for temporary files */
			if ((st.st_size == 0 && difftime(now, st.st_mtime) < 5.0) || 
				strstr(entry->d_name, ".tmp") != NULL || 
				strstr(entry->d_name, ".part") != NULL || 
				strstr(entry->d_name, ".~") != NULL ||
				strstr(entry->d_name, ".crdownload") != NULL ||
				strstr(entry->d_name, ".download") != NULL) {
				log_message(LOG_LEVEL_DEBUG, "Directory %s unstable: temp file detected (%s)", dir_path, entry->d_name);
				stats->has_temp_files = true;
				closedir(dir);
				return false;
			}
		} else if (S_ISDIR(st.st_mode)) {
			stats->dir_count++;
			
			dir_stats_t subdir_stats;
			if (!verify_directory_stability(path, &subdir_stats, recursion_depth + 1)) {
				closedir(dir);
				return false;
			}
			
			/* Update maximum tree depth based on subdirectory scan results */
			if (subdir_stats.depth + 1 > stats->depth) {
				stats->depth = subdir_stats.depth + 1;
			}
			
			/* Incorporate subdirectory size */
			stats->total_size += subdir_stats.total_size;
			
			/* Check for temp files */
			stats->has_temp_files |= subdir_stats.has_temp_files;
			
			/* Calculate and update recursive stats */
			if (subdir_stats.recursive_file_count > 0 || subdir_stats.recursive_dir_count > 0) {
				/* Subdirectory already has recursive stats, use them */
				stats->recursive_file_count += subdir_stats.recursive_file_count;
				stats->recursive_dir_count += subdir_stats.recursive_dir_count;
				stats->recursive_total_size += subdir_stats.recursive_total_size;
				
				/* Update max_depth considering subdirectory's max depth */
				if (subdir_stats.max_depth + 1 > stats->max_depth) {
					stats->max_depth = subdir_stats.max_depth + 1;
				}
			} else {
				/* Subdirectory doesn't have recursive stats, use direct stats */
				stats->recursive_file_count += subdir_stats.file_count;
				stats->recursive_dir_count += subdir_stats.dir_count;
				stats->recursive_total_size += subdir_stats.total_size;
				
				/* Update max_depth considering subdirectory's depth */
				if (subdir_stats.depth + 1 > stats->max_depth) {
					stats->max_depth = subdir_stats.depth + 1;
				}
			}
			
			if (subdir_stats.latest_mtime > stats->latest_mtime) {
				stats->latest_mtime = subdir_stats.latest_mtime;
			}
		}
	}
	
	/* Ensure recursive stats include direct stats at this level */
	stats->recursive_file_count += stats->file_count;
	stats->recursive_dir_count += stats->dir_count;
	stats->recursive_total_size += stats->total_size;
	
	/* If max_depth is not set, use depth */
	if (stats->max_depth == 0 && stats->depth > 0) {
		stats->max_depth = stats->depth;
	}
	
	closedir(dir);
	return !stats->has_temp_files;
}

/* Find the state corresponding to the root path of a watch */
entity_state_t *find_root_state(entity_state_t *state) {
	if (!state || !state->watch || !state->watch->path) {
		if (state && state->path) {
			log_message(LOG_LEVEL_WARNING, "Invalid watch info for state %s", state->path);
		}
		return NULL;
	}
	
	/* If current state is already the root, return it */
	if (strcmp(state->path, state->watch->path) == 0) {
		return state;
	}
	
	/* Otherwise, get the state for the watch path */
	return get_entity_state(state->watch->path, ENTITY_DIRECTORY, state->watch);
}

/* Find all entity states for a path (regardless of watch) */
void synchronize_activity_states(const char *path, entity_state_t *trigger_state) {
	if (!path || !trigger_state || !entity_states) {
		return;
	}
	
	log_message(LOG_LEVEL_DEBUG, "Synchronizing activity states for path: %s", path);
	
	/* First pass: Find the most recent activity timestamp across all watches for this path */
	struct timespec latest_activity_time = trigger_state->last_activity_in_tree;
	bool any_watch_active = trigger_state->activity_in_progress;
	
	for (int i = 0; i < ENTITY_HASH_SIZE; i++) {
		entity_state_t *state = entity_states[i];
		while (state) {
			/* Skip corrupted or invalid states */
			if (is_entity_state_corrupted(state) || !state->path || !state->watch) {
				log_message(LOG_LEVEL_DEBUG, "Skipping corrupted or invalid state during sync");
				state = state->next;
				continue;
			}
			
			if (strcmp(state->path, path) == 0 && state != trigger_state) {
				/* Take the most recent time between this state and our current latest */
				if (state->last_activity_in_tree.tv_sec > latest_activity_time.tv_sec ||
					(state->last_activity_in_tree.tv_sec == latest_activity_time.tv_sec && 
					 state->last_activity_in_tree.tv_nsec > latest_activity_time.tv_nsec)) {
					latest_activity_time = state->last_activity_in_tree;
				}
				
				/* Synchronize scheduling state */
				state->checking_scheduled = trigger_state->checking_scheduled;
				
				/* Record if any watch has active status */
				any_watch_active = any_watch_active || state->activity_in_progress;
			}
			state = state->next;
		}
	}
	
	/* Second pass: Update states with consistent values */
	for (int i = 0; i < ENTITY_HASH_SIZE; i++) {
		entity_state_t *state = entity_states[i];
		while (state) {
			/* Skip corrupted or invalid states */
			if (is_entity_state_corrupted(state) || !state->path || !state->watch) {
				log_message(LOG_LEVEL_DEBUG, "Skipping corrupted or invalid state during sync");
				state = state->next;
				continue;
			}
			
			if (strcmp(state->path, path) == 0 && state != trigger_state) {
				log_message(LOG_LEVEL_DEBUG, "Synchronizing state for path %s (watch: %s) with trigger (watch: %s)",
					   path, (state->watch && state->watch->name) ? state->watch->name : "unknown", 
					   (trigger_state->watch && trigger_state->watch->name) ? trigger_state->watch->name : "unknown");
				
				/* Determine watch configuration compatibility */
				bool fully_compatible = false;
				bool partially_compatible = false;
				
				/* Skip invalid states */
				if (!state->watch || !trigger_state->watch || 
					!state->watch->name || !trigger_state->watch->name) {
					log_message(LOG_LEVEL_DEBUG, "Skipping state with invalid watch pointers during sync");
					continue;
				}
				
				/* Check for full compatibility (same recursive setting, events, and hidden files setting) */
				if (state->watch->recursive == trigger_state->watch->recursive &&
					state->watch->events == trigger_state->watch->events &&
					state->watch->hidden == trigger_state->watch->hidden) {
					fully_compatible = true;
					log_message(LOG_LEVEL_DEBUG, "Fully compatible watches - syncing all stability data");
				}
				/* Check for partial compatibility (overlapping events) */
				else if (state->watch->events & trigger_state->watch->events) {
					partially_compatible = true;
					log_message(LOG_LEVEL_DEBUG, "Partially compatible watches - syncing basic stats only");
				}
				else {
					log_message(LOG_LEVEL_DEBUG, 
							  "Incompatible watches - minimal sync for %s and %s",
							  state->watch->name, trigger_state->watch->name);
				}
				
				/* Always sync these basic factual properties */
				state->exists = trigger_state->exists;
				state->last_update = trigger_state->last_update;
				state->wall_time = trigger_state->wall_time;
				
				/* Always sync the latest activity time to ensure coherent scheduling */
				state->last_activity_in_tree = latest_activity_time;
				
				/* Copy the most recent activity sample for basic timing consistency */
				if (trigger_state->activity_sample_count > 0) {
					int latest_idx = (trigger_state->activity_index + MAX_ACTIVITY_SAMPLES - 1) % MAX_ACTIVITY_SAMPLES;
					int target_idx = (state->activity_index + MAX_ACTIVITY_SAMPLES - 1) % MAX_ACTIVITY_SAMPLES;
					
					state->recent_activity[target_idx] = trigger_state->recent_activity[latest_idx];
					if (state->activity_sample_count == 0) {
						state->activity_sample_count = 1;
					}
				}
				
				/* Make activity_in_progress consistent across all states for the same path */
				state->activity_in_progress = any_watch_active;
				
				/* Sync change detection flags based on overlapping event types */
				if (state->watch->events & EVENT_CONTENT && trigger_state->watch->events & EVENT_CONTENT) {
					state->content_changed = state->content_changed || trigger_state->content_changed;
				}
				if (state->watch->events & EVENT_METADATA && trigger_state->watch->events & EVENT_METADATA) {
					state->metadata_changed = state->metadata_changed || trigger_state->metadata_changed;
				}
				if (state->watch->events & EVENT_MODIFY && trigger_state->watch->events & EVENT_MODIFY) {
					state->structure_changed = state->structure_changed || trigger_state->structure_changed;
				}
				
				/* Only sync directory statistics for fully or partially compatible watches */
				if ((fully_compatible || partially_compatible) && 
					state->type == ENTITY_DIRECTORY && trigger_state->type == ENTITY_DIRECTORY) {
					
					/* Always sync basic directory stats */
					state->dir_stats = trigger_state->dir_stats;
					
					/* For fully compatible watches, sync all stats and stability assessment */
					if (fully_compatible) {
						/* Initialize reference stats if needed */
						if (trigger_state->reference_stats_initialized && !state->reference_stats_initialized) {
							state->stable_reference_stats = trigger_state->stable_reference_stats;
							state->reference_stats_initialized = true;
							log_message(LOG_LEVEL_DEBUG, 
									  "Initialized reference stats for %s from trigger state", state->path);
						}
						
						/* Only update previous stats if they're valid in the trigger */
						if (trigger_state->prev_stats.file_count > 0 || trigger_state->prev_stats.dir_count > 0) {
							state->prev_stats = trigger_state->prev_stats;
						}
						
						/* Stability checks */
						state->stability_check_count = trigger_state->stability_check_count;
						state->failed_checks = trigger_state->failed_checks;
						
						/* For cumulative changes, take the values with the greatest magnitude */
						if (abs(trigger_state->cumulative_file_change) > abs(state->cumulative_file_change)) {
							state->cumulative_file_change = trigger_state->cumulative_file_change;
						}
						
						if (abs(trigger_state->cumulative_dir_change) > abs(state->cumulative_dir_change)) {
							state->cumulative_dir_change = trigger_state->cumulative_dir_change;
						}
						
						if (abs(trigger_state->cumulative_depth_change) > abs(state->cumulative_depth_change)) {
							state->cumulative_depth_change = trigger_state->cumulative_depth_change;
						}
						
						/* Stability lost flag - make this consistent across watches */
						state->stability_lost = state->stability_lost || trigger_state->stability_lost;
					}
					/* For partially compatible watches, sync directory stats but not stability assessment */
					else if (partially_compatible) {
						/* Initialize reference stats if needed but don't sync stability assessment */
						if (!state->reference_stats_initialized) {
							state->stable_reference_stats = state->dir_stats;
							state->reference_stats_initialized = true;
							log_message(LOG_LEVEL_DEBUG, 
									  "Initialized reference stats for %s from its own dir_stats", state->path);
						}
					}
				}
			}
			state = state->next;
		}
	}
}

/* Record a new activity event in the entity's history */
void record_activity(entity_state_t *state, operation_type_t op) {
	if (!state) return;

	/* Store in circular buffer */
	state->recent_activity[state->activity_index].timestamp = state->last_update;
	state->recent_activity[state->activity_index].operation = op;
	state->activity_index = (state->activity_index + 1) % MAX_ACTIVITY_SAMPLES;
	if (state->activity_sample_count < MAX_ACTIVITY_SAMPLES) {
		state->activity_sample_count++;
	}

	/* Reset stability check counter when new activity occurs */
	state->stability_check_count = 0;

	/* Update Root State's Tree Activity Time for recursive watches */
	if (state->watch && state->watch->recursive) {
		/* First, find the root state */
		entity_state_t *root = find_root_state(state);
		if (root) {
			/* Update the root's tree activity time */
			root->last_activity_in_tree = state->last_update;
			root->activity_in_progress = true;
			
			/* Reset root's stability checks */
			root->stability_check_count = 0;
			
			/* For directory operations, update directory stats immediately */
			if (op == OP_DIR_CONTENT_CHANGED && root->type == ENTITY_DIRECTORY) {
				dir_stats_t new_stats;
				if (gather_basic_directory_stats(root->path, &new_stats, 0)) {
					/* Save previous stats for comparison */
					root->prev_stats = root->dir_stats;
					/* Update with new stats */
					root->dir_stats = new_stats;
					
					/* Update cumulative changes */
					update_cumulative_changes(root);
					
					log_message(LOG_LEVEL_DEBUG, 
							  "Updated directory stats for %s after change: files=%d, dirs=%d, depth=%d (was: files=%d, dirs=%d, depth=%d)",
							  root->path, 
							  root->dir_stats.file_count, root->dir_stats.dir_count, root->dir_stats.depth,
							  root->prev_stats.file_count, root->prev_stats.dir_count, root->prev_stats.depth);
				}
			}
			
			/* Synchronize with other watches for the same path */
			synchronize_activity_states(root->path, root);
			
			/* Now propagate activity to all parent directories between this entity and root */
			char *path_copy = strdup(state->path);
			if (path_copy) {
				/* Get parent directory path */
				char *last_slash = strrchr(path_copy, '/');
				while (last_slash && last_slash > path_copy) {
					*last_slash = '\0';  /* Truncate to get parent directory */
					
					/* Skip if we've reached or gone beyond the root watch path */
					if (strlen(path_copy) < strlen(root->path)) {
						break;
					}
					
					/* Update state for this parent directory */
					entity_state_t *parent_state = get_entity_state(path_copy, ENTITY_DIRECTORY, state->watch);
					if (parent_state) {
						parent_state->last_activity_in_tree = state->last_update;
						parent_state->activity_in_progress = true;
						parent_state->stability_check_count = 0;
						
						/* Update directory stats for parent if this is a content change */
						if (op == OP_DIR_CONTENT_CHANGED && parent_state->type == ENTITY_DIRECTORY) {
							dir_stats_t parent_new_stats;
							if (gather_basic_directory_stats(parent_state->path, &parent_new_stats, 0)) {
								parent_state->prev_stats = parent_state->dir_stats;
								parent_state->dir_stats = parent_new_stats;
								
								/* Update cumulative changes */
								update_cumulative_changes(parent_state);
							}
						}
						
						synchronize_activity_states(parent_state->path, parent_state);
					}
					
					/* Move to next parent directory */
					last_slash = strrchr(path_copy, '/');
				}
				free(path_copy);
			}
		} else if (strcmp(state->path, state->watch->path) == 0) {
			/* This is the root itself */
			state->last_activity_in_tree = state->last_update;
			
			/* Update directory stats immediately for content changes to root */
			if (op == OP_DIR_CONTENT_CHANGED && state->type == ENTITY_DIRECTORY) {
				dir_stats_t new_stats;
				if (gather_basic_directory_stats(state->path, &new_stats, 0)) {
					/* Save previous stats for comparison */
					state->prev_stats = state->dir_stats;
					/* Update with new stats */
					state->dir_stats = new_stats;
					
					/* Update cumulative changes */
					update_cumulative_changes(state);
					
					log_message(LOG_LEVEL_DEBUG, 
							  "Updated directory stats for root %s after change: files=%d, dirs=%d, depth=%d",
							  state->path, state->dir_stats.file_count, state->dir_stats.dir_count, state->dir_stats.depth);
				}
			}
			
			synchronize_activity_states(state->path, state);
		}
	}
	
	/* Always sync the current state */
	synchronize_activity_states(state->path, state);
}

/* Calculate time between the last two recorded activities */
static long get_activity_interval_ms(entity_state_t *state) {
	if (!state || state->activity_sample_count < 2) return LONG_MAX;

	int latest_idx = (state->activity_index + MAX_ACTIVITY_SAMPLES - 1) % MAX_ACTIVITY_SAMPLES;
	int prev_idx = (latest_idx + MAX_ACTIVITY_SAMPLES - 1) % MAX_ACTIVITY_SAMPLES;

	struct timespec *newer = &state->recent_activity[latest_idx].timestamp;
	struct timespec *older = &state->recent_activity[prev_idx].timestamp;

	/* Handle potential timestamp wrapping or errors */
	if (newer->tv_sec < older->tv_sec || (newer->tv_sec == older->tv_sec && newer->tv_nsec < older->tv_nsec)) {
		log_message(LOG_LEVEL_WARNING, "Detected non-monotonic timestamps for %s", state->path);
		return LONG_MAX;
	}

	return (newer->tv_sec - older->tv_sec) * 1000 +
		   (long)(newer->tv_nsec - older->tv_nsec) / 1000000;
}

/* Analyze activity to detect if recent events form a burst pattern */
bool is_activity_burst(entity_state_t *state) {
	if (!state || state->activity_sample_count < 2) return false;
	
	long interval_ms = get_activity_interval_ms(state);
	long threshold = DIR_QUIET_PERIOD_MS / 2;
	if (threshold <= 0) threshold = 100; /* Reasonable minimum */
	
	return interval_ms < threshold;
}

/* Determine the required quiet period based on state type and activity */
long get_required_quiet_period(entity_state_t *state) {
	if (!state) return QUIET_PERIOD_MS;

	long required_ms = QUIET_PERIOD_MS;
	
	/* Use a longer base period for directories */
	if (state->type == ENTITY_DIRECTORY) {
		/* Default quiet period */
		required_ms = DIR_QUIET_PERIOD_MS; /* Default 1000ms */
		
		/* For active directories, use adaptive complexity measurement */
		if (state->activity_in_progress) {
			/* Extract complexity indicators */
			int total_entries = state->dir_stats.recursive_file_count + state->dir_stats.recursive_dir_count;
			int tree_depth = state->dir_stats.max_depth > 0 ? state->dir_stats.max_depth : state->dir_stats.depth;
			
			/* Use cumulative change counters instead of just prev/current comparison */
			int abs_file_change = abs(state->cumulative_file_change);
			int abs_dir_change = abs(state->cumulative_dir_change);
			int abs_depth_change = abs(state->cumulative_depth_change);
			int total_change = abs_file_change + abs_dir_change;
			
			/* Prioritize operation complexity */
			/* Start with a base quiet period based primarily on change magnitude */
			if (total_change == 0 && abs_depth_change == 0) {
				/* No change - minimal quiet period */
				required_ms = 250; 
			} else if (total_change < 5 && abs_depth_change == 0) {
				/* Few files change with no structural changes - short quiet period */
				required_ms = 500;
			} else if (total_change < 10 && abs_depth_change == 0) {
				/* Several files changed, no structural changes - modest quiet period */
				required_ms = 1000;
			} else if (abs_depth_change > 0) {
				/* Structural depth changes - significant quiet period */
				required_ms = 1500 + (abs_depth_change * 500);
			} else if (total_change < 10) {
				/* Moderate changes - medium quiet period */
				required_ms = 1200;
			} else {
				/* Many changes - longer quiet period */
				required_ms = 1500 + (total_change / 10) * 250;
			}
			
			/* If stability was previously achieved and then lost, increase quiet period */
			if (state->stability_lost) {
				/* We need a more careful check for resumed activity */
				required_ms = (long)(required_ms * 1.25); /* 25% increase */
				log_message(LOG_LEVEL_DEBUG, "Stability previously achieved and lost, increasing quiet period by 25%%");
			}
			
			/* Tree depth multiplier - less dominant than before */
			if (tree_depth > 0) {
				/* Scale down the depth impact for simple operations */
				float depth_factor = (total_change <= 1) ? 0.5 : 1.0;
				required_ms += tree_depth * 150 * depth_factor; /* Reduced from 250ms to 150ms per level */
			}
			
			/* Directory size complexity factor - minimal for small changes */
			if (total_entries > 100) {
				float size_factor = (total_change <= 3) ? 0.3 : 0.7;
				int size_addition = (int)(250 * size_factor * (total_entries / 200.0));
				/* Cap the size adjustment for small operations */
				if (total_change <= 1 && size_addition > 300) size_addition = 300;
				required_ms += size_addition;
			}
			
			log_message(LOG_LEVEL_DEBUG, 
					  "Using operation-centric quiet period for %s: %ld ms (cumulative changes: %+d files, %+d dirs, %+d depth, in dir with %d entries, depth %d)",
					  state->path, required_ms, state->cumulative_file_change, 
					  state->cumulative_dir_change, state->cumulative_depth_change, 
					  total_entries, tree_depth);
		}
		else {
			/* For inactive directories, just log the base period with recursive stats */
			int total_entries = state->dir_stats.recursive_file_count + state->dir_stats.recursive_dir_count;
			int tree_depth = state->dir_stats.max_depth > 0 ? state->dir_stats.max_depth : state->dir_stats.depth;
			int subdir_count = state->dir_stats.recursive_dir_count;
			
			log_message(LOG_LEVEL_DEBUG, 
					  "Using base quiet period for %s: %ld ms (recursive entries: %d, max depth: %d, total subdirs: %d)",
					  state->path, required_ms, total_entries, tree_depth, subdir_count);
		}
	}

	/* Set reasonable limits */
	if (required_ms < 10) required_ms = 10;
	if (required_ms > 10000) required_ms = 10000;  /* Cap at 10 seconds */
	
	return required_ms;
}

/* Check if enough quiet time has passed since the last activity */
bool is_quiet_period_elapsed(entity_state_t *state, struct timespec *now) {
	if (!state || !now) return true; /* Cannot check, assume elapsed */

	struct timespec *last_activity_ts = NULL;
	const char *time_source_path = state->path;
	entity_state_t *state_for_period_calc = state;

	/* Determine which timestamp to check against */
	if (state->type == ENTITY_DIRECTORY && state->watch && state->watch->recursive) {
		/* For recursive directory watches, always check the root's tree time */
		entity_state_t *root = find_root_state(state);
		if (root) {
			last_activity_ts = &root->last_activity_in_tree;
			time_source_path = root->path;
			state_for_period_calc = root;
		} else {
			log_message(LOG_LEVEL_WARNING, "Cannot find root state for %s, falling back to local activity", state->path);
			/* Fallback: use local activity if root not found */
			if (state->activity_sample_count == 0) return true;
			int latest_idx = (state->activity_index + MAX_ACTIVITY_SAMPLES - 1) % MAX_ACTIVITY_SAMPLES;
			last_activity_ts = &state->recent_activity[latest_idx].timestamp;
		}
	} else {
		/* For files or non-recursive dirs, use local activity time */
		if (state->activity_sample_count == 0) return true;
		int latest_idx = (state->activity_index + MAX_ACTIVITY_SAMPLES - 1) % MAX_ACTIVITY_SAMPLES;
		last_activity_ts = &state->recent_activity[latest_idx].timestamp;
	}

	/* Check for valid timestamp */
	if (!last_activity_ts || (last_activity_ts->tv_sec == 0 && last_activity_ts->tv_nsec == 0)) {
		log_message(LOG_LEVEL_DEBUG, "No valid activity timestamp for %s, quiet period assumed elapsed", state->path);
		return true;
	}

	/* Handle potential time going backwards */
	if (now->tv_sec < last_activity_ts->tv_sec ||
		(now->tv_sec == last_activity_ts->tv_sec && now->tv_nsec < last_activity_ts->tv_nsec)) {
		log_message(LOG_LEVEL_WARNING, "Clock appears to have moved backwards for %s, assuming quiet period elapsed", state->path);
		return true;
	}

	/* Calculate elapsed time */
	long elapsed_ms = (now->tv_sec - last_activity_ts->tv_sec) * 1000 +
					 (long)(now->tv_nsec - last_activity_ts->tv_nsec) / 1000000;

	/* Get the required period */
	long required_quiet_period_ms = get_required_quiet_period(state_for_period_calc);

	bool elapsed = elapsed_ms >= required_quiet_period_ms;

	if (!elapsed) {
		log_message(LOG_LEVEL_DEBUG, "Quiet period check for %s: %ld ms elapsed < %ld ms required (using time from %s)",
				  state->path, elapsed_ms, required_quiet_period_ms, time_source_path);
	} else {
		log_message(LOG_LEVEL_DEBUG, "Quiet period elapsed for %s: %ld ms >= %ld ms required",
				  state->path, elapsed_ms, required_quiet_period_ms);
	}
	
	return elapsed;
}

/* Get or create an entity state for a given path and watch */
entity_state_t *get_entity_state(const char *path, entity_type_t type, watch_entry_t *watch) {
	if (!path || !watch || !entity_states) {
		log_message(LOG_LEVEL_ERR, "Invalid arguments (path=%s, watch=%p, states_initialized=%d)",
				  path ? path : "NULL", watch, entity_states != NULL);
		return NULL;
	}
	
	/* Additional safety check for watch structure */
	if (!watch->name) {
		log_message(LOG_LEVEL_ERR, "Watch has NULL name (path=%s, watch=%p)", path, watch);
		return NULL;
	}

	unsigned int hash = hash_path_watch(path, watch);
	
	if (hash >= ENTITY_HASH_SIZE) {
		log_message(LOG_LEVEL_ERR, "Hash out of bounds: %u >= %d", hash, ENTITY_HASH_SIZE);
		return NULL;
	}
	
	entity_state_t *state = entity_states[hash];

	/* Look for existing state matching both path AND watch */
	int state_count = 0;
	while (state) {
		if (!state->path) {
			log_message(LOG_LEVEL_ERR, "Corrupted entity state: NULL path at index %d", state_count);
			break;
		}
		
		/* Check if state->watch is valid before dereferencing */
		if (!state->watch) {
			state = state->next;
			state_count++;
			continue;
		}
		
		/* Handle stale watch pointers by detecting pointer mismatches */
		const char *state_watch_name = NULL;
		bool state_watch_valid = false;
		
		if (state->watch) {
			/* Try to detect if this is a stale pointer by comparing with current watch */
			if (state->watch == watch) {
				state_watch_name = state->watch->name;
				state_watch_valid = true;
			} else {
				/* For path match, we'll update the watch pointer and continue */
				if (strcmp(state->path, path) == 0) {
					state->watch = watch;
					state_watch_name = watch->name;
					state_watch_valid = true;
				}
			}
		}
		
		if (strcmp(state->path, path) == 0) {
			/* Check if we have valid watch name and it matches */
			if (state_watch_valid && state_watch_name && watch->name && 
				strcmp(state_watch_name, watch->name) == 0) {
				if (state->type == ENTITY_UNKNOWN && type != ENTITY_UNKNOWN) {
					state->type = type; /* Update type if it becomes known */
				}
				return state;
			}
		}
		
		state = state->next;
		state_count++;
		
		if (state_count > 100) {
			log_message(LOG_LEVEL_ERR, "Potential infinite loop detected in hash table traversal!");
			break;
		}
	}

	/* Create new state */
	state = calloc(1, sizeof(entity_state_t));
	if (!state) {
		log_message(LOG_LEVEL_ERR, "Failed to allocate memory for entity state: %s", path);
		return NULL;
	}

	/* Initialize magic number for corruption detection */
	state->magic = ENTITY_STATE_MAGIC;
	
	state->path = strdup(path);
	if (!state->path) {
		log_message(LOG_LEVEL_ERR, "Failed to duplicate path string for entity state: %s", path);
		free(state);
		return NULL;
	}

	state->type = type;
	state->watch = watch;

	struct stat st;
	state->exists = (stat(path, &st) == 0);
	
	/* Determine entity type from stat if needed */
	if (type == ENTITY_UNKNOWN && state->exists) {
		if (S_ISDIR(st.st_mode)) state->type = ENTITY_DIRECTORY;
		else if (S_ISREG(st.st_mode)) state->type = ENTITY_FILE;
	} else if (type != ENTITY_UNKNOWN) {
		state->type = type;
	}

	clock_gettime(CLOCK_MONOTONIC, &state->last_update);
	clock_gettime(CLOCK_REALTIME, &state->wall_time);
	state->last_activity_in_tree = state->last_update;

	init_activity_tracking(state, watch);
	state->last_command_time = 0;
	state->failed_checks = 0;
	
	/* Initialize the new reference stats and change tracking fields */
	state->reference_stats_initialized = false;
	state->cumulative_file_change = 0;
	state->cumulative_dir_change = 0;
	state->cumulative_depth_change = 0;
	state->stability_lost = false;
	state->checking_scheduled = false;
	
	/* If this is a directory, gather initial statistics */
	if (state->type == ENTITY_DIRECTORY && state->exists) {
		if (gather_basic_directory_stats(state->path, &state->dir_stats, 0)) {
			/* Copy initial stats to prev_stats for future comparison */
			state->prev_stats = state->dir_stats;
			
			/* Initialize stable reference stats with current stats */
			state->stable_reference_stats = state->dir_stats;
			state->reference_stats_initialized = true;
			
			log_message(LOG_LEVEL_DEBUG, 
					  "Initialized directory stats for %s: files=%d, dirs=%d, depth=%d, size=%.2f MB",
					  state->path, state->dir_stats.file_count, state->dir_stats.dir_count, 
					  state->dir_stats.depth, state->dir_stats.total_size / (1024.0 * 1024.0));
		} else {
			log_message(LOG_LEVEL_WARNING, 
					  "Failed to gather initial stats for directory: %s", state->path);
		}
	}

	/* Add to hash table */
	state->next = entity_states[hash];
	entity_states[hash] = state;

	log_message(LOG_LEVEL_DEBUG, "Created new state for path=%s, watch=%s, type=%d",
			  path, watch->name, state->type);

	return state;
}

/* Determine the logical operation type based on entity state and event */
operation_type_t determine_operation(entity_state_t *state, event_type_t new_event_type) {
	if (!state) return OP_NONE;

	/* Update state change flags based on the new event type */
	if (new_event_type & EVENT_CONTENT) state->content_changed = true;
	if (new_event_type & EVENT_METADATA) state->metadata_changed = true;
	if (new_event_type & EVENT_MODIFY) state->structure_changed = true;

	/* Check current existence vs tracked existence */
	struct stat st;
	bool exists_now = (stat(state->path, &st) == 0);

	operation_type_t determined_op = OP_NONE;

	if (state->exists && !exists_now) {
		/* Deletion */
		determined_op = (state->type == ENTITY_FILE) ? OP_FILE_DELETED : OP_DIR_DELETED;
		log_message(LOG_LEVEL_DEBUG, "Entity %s detected as DELETED", state->path);
		state->exists = false;
	} else if (!state->exists && exists_now) {
		/* Creation */
		determined_op = (state->type == ENTITY_FILE) ? OP_FILE_CREATED : OP_DIR_CREATED;
		log_message(LOG_LEVEL_DEBUG, "Entity %s detected as CREATED", state->path);
		state->exists = true;
		
		/* Update type if it was unknown */
		if (state->type == ENTITY_UNKNOWN) {
			if (S_ISDIR(st.st_mode)) state->type = ENTITY_DIRECTORY;
			else if (S_ISREG(st.st_mode)) state->type = ENTITY_FILE;
		}
		
		/* For directory creation, gather initial stats */
		if (state->type == ENTITY_DIRECTORY) {
			gather_basic_directory_stats(state->path, &state->dir_stats, 0);
			state->prev_stats = state->dir_stats;
		}
	} else if (exists_now) {
		/* Existed before and exists now - check for other changes */
		state->exists = true;
		
		/* Prioritize which operation to report if multiple flags are set */
		if (state->type == ENTITY_DIRECTORY && (state->structure_changed || state->content_changed)) {
			determined_op = OP_DIR_CONTENT_CHANGED;
			log_message(LOG_LEVEL_DEBUG, "Directory %s content/structure changed", state->path);
		} else if (state->type == ENTITY_FILE && state->structure_changed) {
			determined_op = OP_FILE_RENAMED;
			log_message(LOG_LEVEL_DEBUG, "File %s structure changed (possible rename)", state->path);
		} else if (state->type == ENTITY_FILE && state->content_changed) {
			determined_op = OP_FILE_CONTENT_CHANGED;
			log_message(LOG_LEVEL_DEBUG, "File %s content changed", state->path);
		} else if (state->metadata_changed) {
			determined_op = (state->type == ENTITY_FILE) ? OP_FILE_METADATA_CHANGED : OP_DIR_METADATA_CHANGED;
			log_message(LOG_LEVEL_DEBUG, "Entity %s metadata changed", state->path);
		} else {
			log_message(LOG_LEVEL_DEBUG, "Entity %s exists but no relevant changes detected", state->path);
			determined_op = OP_NONE;
		}
	} else {
		log_message(LOG_LEVEL_DEBUG, "Entity %s still does not exist", state->path);
		determined_op = OP_NONE;
	}

	return determined_op;
}

/* Convert operation type to event type for mask checking */
event_type_t operation_to_event_type(operation_type_t op) {
	switch (op) {
		case OP_FILE_CONTENT_CHANGED:
		case OP_DIR_CONTENT_CHANGED:    return EVENT_CONTENT;
		case OP_FILE_CREATED:
		case OP_FILE_DELETED:
		case OP_FILE_RENAMED:
		case OP_DIR_CREATED:
		case OP_DIR_DELETED:            return EVENT_MODIFY;
		case OP_FILE_METADATA_CHANGED:
		case OP_DIR_METADATA_CHANGED:   return EVENT_METADATA;
		default:                        return EVENT_NONE;
	}
}

/* Check if a command should be executed for a given operation */
bool should_execute_command(entity_state_t *state, operation_type_t op, int default_debounce_ms) {
	if (!state) return false;

	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	/* Record activity (updates timestamps and root tree time) */
	record_activity(state, op);

	/* Directory content changes always defer execution to process_deferred_dir_scans */
	if (op == OP_DIR_CONTENT_CHANGED) {
		entity_state_t *root = find_root_state(state);
		if (root && g_current_monitor) {
			/* Always trigger a deferred check; queue deduplicates */
			root->activity_in_progress = true;
			log_message(LOG_LEVEL_DEBUG, "Directory content change for %s, marked root %s as active - command deferred",
					   state->path, root->path);
			synchronize_activity_states(root->path, root);
			schedule_deferred_check(g_current_monitor, root);
			log_message(LOG_LEVEL_DEBUG, "Added directory %s to deferred check queue", root->path);
		}
		return false; /* Decision happens later in process_deferred_dir_scans */
	}

	/* Standard time-based debounce for non-directory-content operations */
	long elapsed_ms_since_command = (now.tv_sec - state->last_command_time) * 1000;
	
	/* Adjust debounce based on operation type */
	int debounce_ms = default_debounce_ms;
	switch (op) {
		case OP_FILE_DELETED: case OP_DIR_DELETED:
		case OP_FILE_CREATED: case OP_DIR_CREATED:
			debounce_ms = default_debounce_ms > 0 ? default_debounce_ms / 4 : 0; /* Shorter debounce */
			break;
		case OP_FILE_CONTENT_CHANGED:
			debounce_ms = default_debounce_ms > 0 ? default_debounce_ms / 2 : 0; /* Medium debounce */
			break;
		default: /* METADATA, RENAME etc. use default */
			break;
	}
	if (debounce_ms < 0) debounce_ms = 0;

	log_message(LOG_LEVEL_DEBUG, "Debounce check for %s: %ld ms elapsed, %d ms required",
			  state->path, elapsed_ms_since_command, debounce_ms);

	/* Check if enough time has passed or if it's the first command */
	if (elapsed_ms_since_command >= debounce_ms || state->last_command_time == 0) {
		log_message(LOG_LEVEL_DEBUG, "Debounce check passed for %s, command allowed", state->path);
		return true;
	}

	log_message(LOG_LEVEL_DEBUG, "Command execution debounced for %s", state->path);
	return false;
}

/* Process an event and potentially execute a command */
bool process_event(watch_entry_t *watch, file_event_t *event, entity_type_t entity_type) {
	if (watch == NULL || event == NULL || event->path == NULL) {
		log_message(LOG_LEVEL_ERR, "process_event: Received NULL watch, event, or event path");
		return false;
	}
	
	/* Additional safety checks for watch structure */
	if (!watch->name || !watch->command) {
		log_message(LOG_LEVEL_ERR, "process_event: Watch has NULL name or command");
		return false;
	}
	
	log_message(LOG_LEVEL_DEBUG, "Processing event for %s (watch: %s, type: %s)",
			  event->path, watch->name, event_type_to_string(event->type));
	
	/* Handle config file events specially for hot reload */
	if (watch->name != NULL && strcmp(watch->name, "__config_file__") == 0) {
		log_message(LOG_LEVEL_NOTICE, "Configuraion changed: %s", event->path);
		if (g_current_monitor != NULL) {
			monitor_request_reload(g_current_monitor);
		} else {
			log_message(LOG_LEVEL_WARNING, "Config file changed but no monitor available for reload");
		}
		return true;
	}
	
	/* Check if this event was caused by one of our commands */
	if (is_path_affected_by_command(event->path)) {
		log_message(LOG_LEVEL_DEBUG, "Ignoring event for %s - caused by our command execution",
				  event->path);
		return false;
	}
	
	/* Get state using the event path and watch config */
	entity_state_t *state = get_entity_state(event->path, entity_type, watch);
	if (state == NULL) {
		return false; /* Error already logged by get_entity_state */
	}

	/* Update timestamps before determining operation */
	state->last_update = event->time;
	state->wall_time = event->wall_time;

	/* Determine the logical operation */
	operation_type_t op = determine_operation(state, event->type);
	if (op == OP_NONE) {
		return false; /* No relevant change detected */
	}

	log_message(LOG_LEVEL_DEBUG, "Determined operation type %d for %s", op, state->path);

	/* Check if operation is included in watch mask */
	event_type_t event_type_for_mask = operation_to_event_type(op);
	if ((watch->events & event_type_for_mask) == 0) {
		log_message(LOG_LEVEL_DEBUG, "Operation maps to event type %s, which is not in watch mask for %s",
				  event_type_to_string(event_type_for_mask), watch->name);
		return false;
	}

	/* Check debounce/deferral logic */
	if (should_execute_command(state, op, command_get_debounce_time())) {
		/* Execute command immediately (only for non-directory-content changes) */
		file_event_t synthetic_event = {
			.path = state->path,
			.type = event_type_for_mask,
			.time = state->last_update,
			.wall_time = state->wall_time,
			.user_id = event->user_id
		};
		
		log_message(LOG_LEVEL_INFO, "Executing command for %s (watch: %s, operation: %d)",
				  state->path, watch->name, op);
		
		if (command_execute(watch, &synthetic_event)) {
			log_message(LOG_LEVEL_INFO, "Command execution successful for %s", state->path);
			
			/* Update last command time and reset change flags */
			state->last_command_time = state->last_update.tv_sec;
			state->content_changed = false;
			state->metadata_changed = false;
			state->structure_changed = false;
			
			return true;
		} else {
			log_message(LOG_LEVEL_WARNING, "Command execution failed for %s", state->path);
			return false;
		}
	} else {
		log_message(LOG_LEVEL_DEBUG, "Command for %s (op %d) deferred or debounced", state->path, op);
		return false;
	}
}

/* Update entity states with new watch pointers after config reload */
void update_entity_states_after_reload(watch_entry_t *old_watch, watch_entry_t *new_watch) {
	if (!old_watch || !new_watch || !old_watch->name || !new_watch->name || !entity_states) {
		return;
	}
	
	log_message(LOG_LEVEL_DEBUG, "Updating entity states for watch: %s", old_watch->name);
	
	/* Iterate through all entity states and update pointers by name comparison */
	for (int i = 0; i < ENTITY_HASH_SIZE; i++) {
		entity_state_t *state = entity_states[i];
		while (state) {
			entity_state_t *next = state->next; /* Save next pointer early */
			
			/* Skip corrupted or invalid states */
			if (is_entity_state_corrupted(state) || !state->path || !state->watch) {
				log_message(LOG_LEVEL_DEBUG, "Skipping corrupted state during watch update");
				state = next;
				continue;
			}
			
			/* Update both exact pointer matches and name matches */
			if ((state->watch == old_watch) || 
			    (state->watch->name && strcmp(state->watch->name, old_watch->name) == 0)) {
				log_message(LOG_LEVEL_DEBUG, "Updated watch pointer for state: %s", state->path);
				state->watch = new_watch;
			}
			state = next;
		}
	}
}

/* Clean up entity states that reference deleted watches after config reload */
void cleanup_orphaned_entity_states(config_t *old_config) {
	if (!old_config || !entity_states) {
		return;
	}
	
	log_message(LOG_LEVEL_DEBUG, "Cleaning up orphaned entity states after config reload");
	
	/* Remove all entity states - they will be recreated as needed with new watch pointers */
	for (int i = 0; i < ENTITY_HASH_SIZE; i++) {
		entity_state_t *state = entity_states[i];
		
		while (state) {
			entity_state_t *next = state->next;
			
			log_message(LOG_LEVEL_DEBUG, "Removing entity state for path %s during cleanup", 
					   state->path ? state->path : "<unknown>");
			
			/* Free the state */
			if (state->path) {
				free(state->path);
			}
			free(state);
			
			state = next;
		}
		
		/* Clear the hash table entry */
		entity_states[i] = NULL;
	}
}
