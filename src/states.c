#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <limits.h>
#include <sys/stat.h>
#include <libgen.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <dirent.h>

#include "states.h"
#include "command.h"
#include "log.h"

/* Hash table size for storing entity states */
#define ENTITY_HASH_SIZE 64

/* Hash table of entity states */
static entity_state_t **entity_states = NULL;

/* Initialize the entity state system */
void entity_state_init(void) {
	entity_states = calloc(ENTITY_HASH_SIZE, sizeof(entity_state_t *));
	if (entity_states == NULL) {
		log_message(LOG_LEVEL_ERR, "Failed to allocate memory for entity states");
	} else {
		log_message(LOG_LEVEL_DEBUG, "Entity state system initialized");
	}
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
	unsigned int hash = 0;
	if (!path || !watch) return 0;
	
	/* Simple hash combining path and watch pointer address */
	for (const char *p = path; *p; p++) hash = hash * 31 + *p;
	hash = hash * 31 + (uintptr_t)watch; /* Ensure uniqueness per watch config */
	return hash % ENTITY_HASH_SIZE;
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

/* Calculate the depth of a path (number of directory levels) */
int calculate_path_depth(const char *path) {
	int depth = 0;
	const char *p = path;
	
	/* Start with depth 1 for absolute paths, 0 for relative */
	if (*p == '/') {
		depth = 0;
		p++;
	}
	
	while (*p) {
		if (*p == '/') {
			depth++;
		}
		p++;
	}
	
	/* Add 1 for the final component if it's not just a trailing slash */
	if (*(p-1) != '/') {
		depth++;
	}
	
	return depth;
}

/* Compare two directory statistics to check for stability */
bool compare_dir_stats(dir_stats_t *prev, dir_stats_t *current) {
	if (!prev || !current) return false;
	
	/* Check for identical file and directory counts */
	if (prev->file_count != current->file_count || 
		prev->dir_count != current->dir_count) {
		log_message(LOG_LEVEL_DEBUG, "Directory unstable: file/dir count changed from %d/%d to %d/%d",
				   prev->file_count, prev->dir_count, current->file_count, current->dir_count);
		return false;
	}
	
	/* Check if total size is stable (allowing for small changes) */
	/* Use a percentage-based threshold for large directories */
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

/* Collect statistics about a directory and its contents */
bool verify_directory_stability(const char *dir_path, dir_stats_t *stats) {
	DIR *dir;
	struct dirent *entry;
	struct stat st;
	char path[PATH_MAX];
	
	if (!dir_path || !stats) {
		return false;
	}
	
	/* Initialize stats */
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
			
			/* Check for very recent file modifications (< 3 seconds) */
			if (difftime(now, st.st_mtime) < 3.0) {
				log_message(LOG_LEVEL_DEBUG, "Directory %s unstable: recent file modification (%s, %.1f seconds ago)", 
						  dir_path, entry->d_name, difftime(now, st.st_mtime));
				stats->has_temp_files = true;
			}
			
			/* Check for temporary files */
			if (st.st_size == 0 || 
				strstr(entry->d_name, ".tmp") != NULL || 
				strstr(entry->d_name, ".part") != NULL || 
				strstr(entry->d_name, ".~") != NULL) {
				log_message(LOG_LEVEL_DEBUG, "Directory %s unstable: temp file detected (%s)", dir_path, entry->d_name);
				stats->has_temp_files = true;
			}
		} else if (S_ISDIR(st.st_mode)) {
			stats->dir_count++;
			
			/* Don't recursively scan if this directory is too deep or we already know it's unstable */
			if (stats->has_temp_files) {
				continue;
			}
			
			/* Recursively check subdirectory, but limit recursion depth for performance */
			static int recursion_depth = 0;
			recursion_depth++;
			
			/* Skip deep recursion but don't mark as unstable */
			if (recursion_depth > 10) {
				recursion_depth--;
				continue;
			}
			
			dir_stats_t subdir_stats;
			if (!verify_directory_stability(path, &subdir_stats)) {
				recursion_depth--;
				closedir(dir);
				return false;
			}
			recursion_depth--;
			
			/* Incorporate subdirectory stats */
			stats->file_count += subdir_stats.file_count;
			stats->dir_count += subdir_stats.dir_count;
			stats->total_size += subdir_stats.total_size;
			stats->has_temp_files |= subdir_stats.has_temp_files;
			
			if (subdir_stats.latest_mtime > stats->latest_mtime) {
				stats->latest_mtime = subdir_stats.latest_mtime;
			}
		}
	}
	
	closedir(dir);
	return true;
}

/* Find the state corresponding to the root path of a watch */
entity_state_t *find_root_state(entity_state_t *state) {
	if (!state || !state->watch || !state->watch->path) {
		if (state && state->path) {
			log_message(LOG_LEVEL_WARNING, "find_root_state: Invalid watch info for state %s", state->path);
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
	
	/* Loop through all hash buckets */
	for (int i = 0; i < ENTITY_HASH_SIZE; i++) {
		entity_state_t *state = entity_states[i];
		while (state) {
			/* If this state is for the same path but different watch */
			if (strcmp(state->path, path) == 0 && state != trigger_state) {
				log_message(LOG_LEVEL_DEBUG, "Synchronizing state for path %s (watch: %s) with trigger (watch: %s)",
						   path, state->watch->name, trigger_state->watch->name);
				
				/* Synchronize key activity tracking fields */
				state->last_update = trigger_state->last_update;
				state->last_activity_in_tree = trigger_state->last_activity_in_tree;
				state->activity_in_progress = trigger_state->activity_in_progress;
				
				/* Copy the most recent activity sample to keep timing consistent */
				if (trigger_state->activity_sample_count > 0) {
					int latest_idx = (trigger_state->activity_index + MAX_ACTIVITY_SAMPLES - 1) % MAX_ACTIVITY_SAMPLES;
					int target_idx = (state->activity_index + MAX_ACTIVITY_SAMPLES - 1) % MAX_ACTIVITY_SAMPLES;
					
					state->recent_activity[target_idx] = trigger_state->recent_activity[latest_idx];
					if (state->activity_sample_count == 0) {
						state->activity_sample_count = 1;
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

	if (state->type == ENTITY_DIRECTORY) {
		required_ms = DIR_QUIET_PERIOD_MS;
		
		/* Basic multiplier for active directories */
		if (state->activity_in_progress) {
			double multiplier = 3.0;
			
			/* Adjust multiplier based on directory complexity */
			if (state->dir_stats.file_count > 0) {
				/* Scale based on directory size (logarithmic) */
				int total_entries = state->dir_stats.file_count + state->dir_stats.dir_count;
				if (total_entries > 100) {
					multiplier *= (1.0 + log10(total_entries / 100.0));
				}
				
				/* Scale based on directory depth */
				if (state->depth > 3) {
					multiplier *= (1.0 + ((state->depth - 3) * 0.2));
				}
				
				/* Cap the multiplier at a reasonable maximum */
				if (multiplier > 20.0) multiplier = 20.0;
			}
			
			required_ms = (long)(required_ms * multiplier);
			log_message(LOG_LEVEL_DEBUG, "Using adaptive quiet period for %s: %.1fx = %ld ms",
					  state->path, multiplier, required_ms);
		}
	}

	/* Set reasonable limits */
	if (required_ms < 10) required_ms = 10;
	if (required_ms > 30000) required_ms = 30000;  /* Cap at 30 seconds */
	
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
		log_message(LOG_LEVEL_ERR, "Invalid arguments (path=%s, watch=%s, states_initialized=%d)",
				  path ? path : "NULL", watch ? watch->name : "NULL", entity_states != NULL);
		return NULL;
	}

	unsigned int hash = hash_path_watch(path, watch);
	entity_state_t *state = entity_states[hash];

	/* Look for existing state matching both path AND watch */
	while (state) {
		if (strcmp(state->path, path) == 0 && state->watch == watch) {
			if (state->type == ENTITY_UNKNOWN && type != ENTITY_UNKNOWN) {
				state->type = type; /* Update type if it becomes known */
			}
			return state;
		}
		state = state->next;
	}

	/* Create new state */
	state = calloc(1, sizeof(entity_state_t));
	if (!state) {
		log_message(LOG_LEVEL_ERR, "Failed to allocate memory for entity state: %s", path);
		return NULL;
	}

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
		if (root) {
			/* Set activity_in_progress on the ROOT state to trigger deferred check */
			root->activity_in_progress = true;
			log_message(LOG_LEVEL_DEBUG, "Directory content change for %s, marked root %s as active - command deferred",
					  state->path, root->path);
			
			/* Synchronize with other watches for the same path */
			synchronize_activity_states(root->path, root);
		} else {
			log_message(LOG_LEVEL_WARNING, "Directory content change for %s, but could not find root state for deferral",
					  state->path);
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
	
	log_message(LOG_LEVEL_DEBUG, "Processing event for %s (watch: %s, type: %s)",
			  event->path, watch->name, event_type_to_string(event->type));

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

/* Set the global quiet period (placeholder implementation) */
void set_quiet_period(int milliseconds) {
	log_message(LOG_LEVEL_WARNING, "Dynamic quiet period setting not implemented (using defines): %d ms", milliseconds);
}

/* Get the current quiet period value */
int get_quiet_period(void) {
	return QUIET_PERIOD_MS;
}
