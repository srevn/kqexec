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

#include "states.h"
#include "scanner.h"
#include "command.h"
#include "logger.h"
#include "monitor.h"

/* Hash table of path states */
static path_state_t **path_states = NULL;

/* Mutex for protecting access to the path_states hash table */
pthread_mutex_t entity_states_mutex;

/* Check if entity state is corrupted by verifying magic number */
bool is_entity_state_corrupted(const entity_state_t *state) {
	if (!state) return true;
	
	if ((uintptr_t)state < 0x1000 || ((uintptr_t)state & 0x7) != 0) {
		log_message(WARNING, "Entity state appears to be invalid pointer: %p", state);
		return true;
	}
	
	if (state->magic != ENTITY_STATE_MAGIC) {
		log_message(WARNING, "Entity state corruption detected: magic=0x%x, expected=0x%x",
					state->magic, ENTITY_STATE_MAGIC);
		return true;
	}
	return false;
}

/* Hash function for a path string */
static unsigned int hash_path(const char *path) {
	unsigned int hash = 5381; /* djb2 hash initial value */
	if (!path) return 0;
	
	for (const char *p = path; *p; p++) {
		hash = ((hash << 5) + hash) + (unsigned char)*p;
	}
	
	return hash % PATH_HASH_SIZE;
}

/* Initialize the entity state system */
bool entity_state_init(void) {
	path_states = calloc(PATH_HASH_SIZE, sizeof(path_state_t *));
	if (path_states == NULL) {
		log_message(ERROR, "Failed to allocate memory for path states");
		return false;
	}

	/* Initialize the recursive mutex */
	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	if (pthread_mutex_init(&entity_states_mutex, &attr) != 0) {
		log_message(ERROR, "Failed to initialize entity states mutex");
		free(path_states);
		path_states = NULL;
		return false;
	}
	pthread_mutexattr_destroy(&attr);

	log_message(DEBUG, "Entity state system initialized");
	return true;
}

/* Free resources used by an entity state */
static void free_entity_state(entity_state_t *state) {
	if (state) {
		free(state->last_activity_path);
		free(state->trigger_file_path);
		free(state);
	}
}

/* Free resources used by a path state and all its entity states */
static void free_path_state(path_state_t *ps) {
	if (ps) {
		entity_state_t *state = ps->head_entity_state;
		while (state) {
			entity_state_t *next = state->next_for_path;
			free_entity_state(state);
			state = next;
		}
		free(ps->path);
		free(ps);
	}
}

/* Clean up the entity state system */
void entity_state_cleanup(void) {
	if (path_states == NULL) return;

	/* Lock mutex during cleanup */
	pthread_mutex_lock(&entity_states_mutex);

	/* Free all path states */
	for (int i = 0; i < PATH_HASH_SIZE; i++) {
		path_state_t *ps = path_states[i];
		while (ps) {
			path_state_t *next = ps->next_in_bucket;
			free_path_state(ps);
			ps = next;
		}
		path_states[i] = NULL;
	}
	free(path_states);
	path_states = NULL;

	/* Unlock mutex after search */
	pthread_mutex_unlock(&entity_states_mutex);
	pthread_mutex_destroy(&entity_states_mutex);

	log_message(DEBUG, "Entity state system cleanup complete");
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

/* Find the state corresponding to the root path of a watch */
entity_state_t *find_root_state(entity_state_t *state) {
	if (!state || !state->watch || !state->watch->path || !state->path_state) {
		if (state && state->path_state) {
			log_message(WARNING, "Invalid watch info for state %s", state->path_state->path);
		}
		return NULL;
	}

	/* If current state is already the root, return it */
	if (strcmp(state->path_state->path, state->watch->path) == 0) {
		return state;
	}

	/* Otherwise, get the state for the watch path */
	return get_entity_state(state->watch->path, ENTITY_DIRECTORY, state->watch);
}

/* Copies all directory-related statistics and tracking fields from a source to a destination state. */
static void _copy_directory_tracking_state(entity_state_t *dest, const entity_state_t *src) {
	if (!dest || !src) return;

	dest->dir_stats = src->dir_stats;
	dest->prev_stats = src->prev_stats;
	dest->stable_reference_stats = src->stable_reference_stats;
	dest->reference_stats_initialized = src->reference_stats_initialized;
	dest->cumulative_file_change = src->cumulative_file_change;
	dest->cumulative_dir_change = src->cumulative_dir_change;
	dest->cumulative_depth_change = src->cumulative_depth_change;
	dest->stability_lost = src->stability_lost;
	dest->instability_count = src->instability_count;
}

/* Get or create an entity state for a given path and watch */
entity_state_t *get_entity_state(const char *path, entity_type_t type, watch_entry_t *watch) {
	if (!path || !watch || !path_states) {
		log_message(ERROR, "Invalid arguments to get_entity_state");
		return NULL;
	}

	/* Additional safety check for watch structure */
	if (!watch->name) {
		log_message(ERROR, "Watch has NULL name for path %s", path);
		return NULL;
	}

	unsigned int hash = hash_path(path);
	
	pthread_mutex_lock(&entity_states_mutex);
	
	path_state_t *ps = path_states[hash];

	/* Find existing path_state */
	while (ps) {
		if (strcmp(ps->path, path) == 0) {
			break;
		}
		ps = ps->next_in_bucket;
	}

	/* If path_state not found, create it */
	if (!ps) {
		ps = calloc(1, sizeof(path_state_t));
		if (!ps) {
			log_message(ERROR, "Failed to allocate memory for path_state: %s", path);
			pthread_mutex_unlock(&entity_states_mutex);
			return NULL;
		}
		ps->path = strdup(path);
		if (!ps->path) {
			log_message(ERROR, "Failed to duplicate path for path_state: %s", path);
			free(ps);
			pthread_mutex_unlock(&entity_states_mutex);
			return NULL;
		}
		ps->next_in_bucket = path_states[hash];
		path_states[hash] = ps;
	}

	/* Find existing entity_state for this watch */
	entity_state_t *state = ps->head_entity_state;
	while (state) {
		if (strcmp(state->watch->name, watch->name) == 0) {
			if (state->type == ENTITY_UNKNOWN && type != ENTITY_UNKNOWN) {
				state->type = type;
			}
			pthread_mutex_unlock(&entity_states_mutex);
			return state;
		}
		state = state->next_for_path;
	}

	/* Check if we have an existing state for this path to copy stats from */
	entity_state_t *existing_state_for_path = ps->head_entity_state;

	/* Create new entity_state */
	state = calloc(1, sizeof(entity_state_t));
	if (!state) {
		log_message(ERROR, "Failed to allocate memory for entity_state: %s", path);
		/* If the path_state was newly created for this entity, free it to prevent a leak */
		if (!ps->head_entity_state) {
			path_states[hash] = ps->next_in_bucket;
			free_path_state(ps);
		}
		pthread_mutex_unlock(&entity_states_mutex);
		return NULL;
	}

	/* Initialize magic number for corruption detection */
	state->magic = ENTITY_STATE_MAGIC;
	
	state->path_state = ps;
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
	state->last_activity_path = strdup(path);
	state->trigger_file_path = NULL;

	init_activity_tracking(state, watch);
	state->last_command_time = 0;
	state->failed_checks = 0;

	/* If an existing state for this path was found, copy its stats */
	if (existing_state_for_path) {
		log_message(DEBUG, "Copying stats from existing state for path %s (watch: %s)",
		            path, existing_state_for_path->watch->name);
		_copy_directory_tracking_state(state, existing_state_for_path);
	} else {
		/* This is the first state for this path, initialize stats from scratch */
		state->instability_count = 0;
		state->reference_stats_initialized = false;
		state->cumulative_file_change = 0;
		state->cumulative_dir_change = 0;
		state->cumulative_depth_change = 0;
		state->stability_lost = false;
		state->checking_scheduled = false;

		if (state->type == ENTITY_DIRECTORY && state->exists) {
			if (scanner_gather_directory_stats(path, &state->dir_stats, 0)) {
				state->prev_stats = state->dir_stats;
				state->stable_reference_stats = state->dir_stats;
				state->reference_stats_initialized = true;
				log_message(DEBUG,
				            "Initialized directory stats for %s: files=%d, dirs=%d, depth=%d, size=%.2f MB",
				            path, state->dir_stats.file_count, state->dir_stats.dir_count,
				            state->dir_stats.depth, state->dir_stats.total_size / (1024.0 * 1024.0));
			} else {
				log_message(WARNING,
				            "Failed to gather initial stats for directory: %s", path);
			}
		}
	}

	/* Add to the path_state's list */
	state->next_for_path = ps->head_entity_state;
	ps->head_entity_state = state;

	log_message(DEBUG, "Created new state for path=%s, watch=%s", path, watch->name);
	
	pthread_mutex_unlock(&entity_states_mutex);
	return state;
}

/* Determine the logical operation type based on entity state and event */
operation_type_t determine_operation(entity_state_t *state, event_type_t new_event_type) {
	if (!state) return OP_NONE;

	/* Update state change flags based on the new event type */
	if (new_event_type & EVENT_STRUCTURE) state->structure_changed = true;
	if (new_event_type & EVENT_METADATA) state->metadata_changed = true;
	if (new_event_type & EVENT_CONTENT) state->content_changed = true;

	/* Check current existence vs tracked existence */
	struct stat st;
	bool exists_now = (stat(state->path_state->path, &st) == 0);

	operation_type_t determined_op = OP_NONE;

	if (state->exists && !exists_now) {
		/* Deletion */
		determined_op = (state->type == ENTITY_FILE) ? OP_FILE_DELETED : OP_DIR_DELETED;
		log_message(DEBUG, "Entity %s detected as DELETED", state->path_state->path);
		state->exists = false;
	} else if (!state->exists && exists_now) {
		/* Creation */
		determined_op = (state->type == ENTITY_FILE) ? OP_FILE_CREATED : OP_DIR_CREATED;
		log_message(DEBUG, "Entity %s detected as CREATED", state->path_state->path);
		state->exists = true;

		/* Update type if it was unknown */
		if (state->type == ENTITY_UNKNOWN) {
			if (S_ISDIR(st.st_mode)) state->type = ENTITY_DIRECTORY;
			else if (S_ISREG(st.st_mode)) state->type = ENTITY_FILE;
		}

		/* For directory creation, gather initial stats */
		if (state->type == ENTITY_DIRECTORY) {
			scanner_gather_directory_stats(state->path_state->path, &state->dir_stats, 0);
			state->prev_stats = state->dir_stats;
		}
	} else if (exists_now) {
		/* Existed before and exists now - check for other changes */
		state->exists = true;

		/* Prioritize which operation to report if multiple flags are set */
		if (state->type == ENTITY_DIRECTORY && (state->content_changed || state->structure_changed)) {
			determined_op = OP_DIR_CONTENT_CHANGED;
			log_message(DEBUG, "Directory %s structure changed", state->path_state->path);
		} else if (state->type == ENTITY_FILE && state->content_changed) {
			determined_op = OP_FILE_RENAMED;
			log_message(DEBUG, "File %s content changed", state->path_state->path);
		} else if (state->type == ENTITY_FILE && state->structure_changed) {
			determined_op = OP_FILE_CONTENT_CHANGED;
			log_message(DEBUG, "File %s content changed", state->path_state->path);
		} else if (state->metadata_changed) {
			determined_op = (state->type == ENTITY_FILE) ? OP_FILE_METADATA_CHANGED : OP_DIR_METADATA_CHANGED;
			log_message(DEBUG, "Entity %s metadata changed", state->path_state->path);
		} else {
			log_message(DEBUG, "Entity %s exists but no relevant changes detected", state->path_state->path);
			determined_op = OP_NONE;
		}
	} else {
		log_message(DEBUG, "Entity %s still does not exist", state->path_state->path);
		determined_op = OP_NONE;
	}

	return determined_op;
}

/* Convert operation type to event type for mask checking */
event_type_t operation_to_event_type(operation_type_t op) {
	switch (op) {
		case OP_FILE_CONTENT_CHANGED:
		case OP_DIR_CONTENT_CHANGED:  return EVENT_STRUCTURE;
		case OP_FILE_CREATED:
		case OP_FILE_DELETED:
		case OP_FILE_RENAMED:
		case OP_DIR_CREATED:
		case OP_DIR_DELETED:          return EVENT_CONTENT;
		case OP_FILE_METADATA_CHANGED:
		case OP_DIR_METADATA_CHANGED: return EVENT_METADATA;
		default:                      return EVENT_NONE;
	}
}

/* Check if a command should be executed for a given operation */
bool should_execute_command(monitor_t *monitor, entity_state_t *state, operation_type_t op, int default_debounce_ms) {
	if (!state) return false;

	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	/* Record activity (updates timestamps and root tree time) */
	scanner_record_activity(state, op);

	/* Directory content changes always defer execution to process_deferred_dir_scans */
	if (op == OP_DIR_CONTENT_CHANGED) {
		entity_state_t *root = find_root_state(state);
		if (root && monitor) {
			/* Always trigger a deferred check; queue deduplicates */
			root->activity_in_progress = true;
			log_message(DEBUG, "Directory content change for %s, marked root %s as active - command deferred",
			            state->path_state->path, root->path_state->path);
			scanner_synchronize_activity_states(root->path_state, root);

			if (!root) {
				return false;
			}

			schedule_deferred_check(monitor, root);
			log_message(DEBUG, "Added directory %s to deferred check queue", root->path_state->path);
		}
		return false; /* Decision happens later in process_deferred_dir_scans */
	}

	/* Standard time-based debounce for non-directory-content operations */
	long elapsed_ms_since_command = (now.tv_sec - state->last_command_time) * 1000;

	/* Adjust debounce based on operation type */
	int debounce_ms = default_debounce_ms;
	switch (op) {
		case OP_FILE_DELETED:
		case OP_DIR_DELETED:
		case OP_FILE_CREATED:
		case OP_DIR_CREATED:
			debounce_ms = default_debounce_ms > 0 ? default_debounce_ms / 4 : 0; /* Shorter debounce */
			break;
		case OP_FILE_CONTENT_CHANGED:
			debounce_ms = default_debounce_ms > 0 ? default_debounce_ms / 2 : 0; /* Medium debounce */
			break;
		default: /* METADATA, RENAME etc. use default */
			break;
	}
	if (debounce_ms < 0) debounce_ms = 0;

	log_message(DEBUG, "Debounce check for %s: %ld ms elapsed, %d ms required",
	            state->path_state->path, elapsed_ms_since_command, debounce_ms);

	/* Check if enough time has passed or if it's the first command */
	if (elapsed_ms_since_command >= debounce_ms || state->last_command_time == 0) {
		log_message(DEBUG, "Debounce check passed for %s, command allowed", state->path_state->path);
		return true;
	}

	log_message(DEBUG, "Command execution debounced for %s", state->path_state->path);
	return false;
}

/* Process an event and potentially execute a command */
bool process_event(monitor_t *monitor, watch_entry_t *watch, file_event_t *event, entity_type_t entity_type) {
	if (watch == NULL || event == NULL || event->path == NULL) {
		log_message(ERROR, "process_event: Received NULL watch, event, or event path");
		return false;
	}

	/* Additional safety checks for watch structure */
	if (!watch->name || !watch->command) {
		log_message(ERROR, "process_event: Watch has NULL name or command");
		return false;
	}

	log_message(DEBUG, "Processing event for %s (watch: %s, type: %s)",
	            event->path, watch->name, event_type_to_string(event->type));

	/* Handle config file events specially for hot reload */
	if (watch->name != NULL && strcmp(watch->name, "__config_file__") == 0) {
		static struct timespec last_reload_time = {0, 0};
		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);

		/* Calculate time difference in milliseconds */
		long diff_ms = (now.tv_sec - last_reload_time.tv_sec) * 1000 +
		               (now.tv_nsec - last_reload_time.tv_nsec) / 1000000;

		if (diff_ms < 100) {
			log_message(DEBUG, "Skipping consecutive events generated by the configuration save operation");
			return true;
		}
		last_reload_time = now;

		log_message(NOTICE, "Configuraion changed: %s", event->path);
		if (monitor != NULL) {
			monitor_request_reload(monitor);
		} else {
			log_message(WARNING, "Config file changed but no monitor available for reload");
		}
		return true;
	}

	/* Check if this event was caused by one of our commands */
	if (is_path_affected_by_command(event->path)) {
		log_message(DEBUG, "Ignoring event for %s - caused by our command execution",
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

	log_message(DEBUG, "Determined operation type %d for %s", op, state->path_state->path);

	/* Check if operation is included in watch mask */
	event_type_t event_type_for_mask = operation_to_event_type(op);
	if ((watch->events & event_type_for_mask) == 0) {
		log_message(DEBUG, "Operation maps to event type %s, which is not in watch mask for %s",
		            event_type_to_string(event_type_for_mask), watch->name);
		return false;
	}

	/* Check debounce/deferral logic */
	if (should_execute_command(monitor, state, op, command_get_debounce_time())) {
		/* Execute command immediately (only for non-directory-content changes) */
		file_event_t synthetic_event = {
			.path = state->path_state->path,
			.type = event_type_for_mask,
			.time = state->last_update,
			.wall_time = state->wall_time,
			.user_id = event->user_id
		};

		log_message(INFO, "Executing command for %s (watch: %s, operation: %d)",
		            state->path_state->path, watch->name, op);

		if (command_execute(watch, &synthetic_event)) {
			log_message(INFO, "Command execution successful for %s", state->path_state->path);

			/* Update last command time and reset change flags */
			state->last_command_time = state->last_update.tv_sec;
			state->structure_changed = false;
			state->metadata_changed = false;
			state->content_changed = false;

			return true;
		} else {
			log_message(WARNING, "Command execution failed for %s", state->path_state->path);
			return false;
		}
	} else {
		log_message(DEBUG, "Command for %s (op %d) deferred or debounced", state->path_state->path, op);
		return false;
	}
}

/* Update entity states with new watch pointers after config reload */
void update_entity_states_after_reload(config_t *new_config) {
	if (!new_config || !path_states) {
		return;
	}

	pthread_mutex_lock(&entity_states_mutex);

	log_message(DEBUG, "Updating all entity states after reload");

	/* Iterate through all path states and update entity state pointers by name comparison */
	for (int i = 0; i < PATH_HASH_SIZE; i++) {
		path_state_t *ps = path_states[i];
		while (ps) {
			entity_state_t *state = ps->head_entity_state;
			while (state) {
				bool found_new_watch = false;
				for (int j = 0; j < new_config->watch_count; j++) {
					if (state->watch && state->watch->name && new_config->watches[j] &&
					    new_config->watches[j]->name &&
					    strcmp(state->watch->name, new_config->watches[j]->name) == 0) {
						state->watch = new_config->watches[j];
						found_new_watch = true;
						break;
					}
				}
				if (!found_new_watch) {
					log_message(DEBUG, "Could not find new watch for state: %s", state->path_state->path);
				}
				state = state->next_for_path;
			}
			ps = ps->next_in_bucket;
		}
	}

	/* Unlock mutex */
	pthread_mutex_unlock(&entity_states_mutex);
}

/* Clean up entity states that reference deleted watches after config reload */
void cleanup_orphaned_entity_states(config_t *new_config) {
	if (!new_config || !path_states) {
		return;
	}

	pthread_mutex_lock(&entity_states_mutex);

	log_message(DEBUG, "Cleaning up orphaned entity states");

	for (int i = 0; i < PATH_HASH_SIZE; i++) {
		path_state_t *ps = path_states[i];
		path_state_t *prev_ps = NULL;

		while (ps) {
			entity_state_t *state = ps->head_entity_state;
			entity_state_t *prev_state = NULL;

			/* Clean up orphaned entity states within this path state */
			while (state) {
				bool is_orphaned = true;
				for (int j = 0; j < new_config->watch_count; j++) {
					if (state->watch == new_config->watches[j]) {
						is_orphaned = false;
						break;
					}
				}

				if (is_orphaned) {
					log_message(DEBUG, "Removing orphaned state for path %s (watch %s)",
					            state->path_state->path, state->watch ? state->watch->name : "<unknown>");

					entity_state_t *to_free = state;
					if (prev_state) {
						prev_state->next_for_path = state->next_for_path;
					} else {
						ps->head_entity_state = state->next_for_path;
					}
					state = state->next_for_path;
					free_entity_state(to_free);
				} else {
					prev_state = state;
					state = state->next_for_path;
				}
			}

			/* If this path state has no more entity states, remove it */
			if (!ps->head_entity_state) {
				log_message(DEBUG, "Removing empty path state for path %s", ps->path);
				
				path_state_t *to_free_ps = ps;
				if (prev_ps) {
					prev_ps->next_in_bucket = ps->next_in_bucket;
				} else {
					path_states[i] = ps->next_in_bucket;
				}
				ps = ps->next_in_bucket;
				free_path_state(to_free_ps);
			} else {
				prev_ps = ps;
				ps = ps->next_in_bucket;
			}
		}
	}

	/* Unlock mutex */
	pthread_mutex_unlock(&entity_states_mutex);
}
