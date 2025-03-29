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

/* Record a new activity event in the entity's history */
static void record_activity(entity_state_t *state, operation_type_t op) {
	if (!state) return;

	/* Store in circular buffer */
	state->recent_activity[state->activity_index].timestamp = state->last_update;
	state->recent_activity[state->activity_index].operation = op;

	state->activity_index = (state->activity_index + 1) % MAX_ACTIVITY_SAMPLES;
	if (state->activity_sample_count < MAX_ACTIVITY_SAMPLES) {
		state->activity_sample_count++;
	}

	/* Update Root State's Tree Activity Time for recursive watches */
	if (state->watch && state->watch->recursive) {
		entity_state_t *root = find_root_state(state);
		if (root) {
			/* Only update if the new time is later */
			if (state->last_update.tv_sec > root->last_activity_in_tree.tv_sec ||
				(state->last_update.tv_sec == root->last_activity_in_tree.tv_sec &&
				 state->last_update.tv_nsec > root->last_activity_in_tree.tv_nsec))
			{
				root->last_activity_in_tree = state->last_update;
				log_message(LOG_LEVEL_DEBUG, "Updated root state (%s) tree activity time due to activity on %s",
						root->path, state->path);
			}
		} else if (strcmp(state->path, state->watch->path) != 0) {
			log_message(LOG_LEVEL_WARNING, "Could not find root state for %s to update tree activity time", state->path);
		} else {
			/* This is the root, update its own time if needed */
			if (state->last_update.tv_sec > state->last_activity_in_tree.tv_sec ||
				(state->last_update.tv_sec == state->last_activity_in_tree.tv_sec &&
				 state->last_update.tv_nsec > state->last_activity_in_tree.tv_nsec))
			{
				state->last_activity_in_tree = state->last_update;
			}
		}
	} else if (state->watch && strcmp(state->path, state->watch->path) == 0) {
		/* Non-recursive: Update self only if this IS the root */
		if (state->last_update.tv_sec > state->last_activity_in_tree.tv_sec ||
			(state->last_update.tv_sec == state->last_activity_in_tree.tv_sec &&
			 state->last_update.tv_nsec > state->last_activity_in_tree.tv_nsec))
		{
			state->last_activity_in_tree = state->last_update;
		}
	}
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
		
		log_message(LOG_LEVEL_DEBUG, "Checking quiet period for %s: activity_in_progress = %s",
				  state->path, state->activity_in_progress ? "TRUE" : "FALSE");
		
		if (state->activity_in_progress) {
			double multiplier = 3.0;
			required_ms = (long)(required_ms * multiplier);
			log_message(LOG_LEVEL_DEBUG, "Using adaptive quiet period for %s: %.1fx = %ld ms",
					  state->path, multiplier, required_ms);
		}
	}

	if (required_ms < 10) required_ms = 10;
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
