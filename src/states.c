#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h> 
#include <sys/stat.h>
#include <libgen.h>
#include <unistd.h>

#include "states.h"
#include "command.h"
#include "log.h"

/* Hash table size for storing entity states */
#define ENTITY_HASH_SIZE 64

/* Hash table of entity states */
static entity_state_t **entity_states = NULL;

/* Initialize entity state system */
void entity_state_init(void) {
	/* Allocate and initialize entity state hash table */
	entity_states = calloc(ENTITY_HASH_SIZE, sizeof(entity_state_t *));
	if (entity_states == NULL) {
		log_message(LOG_LEVEL_ERR, "Failed to allocate memory for entity states");
		return;
	}
}

/* Free an entity state */
static void free_entity_state(entity_state_t *state) {
	if (state) {
		free(state->path);
		free(state);
	}
}

/* Clean up entity state system */
void entity_state_cleanup(void) {
	if (entity_states == NULL) {
		return;
	}
	
	/* Free all entity states */
	for (int i = 0; i < ENTITY_HASH_SIZE; i++) {
		entity_state_t *state = entity_states[i];
		while (state) {
			entity_state_t *next = state->next;
			free_entity_state(state);
			state = next;
		}
	}
	
	free(entity_states);
	entity_states = NULL;
}

/* Initialize activity tracking for a new entity state */
static void init_activity_tracking(entity_state_t *state, watch_entry_t *watch) {
	state->activity_sample_count = 0;
	state->activity_index = 0;
	state->activity_in_progress = false;
	state->watch = watch;  // Store watch reference for command association
}

/* Record a new event in the activity history */
static void record_activity(entity_state_t *state, operation_type_t op) {
	/* Store in circular buffer */
	state->recent_activity[state->activity_index].timestamp = state->last_update;
	state->recent_activity[state->activity_index].operation = op;
	
	/* Update circular buffer index */
	state->activity_index = (state->activity_index + 1) % MAX_ACTIVITY_SAMPLES;
	
	/* Increment count up to the maximum */
	if (state->activity_sample_count < MAX_ACTIVITY_SAMPLES) {
		state->activity_sample_count++;
	}
	
	/* Mark activity as in progress */
	state->activity_in_progress = true;
}

/* Calculate time between last two activities in milliseconds */
static long get_activity_interval_ms(entity_state_t *state) {
	if (state->activity_sample_count < 2) {
		return LONG_MAX;  /* No interval if fewer than 2 samples */
	}
	
	/* Calculate indices of the two most recent samples */
	int latest_idx = (state->activity_index + MAX_ACTIVITY_SAMPLES - 1) % MAX_ACTIVITY_SAMPLES;
	int prev_idx = (latest_idx + MAX_ACTIVITY_SAMPLES - 1) % MAX_ACTIVITY_SAMPLES;
	
	/* Calculate time difference in milliseconds */
	struct timespec *newer = &state->recent_activity[latest_idx].timestamp;
	struct timespec *older = &state->recent_activity[prev_idx].timestamp;
	
	return (newer->tv_sec - older->tv_sec) * 1000 + 
		   (newer->tv_nsec - older->tv_nsec) / 1000000;
}

/* Analyze activity to detect bursts by checking frequency of recent events */
static bool is_activity_burst(entity_state_t *state) {
	if (state->activity_sample_count < 2) {
		return false;  /* Need at least 2 samples to detect a burst */
	}
	
	/* Check if the interval between recent events is short (indicating a burst) */
	long interval_ms = get_activity_interval_ms(state);
	return interval_ms < QUIET_PERIOD_MS / 2;  /* Bursts have events close together */
}

/* Check if enough quiet time has passed since the last activity */
bool is_quiet_period_elapsed(entity_state_t *state, struct timespec *now) {
	if (state->activity_sample_count == 0) {
		return true;  /* No activity recorded yet */
	}
	
	/* Get most recent activity timestamp */
	int latest_idx = (state->activity_index + MAX_ACTIVITY_SAMPLES - 1) % MAX_ACTIVITY_SAMPLES;
	struct timespec *last_activity = &state->recent_activity[latest_idx].timestamp;
	
	/* Calculate time difference in milliseconds */
	long elapsed_ms = (now->tv_sec - last_activity->tv_sec) * 1000 + 
					  (now->tv_nsec - last_activity->tv_nsec) / 1000000;
	
	/* Determine appropriate quiet period based on entity type and burst detection */
	long required_quiet_period = QUIET_PERIOD_MS;
	
	/* Use longer quiet period for directory operations with bursts of activity */
	if (state->type == ENTITY_DIRECTORY && is_activity_burst(state)) {
		required_quiet_period = DIR_QUIET_PERIOD_MS;
		
		/* Adaptive quiet period - the busier the directory, the longer we wait */
		if (state->activity_sample_count == MAX_ACTIVITY_SAMPLES) {
			required_quiet_period *= 1.5;  /* Even longer for very busy directories */
		}
	}
	
	/* Return true if enough quiet time has elapsed */
	return elapsed_ms >= required_quiet_period;
}

/* Calculate hash for a path and watch entry combination */
static unsigned int hash_path_watch(const char *path, watch_entry_t *watch) {
	unsigned int hash = 0;
	
	/* Hash the path */
	for (const char *p = path; *p; p++) {
		hash = hash * 31 + *p;
	}
	
	/* Incorporate the watch pointer for uniqueness */
	hash = hash * 31 + (uintptr_t)watch;
	
	return hash % ENTITY_HASH_SIZE;
}

/* Get or create entity state */
entity_state_t *get_entity_state(const char *path, entity_type_t type, watch_entry_t *watch) {
	unsigned int hash = hash_path_watch(path, watch);
	entity_state_t *state = entity_states[hash];
	
	/* Look for existing state matching both path AND watch */
	while (state) {
		if (strcmp(state->path, path) == 0 && state->watch == watch) {
			/* Update entity type if it was unknown */
			if (state->type == ENTITY_UNKNOWN && type != ENTITY_UNKNOWN) {
				state->type = type;
			}
			return state;
		}
		state = state->next;
	}
	
	/* Create new state */
	state = calloc(1, sizeof(entity_state_t));
	if (!state) {
		log_message(LOG_LEVEL_ERR, "Failed to allocate memory for entity state");
		return NULL;
	}
	
	state->path = strdup(path);
	if (!state->path) {
		free(state);
		return NULL;
	}
	
	state->type = type;
	state->watch = watch;  /* Store watch entry reference */
	
	/* Initialize state */
	struct stat st;
	state->exists = (stat(path, &st) == 0);
	
	/* Set default timestamps */
	clock_gettime(CLOCK_MONOTONIC, &state->last_update);
	clock_gettime(CLOCK_REALTIME, &state->wall_time);
	
	/* Initialize activity tracking */
	init_activity_tracking(state, watch);
	
	/* Initialize to zero command time */
	state->last_command_time = 0;
	
	/* Add to hash table */
	state->next = entity_states[hash];
	entity_states[hash] = state;
	
	return state;
}

/* Determine operation type based on entity state and new event */
operation_type_t determine_operation(entity_state_t *state, event_type_t new_event_type) {
	/* Update state based on new event */
	if (new_event_type & EVENT_CONTENT) {
		state->content_changed = true;
	}
	if (new_event_type & EVENT_METADATA) {
		state->metadata_changed = true;
	}
	if (new_event_type & EVENT_MODIFY) {
		state->structure_changed = true;
	}
	
	/* Check if entity exists now */
	struct stat st;
	bool exists_now = (stat(state->path, &st) == 0);
	
	/* Handle deletion case */
	if (state->exists && !exists_now) {
		state->exists = false;
		log_message(LOG_LEVEL_DEBUG, "Entity %s no longer exists (deleted)", state->path);
		return (state->type == ENTITY_FILE) ? 
			OP_FILE_DELETED : OP_DIR_DELETED;
	}
	
	/* Handle creation case */
	if (!state->exists && exists_now) {
		state->exists = true;
		log_message(LOG_LEVEL_DEBUG, "Entity %s now exists (created)", state->path);
		return (state->type == ENTITY_FILE) ? 
			OP_FILE_CREATED : OP_DIR_CREATED;
	}
	
	/* Update existence state */
	state->exists = exists_now;
	
	/* Handle other changes with priority */
	if (state->structure_changed) {
		log_message(LOG_LEVEL_DEBUG, "Entity %s had structural change", state->path);
		return (state->type == ENTITY_FILE) ? 
			OP_FILE_RENAMED : OP_DIR_CONTENT_CHANGED;
	}
	
	if (state->content_changed) {
		log_message(LOG_LEVEL_DEBUG, "Entity %s had content change", state->path);
		return (state->type == ENTITY_FILE) ? 
			OP_FILE_CONTENT_CHANGED : OP_DIR_CONTENT_CHANGED;
	}
	
	if (state->metadata_changed) {
		log_message(LOG_LEVEL_DEBUG, "Entity %s had metadata change", state->path);
		return (state->type == ENTITY_FILE) ? 
			OP_FILE_METADATA_CHANGED : OP_DIR_METADATA_CHANGED;
	}
	
	return OP_NONE;
}

/* Convert operation type to event type */
event_type_t operation_to_event_type(operation_type_t op) {
	switch (op) {
		case OP_FILE_CONTENT_CHANGED:
		case OP_DIR_CONTENT_CHANGED:
			return EVENT_CONTENT;
			
		case OP_FILE_CREATED:
		case OP_FILE_DELETED:
		case OP_FILE_RENAMED:
		case OP_DIR_CREATED:
		case OP_DIR_DELETED:
			return EVENT_MODIFY;
			
		case OP_FILE_METADATA_CHANGED:
		case OP_DIR_METADATA_CHANGED:
			return EVENT_METADATA;
			
		default:
			return EVENT_NONE;
	}
}

/* Check if command should be executed based on debouncing rules */
bool should_execute_command(entity_state_t *state, operation_type_t op, int default_debounce_ms) {
	struct timespec now;
	
	/* Get current time */
	clock_gettime(CLOCK_MONOTONIC, &now);
	
	/* Record this activity */
	record_activity(state, op);
	
	/* For directory content operations, enforce a quiet period */
	if (op == OP_DIR_CONTENT_CHANGED) {
		/* If we're still detecting activity, don't execute yet */
		if (!is_quiet_period_elapsed(state, &now)) {
			log_message(LOG_LEVEL_DEBUG, "Activity in progress for %s, deferring command execution",
					  state->path);
			return false;
		}
		
		/* Quiet period has elapsed, mark activity as complete */
		state->activity_in_progress = false;
	}
	
	/* Continue with standard debounce logic */
	long elapsed_ms = (now.tv_sec - state->last_command_time) * 1000;
	
	/* Adjust debounce based on operation importance */
	int debounce_ms = default_debounce_ms;
	
	switch (op) {
		case OP_FILE_DELETED:
		case OP_DIR_DELETED:
		case OP_FILE_CREATED:
		case OP_DIR_CREATED:
			/* Important lifecycle events - shorter debounce */
			debounce_ms = default_debounce_ms / 4;
			break;
		
		case OP_FILE_CONTENT_CHANGED:
			/* Content changes - medium debounce */
			debounce_ms = default_debounce_ms / 2;
			break;
			
		default:
			/* Standard debounce for everything else */
			break;
	}
	
	/* Log debounce decision */
	log_message(LOG_LEVEL_DEBUG, "Debounce check for %s: elapsed=%ld ms, required=%d ms", 
			   state->path, elapsed_ms, debounce_ms);
	
	/* Execute if enough time has passed since last command */
	if (elapsed_ms >= debounce_ms || state->last_command_time == 0) {
		state->last_command_time = now.tv_sec;
		return true;
	}
	
	log_message(LOG_LEVEL_DEBUG, "Command execution debounced for %s", state->path);
	return false;
}

/* Process an event and execute command if needed */
bool process_event(watch_entry_t *watch, file_event_t *event, entity_type_t entity_type) {
	if (watch == NULL || event == NULL) {
		log_message(LOG_LEVEL_ERR, "Invalid arguments to process_event");
		return false;
	}
	
	/* Log the incoming event */
	log_message(LOG_LEVEL_DEBUG, "Processing event for %s (watch: %s, event_type: %s)", 
			   event->path, watch->name, event_type_to_string(event->type));
	
	/* Get entity state - now also passing the watch entry */
	entity_state_t *state = get_entity_state(event->path, entity_type, watch);
	if (state == NULL) {
		log_message(LOG_LEVEL_ERR, "Failed to get entity state for %s", event->path);
		return false;
	}
	
	/* Update timestamps */
	clock_gettime(CLOCK_MONOTONIC, &state->last_update);
	state->wall_time = event->wall_time;
	
	/* Determine operation type */
	operation_type_t op = determine_operation(state, event->type);
	
	/* If no operation detected, skip */
	if (op == OP_NONE) {
		log_message(LOG_LEVEL_DEBUG, "No operation detected for %s", event->path);
		return false;
	}
	
	log_message(LOG_LEVEL_DEBUG, "Determined operation %d for %s (watch: %s)", 
			   op, event->path, watch->name);
	
	/* Convert operation to event type */
	event_type_t event_type = operation_to_event_type(op);
	
	/* Check if event type matches watch mask */
	if ((watch->events & event_type) == 0) {
		log_message(LOG_LEVEL_DEBUG, "Event type %s not in watch mask for %s", 
				   event_type_to_string(event_type), event->path);
		return false;
	}
	
	/* Check if we should execute command (handles debouncing) */
	if (should_execute_command(state, op, command_get_debounce_time())) {
		/* Create synthetic event for command */
		file_event_t synthetic_event = {
			.path = state->path,
			.type = event_type,
			.time = state->last_update,
			.wall_time = state->wall_time,
			.user_id = event->user_id
		};
		
		/* Execute command */
		log_message(LOG_LEVEL_INFO, "Executing command for %s (watch: %s, operation: %d)", 
				   state->path, watch->name, op);
		bool result = command_execute(watch, &synthetic_event);
		
		if (result) {
			log_message(LOG_LEVEL_INFO, "Command execution successful for %s", state->path);
		} else {
			log_message(LOG_LEVEL_WARNING, "Command execution failed for %s", state->path);
		}
		
		/* Reset state flags after execution */
		state->content_changed = false;
		state->metadata_changed = false;
		state->structure_changed = false;
		
		return result;
	}
	
	return false;
}
