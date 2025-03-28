#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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

/* Calculate hash for a path */
static unsigned int hash_path(const char *path) {
	unsigned int hash = 0;
	
	for (const char *p = path; *p; p++) {
		hash = hash * 31 + *p;
	}
	
	return hash % ENTITY_HASH_SIZE;
}

/* Get or create entity state */
entity_state_t *get_entity_state(const char *path, entity_type_t type) {
	unsigned int hash = hash_path(path);
	entity_state_t *state = entity_states[hash];
	
	/* Look for existing state */
	while (state) {
		if (strcmp(state->path, path) == 0) {
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
	
	/* Initialize state */
	struct stat st;
	state->exists = (stat(path, &st) == 0);
	
	/* Set default timestamps */
	clock_gettime(CLOCK_MONOTONIC, &state->last_update);
	clock_gettime(CLOCK_REALTIME, &state->wall_time);
	
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
	long elapsed_ms;
	
	/* Get current time */
	clock_gettime(CLOCK_MONOTONIC, &now);
	
	/* Calculate time since last command */
	elapsed_ms = (now.tv_sec - state->last_command_time) * 1000;
	
	/* Different debounce times for different operations */
	int debounce_ms = default_debounce_ms;
	
	/* Adjust debounce based on operation importance */
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
	log_message(LOG_LEVEL_DEBUG, "Processing event for %s (entity_type: %s, event_type: %s)", 
			   event->path, 
			   entity_type == ENTITY_FILE ? "FILE" : "DIRECTORY", 
			   event_type_to_string(event->type));
	
	/* Get entity state */
	entity_state_t *state = get_entity_state(event->path, entity_type);
	if (state == NULL) {
		log_message(LOG_LEVEL_ERR, "Failed to get entity state for %s", event->path);
		return false;
	}
	
	/* Update timestamps */
	clock_gettime(CLOCK_MONOTONIC, &state->last_update);
	state->wall_time = event->wall_time;
	
	/* Determine operation type */
	operation_type_t op = determine_operation(state, event->type);
	log_message(LOG_LEVEL_DEBUG, "Determined operation %d for %s", op, event->path);
	
	/* If no operation detected, skip */
	if (op == OP_NONE) {
		log_message(LOG_LEVEL_DEBUG, "No operation detected for %s", event->path);
		return false;
	}
	
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
		log_message(LOG_LEVEL_INFO, "Executing command for %s (operation: %d)", 
				   state->path, op);
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
