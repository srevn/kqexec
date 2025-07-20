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

#include "monitor.h"
#include "states.h"
#include "scanner.h"
#include "stability.h"
#include "command.h"
#include "logger.h"
#include "events.h"
#include "scanner.h"


/* Check if entity state is corrupted by verifying magic number */
bool states_corrupted(const entity_state_t *state) {
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
static unsigned int hash_path(const char *path, size_t bucket_count) {
	unsigned int hash = 5381; /* djb2 hash initial value */
	if (!path) return 0;
	
	for (const char *p = path; *p; p++) {
		hash = ((hash << 5) + hash) + (unsigned char)*p;
	}
	
	return hash % bucket_count;
}

/* Create a new state table */
state_table_t *state_table_create(size_t bucket_count) {
	state_table_t *table = calloc(1, sizeof(state_table_t));
	if (!table) {
		log_message(ERROR, "Failed to allocate memory for state table");
		return NULL;
	}

	table->buckets = calloc(bucket_count, sizeof(path_state_t *));
	if (!table->buckets) {
		log_message(ERROR, "Failed to allocate memory for state table buckets");
		free(table);
		return NULL;
	}

	table->bucket_count = bucket_count;

	/* Initialize the recursive mutex */
	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	if (pthread_mutex_init(&table->mutex, &attr) != 0) {
		log_message(ERROR, "Failed to initialize state table mutex");
		free(table->buckets);
		free(table);
		return NULL;
	}
	pthread_mutexattr_destroy(&attr);

	log_message(DEBUG, "State table created with %zu buckets", bucket_count);
	return table;
}

/* Free resources used by an entity state */
static void free_entity_state(entity_state_t *state) {
	if (state) {
		activity_state_destroy(state->activity);
		stability_state_destroy(state->stability);
		free(state->trigger_path);
		free(state);
	}
}

/* Free resources used by a path state and all its entity states */
static void free_path_state(path_state_t *ps) {
	if (ps) {
		entity_state_t *state = ps->entity_head;
		while (state) {
			entity_state_t *next = state->path_next;
			free_entity_state(state);
			state = next;
		}
		free(ps->path);
		free(ps);
	}
}

/* Destroy a state table */
void state_table_destroy(state_table_t *table) {
	if (!table) return;

	/* Lock mutex during cleanup */
	pthread_mutex_lock(&table->mutex);

	/* Free all path states */
	for (size_t i = 0; i < table->bucket_count; i++) {
		path_state_t *ps = table->buckets[i];
		while (ps) {
			path_state_t *next = ps->bucket_next;
			free_path_state(ps);
			ps = next;
		}
		table->buckets[i] = NULL;
	}
	free(table->buckets);
	table->buckets = NULL;

	/* Unlock mutex after cleanup */
	pthread_mutex_unlock(&table->mutex);
	pthread_mutex_destroy(&table->mutex);

	free(table);
	log_message(DEBUG, "State table destroyed");
}


/* Initialize activity tracking for a new entity state */
static void init_tracking(entity_state_t *state, watch_entry_t *watch) {
	if (!state) return;

	state->watch = watch;

	/* Activity tracking is created on demand */
	state->activity = NULL;
	
	/* Stability tracking is created on demand */
	state->stability = NULL;
}

/* Copies all directory-related statistics and tracking fields from a source to a destination state. */
static void copy_state(entity_state_t *dest, const entity_state_t *src) {
	if (!dest || !src) return;

	/* Copy stability state if source has it */
	if (src->stability) {
		if (!dest->stability) {
			dest->stability = stability_state_create();
			if (!dest->stability) return;
		}
		*dest->stability = *src->stability;
	}

	/* Copy activity state if source has it */
	if (src->activity) {
		if (!dest->activity) {
			dest->activity = activity_state_create(src->activity->active_path);
			if (!dest->activity) return;
		}
		/* Copy the activity data but preserve the existing active_path */
		char *saved_path = dest->activity->active_path;
		*dest->activity = *src->activity;
		dest->activity->active_path = saved_path ? strdup(saved_path) : NULL;
		free(saved_path);
	}
}

/* Get or create an entity state for a given path and watch */
entity_state_t *state_table_get(state_table_t *table, const char *path, entity_type_t type, watch_entry_t *watch) {
	if (!table || !path || !watch || !table->buckets) {
		log_message(ERROR, "Invalid arguments to state_table_get");
		return NULL;
	}

	/* Additional safety check for watch structure */
	if (!watch->name) {
		log_message(ERROR, "Watch has NULL name for path %s", path);
		return NULL;
	}

	unsigned int hash = hash_path(path, table->bucket_count);
	
	/* Lock the mutex*/
	pthread_mutex_lock(&table->mutex);
	
	path_state_t *ps = table->buckets[hash];

	/* Find existing path_state */
	while (ps) {
		if (strcmp(ps->path, path) == 0) {
			break;
		}
		ps = ps->bucket_next;
	}

	/* If path_state not found, create it */
	if (!ps) {
		ps = calloc(1, sizeof(path_state_t));
		if (!ps) {
			log_message(ERROR, "Failed to allocate memory for path_state: %s", path);
			pthread_mutex_unlock(&table->mutex);
			return NULL;
		}
		ps->path = strdup(path);
		if (!ps->path) {
			log_message(ERROR, "Failed to duplicate path for path_state: %s", path);
			free(ps);
			pthread_mutex_unlock(&table->mutex);
			return NULL;
		}
		ps->bucket_next = table->buckets[hash];
		table->buckets[hash] = ps;
	}

	/* Find existing entity_state for this watch */
	entity_state_t *state = ps->entity_head;
	while (state) {
		if (strcmp(state->watch->name, watch->name) == 0) {
			if (state->type == ENTITY_UNKNOWN && type != ENTITY_UNKNOWN) {
				state->type = type;
			}
			pthread_mutex_unlock(&table->mutex);
			return state;
		}
		state = state->path_next;
	}

	/* Check if we have an existing state for this path to copy stats from */
	entity_state_t *existing_state_for_path = ps->entity_head;

	/* Create new entity_state */
	state = calloc(1, sizeof(entity_state_t));
	if (!state) {
		log_message(ERROR, "Failed to allocate memory for entity_state: %s", path);
		/* If the path_state was newly created for this entity, free it to prevent a leak */
		if (!ps->entity_head) {
			table->buckets[hash] = ps->bucket_next;
			free_path_state(ps);
		}
		pthread_mutex_unlock(&table->mutex);
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
	state->trigger_path = NULL;

	init_tracking(state, watch);
	state->command_time = 0;
	state->last_op_time.tv_sec = 0;
	state->last_op_time.tv_nsec = 0;

	/* If an existing state for this path was found, copy its stats */
	if (existing_state_for_path) {
		log_message(DEBUG, "Copying stats from existing state for path %s (watch: %s)",
		        			path, existing_state_for_path->watch->name);
		copy_state(state, existing_state_for_path);
	} else {
		/* This is the first state for this path, initialize stats from scratch */
		if (state->type == ENTITY_DIRECTORY && state->exists) {
			/* Create stability state for directories */
			state->stability = stability_state_create();
			if (!state->stability) {
				free_entity_state(state);
				if (!ps->entity_head) {
					table->buckets[hash] = ps->bucket_next;
					free_path_state(ps);
				}
				pthread_mutex_unlock(&table->mutex);
				return NULL;
			}

			if (scanner_scan(path, &state->stability->dir_stats)) {
				state->stability->prev_stats = state->stability->dir_stats;
				log_message(DEBUG, "Initial baseline established for %s: files=%d, dirs=%d, depth=%d, size=%s",
				          			path, state->stability->dir_stats.tree_files, state->stability->dir_stats.tree_dirs,
				           			state->stability->dir_stats.max_depth, format_size((ssize_t)state->stability->dir_stats.tree_size, false));

				state->stability->reference_stats = state->stability->dir_stats;
				state->stability->reference_init = true;
			} else {
				log_message(WARNING, "Failed to gather initial stats for directory: %s", path);
			}
		}
	}

	/* Add to the path_state's list */
	state->path_next = ps->entity_head;
	ps->entity_head = state;

	log_message(DEBUG, "Created new state for path=%s, watch=%s", path, watch->name);
	
	/* Unlock mutex */
	pthread_mutex_unlock(&table->mutex);
	return state;
}

