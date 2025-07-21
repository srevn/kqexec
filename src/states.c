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

/* Hash function for a path string */
static unsigned int state_hash(const char *path, size_t bucket_count) {
	unsigned int hash = 5381; /* djb2 hash initial value */
	if (!path) return 0;
	
	for (const char *p = path; *p; p++) {
		hash = ((hash << 5) + hash) + (unsigned char)*p;
	}
	
	return hash % bucket_count;
}

/* Create a new state table */
state_t *state_create(size_t bucket_count) {
	state_t *table = calloc(1, sizeof(state_t));
	if (!table) {
		log_message(ERROR, "Failed to allocate memory for state table");
		return NULL;
	}

	table->buckets = calloc(bucket_count, sizeof(node_t *));
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
static void state_free_entity(entity_t *state) {
	if (state) {
		scanner_destroy(state->scanner);
		stability_destroy(state->stability);
		free(state->trigger);
		free(state);
	}
}

/* Free resources used by a path state and all its entity states */
static void state_free_node(node_t *node) {
	if (node) {
		entity_t *state = node->entities;
		while (state) {
			entity_t *next = state->next;
			state_free_entity(state);
			state = next;
		}
		free(node->path);
		free(node);
	}
}

/* Destroy a state table */
void state_destroy(state_t *table) {
	if (!table) return;

	/* Lock mutex during cleanup */
	pthread_mutex_lock(&table->mutex);

	/* Free all path states */
	for (size_t i = 0; i < table->bucket_count; i++) {
		node_t *node = table->buckets[i];
		while (node) {
			node_t *next = node->next;
			state_free_node(node);
			node = next;
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

/* Check if entity state is corrupted by verifying magic number */
bool state_corrupted(const entity_t *state) {
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

/* Initialize activity tracking for a new entity state */
static void state_track(entity_t *state, watch_t *watch) {
	if (!state) return;

	state->watch = watch;

	/* Activity tracking is created on demand */
	state->scanner = NULL;
	
	/* Stability tracking is created on demand */
	state->stability = NULL;
}

/* Copies all directory-related statistics and tracking fields from a source to a destination state. */
static void state_copy(entity_t *dest, const entity_t *src) {
	if (!dest || !src) return;

	/* Copy stability state if source has it */
	if (src->stability) {
		if (!dest->stability) {
			dest->stability = stability_create();
			if (!dest->stability) return;
		}
		*dest->stability = *src->stability;
	}

	/* Copy activity state if source has it */
	if (src->scanner) {
		if (!dest->scanner) {
			dest->scanner = scanner_create(src->scanner->active_path);
			if (!dest->scanner) return;
		}
		/* Copy the activity data but preserve the existing active_path */
		char *saved_path = dest->scanner->active_path;
		*dest->scanner = *src->scanner;
		dest->scanner->active_path = saved_path ? strdup(saved_path) : NULL;
		free(saved_path);
	}
}

/* Get or create an entity state for a given path and watch */
entity_t *state_get(state_t *table, const char *path, kind_t kind, watch_t *watch) {
	if (!table || !path || !watch || !table->buckets) {
		log_message(ERROR, "Invalid arguments to state_get");
		return NULL;
	}

	/* Additional safety check for watch structure */
	if (!watch->name) {
		log_message(ERROR, "Watch has NULL name for path %s", path);
		return NULL;
	}

	unsigned int hash = state_hash(path, table->bucket_count);
	
	/* Lock the mutex*/
	pthread_mutex_lock(&table->mutex);
	
	node_t *node = table->buckets[hash];

	/* Find existing node */
	while (node) {
		if (strcmp(node->path, path) == 0) {
			break;
		}
		node = node->next;
	}

	/* If node not found, create it */
	if (!node) {
		node = calloc(1, sizeof(node_t));
		if (!node) {
			log_message(ERROR, "Failed to allocate memory for node: %s", path);
			pthread_mutex_unlock(&table->mutex);
			return NULL;
		}
		node->path = strdup(path);
		if (!node->path) {
			log_message(ERROR, "Failed to duplicate path for node: %s", path);
			free(node);
			pthread_mutex_unlock(&table->mutex);
			return NULL;
		}
		node->next = table->buckets[hash];
		table->buckets[hash] = node;
	}

	/* Find existing entity for this watch */
	entity_t *state = node->entities;
	while (state) {
		if (strcmp(state->watch->name, watch->name) == 0) {
			if (state->kind == ENTITY_UNKNOWN && kind != ENTITY_UNKNOWN) {
				state->kind = kind;
			}
			pthread_mutex_unlock(&table->mutex);
			return state;
		}
		state = state->next;
	}

	/* Check if we have an existing state for this path to copy stats from */
	entity_t *existing_state = node->entities;

	/* Create new entity */
	state = calloc(1, sizeof(entity_t));
	if (!state) {
		log_message(ERROR, "Failed to allocate memory for entity: %s", path);
		/* If the node was newly created for this entity, free it to prevent a leak */
		if (!node->entities) {
			table->buckets[hash] = node->next;
			state_free_node(node);
		}
		pthread_mutex_unlock(&table->mutex);
		return NULL;
	}

	/* Initialize magic number for corruption detection */
	state->magic = ENTITY_STATE_MAGIC;
	
	state->node = node;
	state->kind = kind;
	state->watch = watch;

	struct stat info;
	state->exists = (stat(path, &info) == 0);

	/* Determine entity type from stat if needed */
	if (kind == ENTITY_UNKNOWN && state->exists) {
		if (S_ISDIR(info.st_mode)) state->kind = ENTITY_DIRECTORY;
		else if (S_ISREG(info.st_mode)) state->kind = ENTITY_FILE;
	} else if (kind != ENTITY_UNKNOWN) {
		state->kind = kind;
	}

	clock_gettime(CLOCK_MONOTONIC, &state->last_time);
	clock_gettime(CLOCK_REALTIME, &state->wall_time);
	state->trigger = NULL;

	state_track(state, watch);
	state->command_time = 0;
	state->op_time.tv_sec = 0;
	state->op_time.tv_nsec = 0;

	/* If an existing state for this path was found, copy its stats */
	if (existing_state) {
		log_message(DEBUG, "Copying stats from existing state for path %s (watch: %s)",
		        			path, existing_state->watch->name);
		state_copy(state, existing_state);
	} else {
		/* This is the first state for this path, initialize stats from scratch */
		if (state->kind == ENTITY_DIRECTORY && state->exists) {
			/* Create stability state for directories */
			state->stability = stability_create();
			if (!state->stability) {
				state_free_entity(state);
				if (!node->entities) {
					table->buckets[hash] = node->next;
					state_free_node(node);
				}
				pthread_mutex_unlock(&table->mutex);
				return NULL;
			}

			if (scanner_scan(path, &state->stability->stats)) {
				state->stability->prev_stats = state->stability->stats;
				log_message(DEBUG, "Initial baseline established for %s: files=%d, dirs=%d, depth=%d, size=%s",
				          			path, state->stability->stats.tree_files, state->stability->stats.tree_dirs,
				           			state->stability->stats.max_depth, format_size((ssize_t)state->stability->stats.tree_size, false));

				state->stability->ref_stats = state->stability->stats;
				state->stability->reference_init = true;
			} else {
				log_message(WARNING, "Failed to gather initial stats for directory: %s", path);
			}
		}
	}

	/* Add to the node's list */
	state->next = node->entities;
	node->entities = state;

	log_message(DEBUG, "Created new state for path=%s, watch=%s", path, watch->name);
	
	/* Unlock mutex */
	pthread_mutex_unlock(&table->mutex);
	return state;
}
