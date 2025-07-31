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
#include "registry.h"
#include "scanner.h"

/* Free resources used by an entity state */
static void state_free_entity(entity_t *state) {
	if (state) {
		scanner_destroy(state->scanner);
		stability_destroy(state->stability);
		free(state->trigger);
		free(state);
	}
}

/* Observer callback for watch deactivation */
static void states_on_watch_deactivated(watchref_t ref, void *context) {
	states_t *states = (states_t *)context;
	if (!states || !states->buckets) {
		return;
	}
	
	log_message(DEBUG, "States observer: Watch ID %u (gen %u) deactivated, cleaning up states", 
	           ref.watch_id, ref.generation);
	
	int entities_removed = 0;
	int nodes_removed = 0;
	
	/* Scan all buckets for entities with the deactivated watch */
	for (size_t bucket = 0; bucket < states->bucket_count; bucket++) {
		pthread_mutex_lock(&states->mutexes[bucket]);
		
		node_t **node_ptr = &states->buckets[bucket];
		while (*node_ptr) {
			node_t *node = *node_ptr;
			
			/* Remove entities with deactivated watch from this node */
			entity_t **entity_ptr = &node->entities;
			while (*entity_ptr) {
				entity_t *entity = *entity_ptr;
				if (watchref_equal(entity->watchref, ref)) {
					log_message(DEBUG, "Removing deactivated entity for path: %s", 
					           node->path ? node->path : "<null>");
					*entity_ptr = entity->next;
					state_free_entity(entity);
					entities_removed++;
				} else {
					entity_ptr = &entity->next;
				}
			}
			
			/* If node has no entities left, remove entire node */
			if (!node->entities) {
				log_message(DEBUG, "Removing empty node after cleanup: %s", 
				           node->path ? node->path : "<null>");
				*node_ptr = node->next;
				free(node->path);
				free(node);
				nodes_removed++;
			} else {
				node_ptr = &node->next;
			}
		}
		
		pthread_mutex_unlock(&states->mutexes[bucket]);
	}
	
	if (entities_removed > 0 || nodes_removed > 0) {
		log_message(DEBUG, "States cleanup complete: removed %d entities, %d nodes", 
		           entities_removed, nodes_removed);
	}
}

/* Hash function for a path string */
unsigned int states_hash(const char *path, size_t bucket_count) {
	unsigned int hash = 5381; /* djb2 hash initial value */
	if (!path) return 0;

	for (const char *p = path; *p; p++) {
		hash = ((hash << 5) + hash) + (unsigned char) *p;
	}

	return hash % bucket_count;
}

/* Create a new state table */
states_t *states_create(size_t bucket_count, registry_t *registry) {
	states_t *states = calloc(1, sizeof(states_t));
	if (!states) {
		log_message(ERROR, "Failed to allocate memory for state table");
		return NULL;
	}

	states->buckets = calloc(bucket_count, sizeof(node_t *));
	if (!states->buckets) {
		log_message(ERROR, "Failed to allocate memory for state table buckets");
		free(states);
		return NULL;
	}

	states->bucket_count = bucket_count;

	/* Allocate array of mutexes */
	states->mutexes = calloc(bucket_count, sizeof(pthread_mutex_t));
	if (!states->mutexes) {
		log_message(ERROR, "Failed to allocate memory for mutexes");
		free(states->buckets);
		free(states);
		return NULL;
	}

	/* Initialize all mutexes (standard, non-recursive) */
	for (size_t i = 0; i < bucket_count; i++) {
		if (pthread_mutex_init(&states->mutexes[i], NULL) != 0) {
			log_message(ERROR, "Failed to initialize mutex %zu", i);
			/* Clean up previously initialized mutexes */
			for (size_t j = 0; j < i; j++) {
				pthread_mutex_destroy(&states->mutexes[j]);
			}
			free(states->mutexes);
			free(states->buckets);
			free(states);
			return NULL;
		}
	}

	/* Initialize registry integration */
	states->registry = registry;
	states->observer.on_watch_deactivated = states_on_watch_deactivated;
	states->observer.context = states;
	states->observer.next = NULL;
	
	/* Register as observer with the registry */
	if (registry && !register_observer(registry, &states->observer)) {
		log_message(ERROR, "Failed to register states as observer with registry");
		states_destroy(states);
		return NULL;
	}

	log_message(DEBUG, "State table created with %zu buckets and registry observer registered",
				bucket_count);
	return states;
}

/* Free resources used by a path state and all its entity states */
static void node_free(node_t *node) {
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
void states_destroy(states_t *states) {
	if (!states) return;

	/* Unregister from registry observer notifications */
	if (states->registry) {
		unregister_observer(states->registry, &states->observer);
	}

	/* Lock all mutexes during cleanup to ensure thread safety */
	for (size_t i = 0; i < states->bucket_count; i++) {
		pthread_mutex_lock(&states->mutexes[i]);
	}

	/* Free all path states */
	for (size_t i = 0; i < states->bucket_count; i++) {
		node_t *node = states->buckets[i];
		while (node) {
			node_t *next = node->next;
			node_free(node);
			node = next;
		}
		states->buckets[i] = NULL;
	}
	free(states->buckets);
	states->buckets = NULL;

	/* Unlock and destroy all mutexes */
	for (size_t i = 0; i < states->bucket_count; i++) {
		pthread_mutex_unlock(&states->mutexes[i]);
		pthread_mutex_destroy(&states->mutexes[i]);
	}
	free(states->mutexes);
	states->mutexes = NULL;

	free(states);
	log_message(DEBUG, "State table destroyed and observer unregistered");
}

/* Check if entity state is corrupted by verifying magic number */
bool state_corrupted(const entity_t *state) {
	if (!state) return true;

	if ((uintptr_t) state < 0x1000 || ((uintptr_t) state & 0x7) != 0) {
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
static void state_track(entity_t *state, watchref_t watchref) {
	if (!state) return;

	state->watchref = watchref;

	/* Activity tracking is created on demand */
	state->scanner = NULL;

	/* Stability tracking is created on demand */
	state->stability = NULL;
}

/* Copies all directory-related statistics and tracking fields from a source to a destination state */
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
			/* If the destination doesn't have a scanner, create a blank one */
			dest->scanner = scanner_create(NULL);
			if (!dest->scanner) return;
		}

		/* Preserve the pointer to the old path */
		char *saved_path = dest->scanner->active_path;

		/* Perform a full, shallow copy of the entire struct */
		*dest->scanner = *src->scanner;

		/* Give the destination its own deep copy of the path pointer */
		dest->scanner->active_path = src->scanner->active_path ? strdup(src->scanner->active_path) : NULL;
		free(saved_path);
	}
}



/* Get or create an entity state for a given path and watch reference */
entity_t *states_get(states_t *states, const char *path, kind_t kind, watchref_t watchref, registry_t *registry) {
	if (!states || !path || !watchref_valid(watchref) || !registry || !states->buckets) {
		log_message(ERROR, "Invalid arguments to states_get");
		return NULL;
	}

	/* Validate watch reference against registry */
	if (!registry_valid(registry, watchref)) {
		log_message(WARNING, "Watch reference is invalid or deactivated");
		return NULL;
	}

	/* Get watch for logging purposes */
	watch_t *watch = registry_get(registry, watchref);
	if (!watch || !watch->name) {
		log_message(ERROR, "Could not resolve watch from registry for path %s", path);
		return NULL;
	}

	unsigned int hash = states_hash(path, states->bucket_count);

	/* Lock only the specific mutex for this bucket */
	pthread_mutex_lock(&states->mutexes[hash]);

	node_t *node = states->buckets[hash];

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
			pthread_mutex_unlock(&states->mutexes[hash]);
			return NULL;
		}
		node->path = strdup(path);
		if (!node->path) {
			log_message(ERROR, "Failed to duplicate path for node: %s", path);
			free(node);
			pthread_mutex_unlock(&states->mutexes[hash]);
			return NULL;
		}
		node->executing = false;
		node->next = states->buckets[hash];
		states->buckets[hash] = node;
	}

	/* Find existing entity for this watch reference */
	entity_t *state = node->entities;
	while (state) {
		if (watchref_equal(state->watchref, watchref)) {
			/* Update kind if it was previously unknown */
			if (state->kind == ENTITY_UNKNOWN && kind != ENTITY_UNKNOWN) {
				state->kind = kind;
			}
			pthread_mutex_unlock(&states->mutexes[hash]);
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
			states->buckets[hash] = node->next;
			node_free(node);
		}
		pthread_mutex_unlock(&states->mutexes[hash]);
		return NULL;
	}

	/* Initialize magic number for corruption detection */
	state->magic = ENTITY_STATE_MAGIC;

	state->node = node;
	state->kind = kind;
	state->watchref = watchref;

	/* If an existing state for this path was found, inherit its existence status */
	if (existing_state) {
		state->exists = existing_state->exists;
	} else {
		struct stat info;
		state->exists = (stat(path, &info) == 0);
	}

	/* Determine entity type from stat if needed */
	if (kind == ENTITY_UNKNOWN && state->exists) {
		struct stat info;
		if (stat(path, &info) == 0) {
			if (S_ISDIR(info.st_mode)) state->kind = ENTITY_DIRECTORY;
			else if (S_ISREG(info.st_mode)) state->kind = ENTITY_FILE;
		}
	} else if (kind != ENTITY_UNKNOWN) {
		state->kind = kind;
	}

	clock_gettime(CLOCK_MONOTONIC, &state->last_time);
	clock_gettime(CLOCK_REALTIME, &state->wall_time);
	state->trigger = NULL;

	state_track(state, watchref);
	state->command_time = 0;
	state->op_time.tv_sec = 0;
	state->op_time.tv_nsec = 0;

	/* If an existing state for this path was found, copy its stats */
	if (existing_state) {
		state_copy(state, existing_state);
	} else {
		/* This is the first state for this path, initialize stats from scratch */
		if (state->kind == ENTITY_DIRECTORY && state->exists) {
			/* Create stability state for directories */
			state->stability = stability_create();
			if (!state->stability) {
				state_free_entity(state);
				if (!node->entities) {
					states->buckets[hash] = node->next;
					node_free(node);
				}
				pthread_mutex_unlock(&states->mutexes[hash]);
				return NULL;
			}

			if (scanner_scan(path, &state->stability->stats)) {
				state->stability->prev_stats = state->stability->stats;
				log_message(DEBUG, "Initial baseline established for %s: files=%d, dirs=%d, depth=%d, size=%s",
				            path, state->stability->stats.tree_files, state->stability->stats.tree_dirs,
				            state->stability->stats.max_depth, format_size((ssize_t) state->stability->stats.tree_size, false));

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
	pthread_mutex_unlock(&states->mutexes[hash]);
	return state;
}
