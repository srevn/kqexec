#include "states.h"

#include <dirent.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "events.h"
#include "logger.h"
#include "registry.h"
#include "scanner.h"
#include "stability.h"

/* Free resources used by an entity state */
static void state_free_entity(entity_t *state) {
	if (state) {
		free(state->trigger);
		free(state);
	}
}

/* Observer callback for watch deactivation */
static void states_handle_deactivation(watchref_t watchref, void *context) {
	states_t *states = (states_t *) context;
	if (!states || !states->buckets) {
		return;
	}

	log_message(DEBUG, "Watch ID %u (gen %u) deactivated, cleaning up states", watchref.watch_id, watchref.generation);

	int entities_removed = 0;
	int nodes_removed = 0;

	/* Scan all buckets for entities with the deactivated watch */
	for (size_t bucket = 0; bucket < states->bucket_count; bucket++) {
		pthread_mutex_lock(&states->mutexes[bucket]);

		node_t **node_ptr = &states->buckets[bucket];
		while (*node_ptr) {
			node_t *node = *node_ptr;

			/* Remove entities with deactivated watch from all groups on this node */
			group_t **group_ptr = &node->groups;
			while (*group_ptr) {
				group_t *group = *group_ptr;
				entity_t **entity_ptr = &group->entities;
				bool group_has_entities = false;

				while (*entity_ptr) {
					entity_t *entity = *entity_ptr;
					if (watchref_equal(entity->watchref, watchref)) {
						log_message(DEBUG, "Removing deactivated entity for path: %s", node->path ? node->path : "<null>");
						*entity_ptr = entity->next;
						state_free_entity(entity);
						entities_removed++;
					} else {
						entity_ptr = &entity->next;
						group_has_entities = true;
					}
				}

				/* If group has no entities left, remove the group */
				if (!group_has_entities) {
					log_message(DEBUG, "Removing empty stability group for path: %s", node->path ? node->path : "<null>");
					*group_ptr = group->next;
					group_destroy(group);
				} else {
					group_ptr = &group->next;
				}
			}

			/* If node has no groups left, remove entire node */
			if (!node->groups) {
				log_message(DEBUG, "Removing empty node after cleanup: %s", node->path ? node->path : "<null>");
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
		log_message(DEBUG, "States cleanup complete: removed %d entities, %d nodes", entities_removed, nodes_removed);
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
	states->observer.handle_deactivation = states_handle_deactivation;
	states->observer.context = states;
	states->observer.next = NULL;

	/* Register as observer with the registry */
	if (registry && !observer_register(registry, &states->observer)) {
		log_message(ERROR, "Failed to register states as observer with registry");
		states_destroy(states);
		return NULL;
	}

	log_message(DEBUG, "State table created with %zu buckets", bucket_count);
	return states;
}

/* Free resources used by a path state and all its entity states */
static void node_free(node_t *node) {
	if (node) {
		/* Free all stability groups and their entities */
		group_t *group = node->groups;
		while (group) {
			group_t *next_group = group->next;

			/* Free all entities in this group */
			entity_t *state = group->entities;
			while (state) {
				entity_t *next_state = state->next;
				state_free_entity(state);
				state = next_state;
			}

			/* Free the group itself */
			group_destroy(group);
			group = next_group;
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
		observer_unregister(states->registry, &states->observer);
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

/* Get or create an entity state for a given path and watch reference */
entity_t *states_get(states_t *states, registry_t *registry, const char *path, watchref_t watchref, kind_t kind) {
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

	/* If node not found, create it with consolidated state */
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

		/* Initialize node state */
		node->executing = false;
		node->kind = kind;
		node->groups = NULL;

		/* Determine node type and existence from filesystem */
		struct stat info;
		node->exists = (stat(path, &info) == 0);

		if (kind == ENTITY_UNKNOWN && node->exists) {
			if (S_ISDIR(info.st_mode)) node->kind = ENTITY_DIRECTORY;
			else if (S_ISREG(info.st_mode)) node->kind = ENTITY_FILE;
		} else if (kind != ENTITY_UNKNOWN) {
			node->kind = kind;
		}

		/* Initialize timestamps on the node */
		clock_gettime(CLOCK_MONOTONIC, &node->last_time);
		clock_gettime(CLOCK_REALTIME, &node->wall_time);
		node->op_time.tv_sec = 0;
		node->op_time.tv_nsec = 0;
		node->content_changed = false;
		node->metadata_changed = false;
		node->structure_changed = false;

		node->next = states->buckets[hash];
		states->buckets[hash] = node;
	}

	/* Calculate configuration hash for this watch */
	uint64_t watch_hash = config_hash(watch);

	/* Find existing stability group with matching configuration */
	group_t *group = node->groups;
	while (group) {
		if (group->config_hash == watch_hash) {
			break;
		}
		group = group->next;
	}

	/* If no matching group found, create a new one */
	if (!group) {
		group = group_create(watch_hash);
		if (!group) {
			log_message(ERROR, "Failed to create stability group for %s", path);
			/* If the node was newly created, clean it up */
			if (!node->groups) {
				states->buckets[hash] = node->next;
				node_free(node);
			}
			pthread_mutex_unlock(&states->mutexes[hash]);
			return NULL;
		}

		/* Initialize the group for directories */
		if (node->kind == ENTITY_DIRECTORY && node->exists) {
			/* Create stability state for this configuration */
			group->stability = stability_create();
			if (!group->stability) {
				log_message(ERROR, "Failed to create stability state for directory: %s", path);
				group_destroy(group);
				if (!node->groups) {
					states->buckets[hash] = node->next;
					node_free(node);
				}
				pthread_mutex_unlock(&states->mutexes[hash]);
				return NULL;
			}

			/* Perform initial scan with this watch's configuration */
			if (scanner_scan(path, watch, &group->stability->stats)) {
				group->stability->prev_stats = group->stability->stats;
				group->stability->ref_stats = group->stability->stats;
				group->stability->reference_init = true;

				log_message(DEBUG, "Initial baseline established for %s: files=%d, dirs=%d, depth=%d, size=%s",
							path, group->stability->stats.tree_files, group->stability->stats.tree_dirs,
							group->stability->stats.max_depth, format_size((ssize_t) group->stability->stats.tree_size, false));
			} else {
				log_message(WARNING, "Failed to gather initial stats for directory: %s", path);
			}
		}

		/* Add the new group to the node */
		group->next = node->groups;
		node->groups = group;
	}

	/* Find existing entity for this watch reference within the group */
	entity_t *state = group->entities;
	while (state) {
		if (watchref_equal(state->watchref, watchref)) {
			pthread_mutex_unlock(&states->mutexes[hash]);
			return state;
		}
		state = state->next;
	}

	/* Create new lightweight entity linking this watch to the node */
	state = calloc(1, sizeof(entity_t));
	if (!state) {
		log_message(ERROR, "Failed to allocate memory for entity: %s", path);
		/* If the node was newly created for this entity, free it to prevent a leak */
		if (!node->groups) {
			states->buckets[hash] = node->next;
			node_free(node);
		}
		pthread_mutex_unlock(&states->mutexes[hash]);
		return NULL;
	}

	/* Initialize entity as lightweight link */
	state->magic = ENTITY_STATE_MAGIC;
	state->node = node;
	state->watchref = watchref;
	state->group = group;
	state->command_time = 0;
	state->trigger = NULL;

	/* Add to the stability group's entity list */
	state->next = group->entities;
	group->entities = state;

	pthread_mutex_unlock(&states->mutexes[hash]);
	return state;
}

/* Calculate configuration hash for a watch to identify compatible groups */
uint64_t config_hash(const watch_t *watch) {
	if (!watch) return 0;

	/* Use FNV-1a hash algorithm */
	uint64_t hash = 14695981039346656037ULL; /* FNV offset basis */
	const uint64_t prime = 1099511628211ULL; /* FNV prime */

	/* Hash boolean flags */
	hash ^= (uint64_t) (watch->recursive ? 1 : 0);
	hash *= prime;
	hash ^= (uint64_t) (watch->hidden ? 1 : 0);
	hash *= prime;

	/* Hash exclude patterns */
	if (watch->exclude && watch->num_exclude > 0) {
		for (int i = 0; i < watch->num_exclude; i++) {
			if (watch->exclude[i]) {
				const char *pattern = watch->exclude[i];
				while (*pattern) {
					hash ^= (uint64_t) (*pattern);
					hash *= prime;
					pattern++;
				}
			}
		}
	}

	return hash;
}

/* Create a new stability group */
group_t *group_create(uint64_t hash) {
	group_t *group = calloc(1, sizeof(group_t));
	if (!group) {
		log_message(ERROR, "Failed to allocate memory for stability group");
		return NULL;
	}

	group->config_hash = hash;

	/* Initialize the mutex for protecting shared group state */
	if (pthread_mutex_init(&group->mutex, NULL) != 0) {
		log_message(ERROR, "Failed to initialize mutex for stability group");
		free(group);
		return NULL;
	}

	group->stability = NULL;
	group->scanner = NULL;
	group->entities = NULL;
	group->next = NULL;

	return group;
}

/* Destroy a stability group and all its resources */
void group_destroy(group_t *group) {
	if (group) {
		stability_destroy(group->stability);
		scanner_destroy(group->scanner);
		pthread_mutex_destroy(&group->mutex);
		free(group);
	}
}
