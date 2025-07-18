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

/* Hash table of path states */
static path_state_t **path_states = NULL;

/* Mutex for protecting access to the path_states hash table */
pthread_mutex_t states_mutex;

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
static unsigned int hash_path(const char *path) {
	unsigned int hash = 5381; /* djb2 hash initial value */
	if (!path) return 0;
	
	for (const char *p = path; *p; p++) {
		hash = ((hash << 5) + hash) + (unsigned char)*p;
	}
	
	return hash % PATH_HASH_SIZE;
}

/* Initialize the entity state system */
bool states_init(void) {
	path_states = calloc(PATH_HASH_SIZE, sizeof(path_state_t *));
	if (path_states == NULL) {
		log_message(ERROR, "Failed to allocate memory for path states");
		return false;
	}

	/* Initialize the recursive mutex */
	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	if (pthread_mutex_init(&states_mutex, &attr) != 0) {
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
		free(state->active_path);
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

/* Clean up the entity state system */
void states_cleanup(void) {
	if (path_states == NULL) return;

	/* Lock mutex during cleanup */
	pthread_mutex_lock(&states_mutex);

	/* Free all path states */
	for (int i = 0; i < PATH_HASH_SIZE; i++) {
		path_state_t *ps = path_states[i];
		while (ps) {
			path_state_t *next = ps->bucket_next;
			free_path_state(ps);
			ps = next;
		}
		path_states[i] = NULL;
	}
	free(path_states);
	path_states = NULL;

	/* Unlock mutex after cleanup */
	pthread_mutex_unlock(&states_mutex);
	pthread_mutex_destroy(&states_mutex);

	log_message(DEBUG, "Entity state system cleanup complete");
}

/* Initialize activity tracking for a new entity state */
static void init_tracking(entity_state_t *state, watch_entry_t *watch) {
	if (!state) return;

	state->activity_count = 0;
	state->activity_index = 0;
	state->activity_active = false;
	state->watch = watch;

	/* Initialize tree time. Use last_update as a reasonable starting point. */
	state->tree_activity = state->last_update;
}

/* Copies all directory-related statistics and tracking fields from a source to a destination state. */
static void copy_state(entity_state_t *dest, const entity_state_t *src) {
	if (!dest || !src) return;

	dest->dir_stats = src->dir_stats;
	dest->prev_stats = src->prev_stats;
	dest->reference_stats = src->reference_stats;
	dest->reference_init = src->reference_init;
	dest->cumulative_file = src->cumulative_file;
	dest->cumulative_dirs = src->cumulative_dirs;
	dest->cumulative_depth = src->cumulative_depth;
	dest->cumulative_size = src->cumulative_size;
	dest->stability_lost = src->stability_lost;
	dest->unstable_count = src->unstable_count;
	dest->required_checks = src->required_checks;
}

/* Get or create an entity state for a given path and watch */
entity_state_t *states_get(const char *path, entity_type_t type, watch_entry_t *watch) {
	if (!path || !watch || !path_states) {
		log_message(ERROR, "Invalid arguments to states_get");
		return NULL;
	}

	/* Additional safety check for watch structure */
	if (!watch->name) {
		log_message(ERROR, "Watch has NULL name for path %s", path);
		return NULL;
	}

	unsigned int hash = hash_path(path);
	
	/* Lock the mutex*/
	pthread_mutex_lock(&states_mutex);
	
	path_state_t *ps = path_states[hash];

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
			pthread_mutex_unlock(&states_mutex);
			return NULL;
		}
		ps->path = strdup(path);
		if (!ps->path) {
			log_message(ERROR, "Failed to duplicate path for path_state: %s", path);
			free(ps);
			pthread_mutex_unlock(&states_mutex);
			return NULL;
		}
		ps->bucket_next = path_states[hash];
		path_states[hash] = ps;
	}

	/* Find existing entity_state for this watch */
	entity_state_t *state = ps->entity_head;
	while (state) {
		if (strcmp(state->watch->name, watch->name) == 0) {
			if (state->type == ENTITY_UNKNOWN && type != ENTITY_UNKNOWN) {
				state->type = type;
			}
			pthread_mutex_unlock(&states_mutex);
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
			path_states[hash] = ps->bucket_next;
			free_path_state(ps);
		}
		pthread_mutex_unlock(&states_mutex);
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
	state->tree_activity = state->last_update;
	state->active_path = strdup(path);
	state->trigger_path = NULL;

	init_tracking(state, watch);
	state->command_time = 0;
	state->checks_failed = 0;
	state->required_checks = 0;

	/* If an existing state for this path was found, copy its stats */
	if (existing_state_for_path) {
		log_message(DEBUG, "Copying stats from existing state for path %s (watch: %s)",
		        			path, existing_state_for_path->watch->name);
		copy_state(state, existing_state_for_path);
		state->is_new = false;
	} else {
		/* This is the first state for this path, initialize stats from scratch */
		state->is_new = true;
		state->unstable_count = 0;
		state->required_checks = 0;
		state->reference_init = false;
		state->cumulative_file = 0;
		state->cumulative_dirs = 0;
		state->cumulative_depth = 0;
		state->cumulative_size = 0;
		state->stability_lost = false;
		state->check_pending = false;

		if (state->type == ENTITY_DIRECTORY && state->exists) {
			if (scanner_scan(path, &state->dir_stats)) {
				/* For a new state, prev_stats is zeroed to correctly calculate the initial change */
				memset(&state->prev_stats, 0, sizeof(dir_stats_t));
				state->reference_stats = state->dir_stats;
				state->reference_init = true;

				log_message(DEBUG, "Initialized directory stats for %s: files=%d, dirs=%d, depth=%d, size=%s",
				        			path, state->dir_stats.tree_files, state->dir_stats.tree_dirs,
				        			state->dir_stats.max_depth, format_size((ssize_t)state->dir_stats.tree_size, false));
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
	pthread_mutex_unlock(&states_mutex);
	return state;
}

/* Update entity states with new watch pointers after config reload */
void states_update(config_t *new_config) {
	if (!new_config || !path_states) {
		return;
	}

	/* Lock mutex to ensure thread safety during update */
	pthread_mutex_lock(&states_mutex);

	log_message(DEBUG, "Updating all entity states after reload");

	/* Iterate through all path states and update entity state pointers by name comparison */
	for (int i = 0; i < PATH_HASH_SIZE; i++) {
		path_state_t *ps = path_states[i];
		while (ps) {
			entity_state_t *state = ps->entity_head;
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
				state = state->path_next;
			}
			ps = ps->bucket_next;
		}
	}

	/* Unlock mutex */
	pthread_mutex_unlock(&states_mutex);
}

/* Clean up entity states that reference deleted watches after config reload */
void states_prune(config_t *new_config) {
	if (!new_config || !path_states) {
		return;
	}

	/* Lock mutex to ensure thread safety during prune */
	pthread_mutex_lock(&states_mutex);

	log_message(DEBUG, "Cleaning up orphaned entity states");

	for (int i = 0; i < PATH_HASH_SIZE; i++) {
		path_state_t *ps = path_states[i];
		path_state_t *prev_ps = NULL;

		while (ps) {
			entity_state_t *state = ps->entity_head;
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
						prev_state->path_next = state->path_next;
					} else {
						ps->entity_head = state->path_next;
					}
					state = state->path_next;
					free_entity_state(to_free);
				} else {
					prev_state = state;
					state = state->path_next;
				}
			}

			/* If this path state has no more entity states, remove it */
			if (!ps->entity_head) {
				log_message(DEBUG, "Removing empty path state for path %s", ps->path);
				
				path_state_t *to_free_ps = ps;
				if (prev_ps) {
					prev_ps->bucket_next = ps->bucket_next;
				} else {
					path_states[i] = ps->bucket_next;
				}
				ps = ps->bucket_next;
				free_path_state(to_free_ps);
			} else {
				prev_ps = ps;
				ps = ps->bucket_next;
			}
		}
	}

	/* Unlock mutex */
	pthread_mutex_unlock(&states_mutex);
}
