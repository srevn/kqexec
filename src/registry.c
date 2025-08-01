#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "registry.h"
#include "config.h"
#include "logger.h"

/* Initialize the global registry */
registry_t *registry_create(uint32_t initial_capacity) {
	if (initial_capacity == 0) {
		initial_capacity = REGISTRY_INITIAL_CAPACITY;
	}

	registry_t *registry = calloc(1, sizeof(registry_t));
	if (!registry) {
		log_message(ERROR, "Failed to allocate registry structure");
		return NULL;
	}

	/* Allocate storage arrays */
	registry->watches = calloc(initial_capacity, sizeof(watch_t *));
	registry->generations = calloc(initial_capacity, sizeof(uint32_t));
	registry->states = calloc(initial_capacity, sizeof(lifecycle_t));

	if (!registry->watches || !registry->generations || !registry->states) {
		log_message(ERROR, "Failed to allocate registry storage arrays");
		free(registry->watches);
		free(registry->generations);
		free(registry->states);
		free(registry);
		return NULL;
	}

	registry->capacity = initial_capacity;
	registry->count = 0;
	registry->next_id = 1; /* Start from 1, reserve 0 for invalid */
	registry->observers = NULL;

	/* Initialize read-write lock */
	if (pthread_rwlock_init(&registry->lock, NULL) != 0) {
		log_message(ERROR, "Failed to initialize registry lock: %s", strerror(errno));
		free(registry->watches);
		free(registry->generations);
		free(registry->states);
		free(registry);
		return NULL;
	}

	log_message(DEBUG, "Created registry with capacity %u", initial_capacity);
	return registry;
}

/* Destroy the registry and free all resources */
void registry_destroy(registry_t *registry) {
	if (!registry) return;

	/* Acquire write lock to prevent concurrent access during destruction */
	pthread_rwlock_wrlock(&registry->lock);

	/* Free all active watches */
	for (uint32_t i = 0; i < registry->capacity; i++) {
		if (registry->watches[i]) {
			config_destroy_watch(registry->watches[i]);
		}
	}

	/* Free storage arrays */
	free(registry->watches);
	free(registry->generations);
	free(registry->states);

	/* Note: We don't free observer structs as they're owned by callers */

	pthread_rwlock_unlock(&registry->lock);
	pthread_rwlock_destroy(&registry->lock);

	log_message(DEBUG, "Destroyed registry with %u total watches processed", registry->next_id - 1);
	free(registry);
}

/* Expand registry capacity when needed */
static bool registry_expand(registry_t *registry) {
	uint32_t new_capacity = registry->capacity * REGISTRY_GROWTH_FACTOR;

	/* Reallocate storage arrays */
	watch_t **new_watches = realloc(registry->watches, new_capacity * sizeof(watch_t *));
	uint32_t *new_generations = realloc(registry->generations, new_capacity * sizeof(uint32_t));
	lifecycle_t *new_states = realloc(registry->states, new_capacity * sizeof(lifecycle_t));

	if (!new_watches || !new_generations || !new_states) {
		log_message(ERROR, "Failed to expand registry to capacity %u", new_capacity);
		/* Cleanup partial allocations */
		if (new_watches != registry->watches) free(new_watches);
		if (new_generations != registry->generations) free(new_generations);
		if (new_states != registry->states) free(new_states);
		return false;
	}

	/* Update pointers */
	registry->watches = new_watches;
	registry->generations = new_generations;
	registry->states = new_states;

	/* Zero out new entries */
	memset(&registry->watches[registry->capacity], 0,
	       (new_capacity - registry->capacity) * sizeof(watch_t *));
	memset(&registry->generations[registry->capacity], 0,
	       (new_capacity - registry->capacity) * sizeof(uint32_t));
	memset(&registry->states[registry->capacity], 0,
	       (new_capacity - registry->capacity) * sizeof(lifecycle_t));

	log_message(DEBUG, "Expanded registry capacity from %u to %u", registry->capacity, new_capacity);
	registry->capacity = new_capacity;
	return true;
}

/* Add a watch to the registry */
watchref_t registry_add(registry_t *registry, struct watch *watch) {
	if (!registry || !watch) {
		log_message(ERROR, "Invalid parameters to registry_add");
		return WATCH_REF_INVALID;
	}

	pthread_rwlock_wrlock(&registry->lock);

	/* Check if we need to expand capacity */
	if (registry->next_id >= registry->capacity) {
		if (!registry_expand(registry)) {
			pthread_rwlock_unlock(&registry->lock);
			return WATCH_REF_INVALID;
		}
	}

	/* Allocate new ID and generation */
	uint32_t watch_id = registry->next_id++;
	uint32_t generation = 1; /* Start from 1 for new watches */

	/* Store watch data */
	registry->watches[watch_id] = watch;
	registry->generations[watch_id] = generation;
	registry->states[watch_id] = WATCH_STATE_ACTIVE;
	registry->count++;

	watchref_t watchref = {watch_id, generation};

	pthread_rwlock_unlock(&registry->lock);

	log_message(DEBUG, "Added watch '%s' to registry with ID %u", watch->name, watch_id);
	return watchref;
}

/* Get watch by reference */
struct watch *registry_get(registry_t *registry, watchref_t watchref) {
	if (!registry || !watchref_valid(watchref)) {
		return NULL;
	}

	pthread_rwlock_rdlock(&registry->lock);

	watch_t *watch = NULL;
	if (watchref.watch_id < registry->capacity &&
	    registry->generations[watchref.watch_id] == watchref.generation &&
	    registry->states[watchref.watch_id] == WATCH_STATE_ACTIVE) {
		watch = registry->watches[watchref.watch_id];
	}

	pthread_rwlock_unlock(&registry->lock);
	return watch;
}

/* Check if a watch reference is valid */
bool registry_valid(registry_t *registry, watchref_t watchref) {
	if (!registry || !watchref_valid(watchref)) {
		return false;
	}

	pthread_rwlock_rdlock(&registry->lock);

	bool valid = (watchref.watch_id < registry->capacity &&
	              registry->generations[watchref.watch_id] == watchref.generation &&
	              registry->states[watchref.watch_id] == WATCH_STATE_ACTIVE);

	pthread_rwlock_unlock(&registry->lock);
	return valid;
}

/* Utility function: Compare two watch references */
bool watchref_equal(watchref_t a, watchref_t b) {
	return a.watch_id == b.watch_id && a.generation == b.generation;
}

/* Utility function: Check if watch reference is valid (non-zero) */
bool watchref_valid(watchref_t watchref) {
	return watchref.watch_id != 0 || watchref.generation != 0;
}

/* Register an observer for watch lifecycle events */
bool observer_register(registry_t *registry, observer_t *observer) {
	if (!registry || !observer || !observer->handle_deactivation) {
		log_message(ERROR, "Invalid parameters to observer_register");
		return false;
	}

	pthread_rwlock_wrlock(&registry->lock);

	/* Check if observer is already registered (prevent duplicates) */
	for (observer_t *existing = registry->observers; existing; existing = existing->next) {
		if (existing == observer) {
			pthread_rwlock_unlock(&registry->lock);
			log_message(WARNING, "Observer already registered, ignoring duplicate");
			return true;
		}
	}

	/* Add to front of linked list */
	observer->next = registry->observers;
	registry->observers = observer;

	pthread_rwlock_unlock(&registry->lock);

	log_message(DEBUG, "Registered watch observer");
	return true;
}

/* Unregister an observer */
void observer_unregister(registry_t *registry, observer_t *observer) {
	if (!registry || !observer) return;

	pthread_rwlock_wrlock(&registry->lock);

	/* Remove from linked list */
	observer_t **current = &registry->observers;
	while (*current) {
		if (*current == observer) {
			*current = observer->next;
			observer->next = NULL; /* Clear the next pointer */
			log_message(DEBUG, "Unregistered watch observer");
			break;
		}
		current = &(*current)->next;
	}

	pthread_rwlock_unlock(&registry->lock);
}

/* Notify all observers about watch deactivation */
static void registry_notify(registry_t *registry, watchref_t watchref) {
	/* Create a snapshot of observers to safely iterate during callbacks */
	int observer_count = 0;

	/* Count observers and validate */
	for (observer_t *obs = registry->observers; obs; obs = obs->next) {
		observer_count++;
	}

	if (observer_count == 0) {
		return; /* No observers to notify */
	}

	/* Allocate snapshot array */
	observer_t **snapshot = malloc(observer_count * sizeof(observer_t *));
	if (!snapshot) {
		log_message(ERROR, "Failed to allocate observer snapshot for notifications");
		return;
	}

	/* Copy observer pointers to snapshot */
	int i = 0;
	for (observer_t *obs = registry->observers; obs && i < observer_count; obs = obs->next) {
		snapshot[i++] = obs;
	}

	/* Temporarily release lock for callbacks (prevents deadlock) */
	pthread_rwlock_unlock(&registry->lock);

	/* Notify all observers in snapshot */
	for (int j = 0; j < i; j++) {
		if (snapshot[j] && snapshot[j]->handle_deactivation) {
			snapshot[j]->handle_deactivation(watchref, snapshot[j]->context);
		}
	}

	/* Reacquire lock */
	pthread_rwlock_wrlock(&registry->lock);

	free(snapshot);
}

/* Two-phase deletion: deactivate watch and notify observers */
void registry_deactivate(registry_t *registry, watchref_t watchref) {
	if (!registry || !watchref_valid(watchref)) {
		return;
	}

	pthread_rwlock_wrlock(&registry->lock);

	/* Validate reference */
	if (watchref.watch_id >= registry->capacity ||
	    registry->generations[watchref.watch_id] != watchref.generation ||
	    registry->states[watchref.watch_id] != WATCH_STATE_ACTIVE) {
		pthread_rwlock_unlock(&registry->lock);
		return; /* Invalid or already deactivated */
	}

	watch_t *watch = registry->watches[watchref.watch_id];
	log_message(DEBUG, "Deactivating watch '%s' (ID: %u, Gen: %u)",
	            watch ? watch->name : "unknown", watchref.watch_id, watchref.generation);

	/* Phase 1: Notify all observers (releases and reacquires lock) */
	registry_notify(registry, watchref);

	/* Phase 2: Mark inactive and increment generation */
	registry->states[watchref.watch_id] = WATCH_STATE_INACTIVE;
	registry->generations[watchref.watch_id]++;
	registry->count--;

	pthread_rwlock_unlock(&registry->lock);

	log_message(DEBUG, "Watch deactivated, generation incremented to %u",
	            registry->generations[watchref.watch_id]);
}

/* Garbage collect inactive watches */
void registry_garbage(registry_t *registry) {
	if (!registry) return;

	pthread_rwlock_wrlock(&registry->lock);

	uint32_t freed_count = 0;
	for (uint32_t i = 1; i < registry->next_id && i < registry->capacity; i++) {
		if (registry->states[i] == WATCH_STATE_INACTIVE && registry->watches[i]) {
			watch_t *watch = registry->watches[i];
			log_message(DEBUG, "Garbage collecting watch '%s' (ID: %u)", watch->name, i);

			config_destroy_watch(watch);
			registry->watches[i] = NULL;
			freed_count++;
		}
	}

	pthread_rwlock_unlock(&registry->lock);

	if (freed_count > 0) {
		log_message(DEBUG, "Garbage collected %u inactive watches", freed_count);
	}
}
