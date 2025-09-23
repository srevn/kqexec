#ifndef REGISTRY_H
#define REGISTRY_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#define REGISTRY_INITIAL_CAPACITY 256         /* Initial number of watch slots in registry */
#define REGISTRY_GROWTH_FACTOR 2              /* Multiplier for expanding registry capacity */
#define WATCHREF_INVALID ((watchref_t){0, 0}) /* Invalid watch reference constant */

/* Watch lifecycle states */
typedef enum {
	WATCH_STATE_ACTIVE,                    /* Watch is operational */
	WATCH_STATE_INACTIVE,                  /* Watch marked for deletion */
	WATCH_STATE_INTERNAL                   /* Internal watch, excluded from monitoring */
} lifecycle_t;

/* Watch reference structure */
typedef struct watchref {
	uint32_t watch_id;                     /* Unique identifier for the watch */
	uint32_t generation;                   /* Generation counter for ABA prevention */
} watchref_t;

/* Observer callback for watch lifecycle events */
struct observer;
typedef void (*observer_cb_t)(watchref_t watchref, void *context);

typedef struct observer {
	observer_cb_t handle_deactivation;     /* Callback invoked when watch is deactivated */
	void *context;                         /* User-provided context data */
	struct observer *next;                 /* Next observer in linked list */
} observer_t;

/* Central watch registry */
typedef struct registry {
	/* Storage arrays - all indexed by watch_id */
	struct watch **watches;                /* Array of watch pointers, NULL for empty slots */
	uint32_t *generations;                 /* Generation numbers for ABA problem prevention */
	lifecycle_t *states;                   /* Current lifecycle state of each watch */
	
	/* Registry metadata */
	uint32_t capacity;                     /* Total allocated array size */
	uint32_t count;                        /* Number of currently active watches */
	uint32_t next_id;                      /* Next watch ID to assign (monotonic) */
	
	/* Observer management */
	observer_t *observers;                 /* Head of observer linked list */
	
	/* Thread safety */
	pthread_rwlock_t lock;                 /* Read-write lock for thread-safe access */
} registry_t;

/* Registry lifecycle */
registry_t *registry_create(uint32_t initial_capacity);
void registry_destroy(registry_t *registry);

/* Watch management */
watchref_t registry_add(registry_t *registry, struct watch *watch);
struct watch *registry_get(registry_t *registry, watchref_t watchref);
bool registry_valid(registry_t *registry, watchref_t watchref);
watchref_t *registry_active(registry_t *registry, uint32_t *count);
bool registry_exists(registry_t *registry, const char *path);
watchref_t registry_find(registry_t *registry, const char *watch_name);

/* Observer management */
bool observer_register(registry_t *registry, observer_t *observer);
void observer_unregister(registry_t *registry, observer_t *observer);

/* Two-phase deletion */
void registry_deactivate(registry_t *registry, watchref_t watchref);
void registry_garbage(registry_t *registry);

/* Utility functions */
bool watchref_equal(watchref_t a, watchref_t b);
bool watchref_valid(watchref_t watchref);

#endif /* REGISTRY_H */
