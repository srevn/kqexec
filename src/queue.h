#ifndef QUEUE_H
#define QUEUE_H

#include <stdbool.h>

#include "config.h"
#include "registry.h"

/* Queued directory check entry */
typedef struct check {
	/* Path information */
	char *path;                            /* Path to the watched directory (unique key) */
	
	/* Timing information */
	struct timespec next_check;            /* When this directory needs checking */
	long scheduled_quiet;                  /* Quiet period used when scheduling this check */
	bool verifying;                        /* True if in verification phase (skip quiet period checks) */
	
	/* Watch references */
	watchref_t *watchrefs;                 /* Array of watch references for this path */
	int num_watches;                       /* Number of watches for this path */
	int watches_capacity;                  /* Allocated capacity for watches array */

	/* Event aggregation */
	filter_t aggregated_events;            /* Bitmask of event types that triggered this check */
} check_t;

/* Directory check queue structure */
typedef struct queue {
	/* Queue storage */
	check_t *items;                        /* Min-heap of queued checks */
	int size;                              /* Current number of entries */
	int items_capacity;                    /* Allocated capacity */
	
	/* Dependencies */
	registry_t *registry;                  /* Registry reference for lookups */
	observer_t observer;                   /* Observer registration for cleanup */
} queue_t;

/* Queue lifecycle management */
queue_t *queue_create(registry_t *registry, int initial_capacity);
void queue_destroy(queue_t *queue);

/* Queue operations */
int queue_find(queue_t *queue, const char *path);
void queue_upsert(queue_t *queue, const char *path, watchref_t watchref, struct timespec next_check, filter_t event_type);
void queue_remove(queue_t *queue, const char *path);
void queue_remove_by_index(queue_t *queue, int index);

/* Check entry management */
bool queue_add(check_t *check, watchref_t watchref);

/* Heap operations */
void heap_up(check_t *queue, int heap_index);
void heap_down(check_t *queue, int queue_size, int heap_index);

#endif /* QUEUE_H */
