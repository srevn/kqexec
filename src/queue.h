#ifndef QUEUE_H
#define QUEUE_H

#include <stdbool.h>

#include "registry.h"

/* Deferred directory check queue entry */
typedef struct check {
	char *path;                            /* Path to the watched directory (unique key) */
	struct timespec next_check;            /* When this directory needs checking */
	watchref_t *watchrefs;                 /* Array of watch references for this path */
	int num_watches;                       /* Number of watches for this path */
	int watches_capacity;                  /* Allocated capacity for watches array */
	bool verifying;                        /* True if in verification phase (skip quiet period checks) */
	long scheduled_quiet;                  /* Quiet period used when scheduling this check */
} check_t;

/* Deferred check queue structure */
typedef struct queue {
	check_t *items;                        /* Min-heap of deferred checks */
	int size;                              /* Current number of entries */
	int items_capacity;                    /* Allocated capacity */
	registry_t *registry;                  /* Registry reference for lookups */
	observer_t observer;                   /* Observer registration for cleanup */
} queue_t;

/* Queue lifecycle management */
queue_t *queue_create(registry_t *registry, int initial_capacity);
void queue_destroy(queue_t *queue);

/* Queue operations */
int queue_find(queue_t *queue, const char *path);
void queue_upsert(queue_t *queue, const char *path, watchref_t watchref, struct timespec next_check);
void queue_remove(queue_t *queue, const char *path);
void queue_remove_by_index(queue_t *queue, int index);

/* Check entry management */
bool queue_add(check_t *check, watchref_t watchref);

/* Time comparison and heap operations */
int time_compare(struct timespec *a, struct timespec *b);
void heap_up(check_t *queue, int heap_index);
void heap_down(check_t *queue, int queue_size, int heap_index);

#endif /* QUEUE_H */
