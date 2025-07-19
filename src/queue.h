#ifndef QUEUE_H
#define QUEUE_H

#include <stdbool.h>
#include <time.h>

#include "config.h"
#include "logger.h"

/* Deferred directory check queue entry */
typedef struct {
	char *path;                            /* Path to the watched directory (unique key) */
	struct timespec next_check;            /* When this directory needs checking */
	watch_entry_t **watches;               /* Array of watches for this path */
	int watch_count;                       /* Number of watches for this path */
	int watch_capacity;                    /* Allocated capacity for watches array */
	bool in_verification;                  /* True if in verification phase (skip quiet period checks) */
	long scheduled_period;                 /* Quiet period used when scheduling this check */
	long initial_period;                   /* Original calculated period (for graduated escalation) */
	struct timespec last_escalation;       /* When we last escalated this check */
	int escalation_count;                  /* Number of times we've escalated */
} deferred_check_t;

/* Deferred check queue structure */
typedef struct {
	deferred_check_t *items;               /* Min-heap of deferred checks */
	int size;                              /* Current number of entries */
	int capacity;                          /* Allocated capacity */
} defer_queue_t;

/* Function prototypes */
bool queue_watch_add(deferred_check_t *entry, watch_entry_t *watch);
defer_queue_t *queue_create(int initial_capacity);
void queue_destroy(defer_queue_t *queue);
int time_compare(struct timespec *a, struct timespec *b);
void heap_up(deferred_check_t *queue, int index);
void heap_down(deferred_check_t *queue, int size, int index);
int queue_find(defer_queue_t *queue, const char *path);
void queue_upsert(defer_queue_t *queue, const char *path, watch_entry_t *watch, struct timespec next_check);
void queue_remove(defer_queue_t *queue, const char *path);

#endif /* QUEUE_H */
