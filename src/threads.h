#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <stdbool.h>

#include "config.h"
#include "monitor.h"

/* Thread pool configuration constants */
#define MAX_WORKER_THREADS 3         /* Maximum number of worker threads */
#define MAX_WORK_QUEUE_SIZE 8        /* Maximum number of queued work items */

/* Work item for thread pool */
typedef struct work_item {
	watch_entry_t *watch;            /* Watch configuration (copied) */
	file_event_t *event;             /* Event data (copied) */
	struct work_item *next;          /* Next item in queue */
} work_item_t;

/* Thread pool structure */
typedef struct {
	pthread_t threads[MAX_WORKER_THREADS]; /* Worker thread handles */
	work_item_t *queue_head;		 /* Head of work queue */
	work_item_t *queue_tail;		 /* Tail of work queue */
	int queue_size;	                 /* Current queue size */
	int thread_count;                /* Number of active threads */
	bool shutdown;                   /* Shutdown flag */
	pthread_mutex_t queue_mutex;     /* Queue access mutex */
	pthread_cond_t work_available;   /* Work available condition */
	pthread_cond_t work_done;        /* Work completion condition */
} thread_pool_t;

/* Thread pool function prototypes */
bool thread_pool_init(void);
void thread_pool_destroy(void);
bool thread_pool_submit(const watch_entry_t *watch, const file_event_t *event);
void thread_pool_wait_all(void);

#endif /* THREAD_POOL_H */
