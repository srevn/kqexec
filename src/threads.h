#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <stdbool.h>
#include <pthread.h>

#include "config.h"
#include "monitor.h"

/* Thread pool configuration */
#define MAX_WORKER_THREADS 4
#define MAX_WORK_QUEUE_SIZE 32

/* Work item for thread pool */
typedef struct work_item {
	watch_entry_t *watch;            /* Watch configuration (copied) */
	file_event_t *event;             /* Event data (copied) */
	struct work_item *next;          /* Next item in queue */
} work_item_t;

/* Thread pool structure */
typedef struct {
	pthread_t threads[MAX_WORKER_THREADS];
	work_item_t *queue_head;
	work_item_t *queue_tail;
	int queue_size;
	int thread_count;
	bool shutdown;
	pthread_mutex_t queue_mutex;
	pthread_cond_t work_available;
	pthread_cond_t work_done;
} thread_pool_t;

/* Thread pool function prototypes */
bool thread_pool_init(void);
void thread_pool_destroy(void);
bool thread_pool_submit(const watch_entry_t *watch, const file_event_t *event);
void thread_pool_wait_all(void);


#endif /* THREAD_POOL_H */
