#ifndef THREADS_H
#define THREADS_H

#include <stdbool.h>

#include "monitor.h"
#include "registry.h"

/* Thread pool configuration constants */
#define MAX_WORKER_THREADS 3               /* Maximum number of worker threads */
#define MAX_WORK_QUEUE_SIZE 8              /* Maximum number of queued work items */

/* Work task for thread pool */
typedef struct task {
	monitor_t *monitor;                    /* Monitor instance */
	watchref_t watchref;                   /* Watch reference */
	event_t *event;                        /* Event data (copied) */
	struct task *next;                     /* Next task in queue */
} task_t;

/* Thread pool structure */
typedef struct threads {
	/* Worker threads */
	pthread_t threads[MAX_WORKER_THREADS]; /* Worker thread handles */
	int thread_count;                      /* Number of active threads */
	
	/* Work queue */
	int queue_size;                        /* Current queue size */
	int active_tasks;                      /* Number of tasks currently executing */
	task_t *queue_head;                    /* Head of work queue */
	task_t *queue_tail;                    /* Tail of work queue */
	
	/* Synchronization */
	pthread_mutex_t queue_mutex;           /* Queue access mutex */
	pthread_cond_t work_available;         /* Work available condition */
	pthread_cond_t work_done;              /* Work completion condition */
	
	/* Control */
	bool shutdown;                         /* Shutdown flag */
} threads_t;

/* Thread pool function prototypes */
threads_t* threads_create(void);
void threads_destroy(threads_t *threads);
bool threads_submit(threads_t *threads, monitor_t *monitor, watchref_t watchref, const event_t *event);
void threads_wait(threads_t *threads);

#endif /* THREADS_H */
