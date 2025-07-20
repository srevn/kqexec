#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "threads.h"
#include "command.h"
#include "logger.h"

/* Global thread pool instance */
static threads_t *g_threads = NULL;

/* Deep copy a watch entry for thread safety */
static watch_t *copy_watch_entry(const watch_t *watch) {
	if (!watch) return NULL;

	watch_t *copy = calloc(1, sizeof(watch_t));
	if (!copy) return NULL;

	copy->name = watch->name ? strdup(watch->name) : NULL;
	copy->path = watch->path ? strdup(watch->path) : NULL;
	copy->command = watch->command ? strdup(watch->command) : NULL;
	copy->target = watch->target;
	copy->filter = watch->filter;
	copy->log_output = watch->log_output;
	copy->buffer_output = watch->buffer_output;
	copy->recursive = watch->recursive;
	copy->hidden = watch->hidden;
	copy->environment = watch->environment;
	copy->complexity = watch->complexity;
	copy->processing_delay = watch->processing_delay;

	return copy;
}

/* Free a copied watch entry */
static void free_watch_entry(watch_t *watch) {
	if (!watch) return;

	free(watch->name);
	free(watch->path);
	free(watch->command);
	free(watch);
}

/* Deep copy a file event for thread safety */
static event_t *copy_file_event(const event_t *event) {
	if (!event) return NULL;

	event_t *copy = calloc(1, sizeof(event_t));
	if (!copy) return NULL;

	copy->path = event->path ? strdup(event->path) : NULL;
	copy->type = event->type;
	copy->time = event->time;
	copy->wall_time = event->wall_time;
	copy->user_id = event->user_id;

	return copy;
}

/* Free a copied file event */
static void free_file_event(event_t *event) {
	if (!event) return;

	free((char *) event->path);
	free(event);
}

/* Worker thread function */
static void *worker_thread(void *arg) {
	threads_t *pool = (threads_t *) arg;

	while (true) {
		task_t *item = NULL;

		/* Get work item from queue */
		pthread_mutex_lock(&pool->queue_mutex);

		while (pool->queue_head == NULL && !pool->shutdown) {
			pthread_cond_wait(&pool->work_available, &pool->queue_mutex);
		}

		if (pool->shutdown) {
			pthread_mutex_unlock(&pool->queue_mutex);
			break;
		}

		/* Dequeue work item */
		item = pool->queue_head;
		pool->queue_head = item->next;
		if (pool->queue_head == NULL) {
			pool->queue_tail = NULL;
		}
		pool->queue_size--;

		pthread_mutex_unlock(&pool->queue_mutex);

		/* Execute the command */
		if (item) {
			command_execute(item->monitor, item->watch, item->event, true);

			/* Clean up work item */
			free_watch_entry(item->watch);
			free_file_event(item->event);
			free(item);
		}

		/* Signal that work is done */
		pthread_cond_signal(&pool->work_done);
	}

	return NULL;
}

/* Initialize thread pool */
bool threads_init(void) {
	if (g_threads != NULL) {
		log_message(WARNING, "Thread pool already initialized");
		return true;
	}

	g_threads = calloc(1, sizeof(threads_t));
	if (!g_threads) {
		log_message(ERROR, "Failed to allocate memory for thread pool");
		return false;
	}

	/* Initialize mutex and condition variables */
	if (pthread_mutex_init(&g_threads->queue_mutex, NULL) != 0) {
		log_message(ERROR, "Failed to initialize queue mutex");
		free(g_threads);
		g_threads = NULL;
		return false;
	}

	if (pthread_cond_init(&g_threads->work_available, NULL) != 0) {
		log_message(ERROR, "Failed to initialize work_available condition");
		pthread_mutex_destroy(&g_threads->queue_mutex);
		free(g_threads);
		g_threads = NULL;
		return false;
	}

	if (pthread_cond_init(&g_threads->work_done, NULL) != 0) {
		log_message(ERROR, "Failed to initialize work_done condition");
		pthread_cond_destroy(&g_threads->work_available);
		pthread_mutex_destroy(&g_threads->queue_mutex);
		free(g_threads);
		g_threads = NULL;
		return false;
	}

	/* Initialize queue */
	g_threads->queue_head = NULL;
	g_threads->queue_tail = NULL;
	g_threads->queue_size = 0;
	g_threads->shutdown = false;

	/* Create worker threads */
	g_threads->thread_count = MAX_WORKER_THREADS;
	for (int i = 0; i < MAX_WORKER_THREADS; i++) {
		if (pthread_create(&g_threads->threads[i], NULL, worker_thread, g_threads) != 0) {
			log_message(ERROR, "Failed to create worker thread %d", i);
			g_threads->thread_count = i;
			threads_destroy();
			return false;
		}
	}

	log_message(DEBUG, "Thread pool initialized with %d worker threads", MAX_WORKER_THREADS);
	return true;
}

/* Destroy thread pool */
void threads_destroy(void) {
	if (!g_threads) return;

	/* Signal shutdown */
	pthread_mutex_lock(&g_threads->queue_mutex);
	g_threads->shutdown = true;
	pthread_cond_broadcast(&g_threads->work_available);
	pthread_mutex_unlock(&g_threads->queue_mutex);

	/* Wait for all threads to finish */
	for (int i = 0; i < g_threads->thread_count; i++) {
		pthread_join(g_threads->threads[i], NULL);
	}

	/* Clean up remaining work items */
	task_t *item = g_threads->queue_head;
	while (item) {
		task_t *next = item->next;
		free_watch_entry(item->watch);
		free_file_event(item->event);
		free(item);
		item = next;
	}

	/* Destroy synchronization objects */
	pthread_cond_destroy(&g_threads->work_done);
	pthread_cond_destroy(&g_threads->work_available);
	pthread_mutex_destroy(&g_threads->queue_mutex);

	free(g_threads);
	g_threads = NULL;

	log_message(DEBUG, "Thread pool destroyed");
}

/* Submit work to thread pool */
bool threads_submit(monitor_t *monitor, const watch_t *watch, const event_t *event) {
	if (!g_threads || !watch || !event) {
		log_message(ERROR, "Invalid parameters for threads_submit");
		return false;
	}

	/* Create work item */
	task_t *item = calloc(1, sizeof(task_t));
	if (!item) {
		log_message(ERROR, "Failed to allocate memory for work item");
		return false;
	}

	item->monitor = monitor;
	item->watch = copy_watch_entry(watch);
	item->event = copy_file_event(event);
	item->next = NULL;

	if (!item->watch || !item->event) {
		log_message(ERROR, "Failed to copy watch/event data for work item");
		free_watch_entry(item->watch);
		free_file_event(item->event);
		free(item);
		return false;
	}

	/* Add to queue */
	pthread_mutex_lock(&g_threads->queue_mutex);

	if (g_threads->queue_size >= MAX_WORK_QUEUE_SIZE) {
		pthread_mutex_unlock(&g_threads->queue_mutex);
		log_message(WARNING, "Work queue is full, dropping command execution for %s", event->path);
		free_watch_entry(item->watch);
		free_file_event(item->event);
		free(item);
		return false;
	}

	/* Add to tail of queue */
	if (g_threads->queue_tail) {
		g_threads->queue_tail->next = item;
	} else {
		g_threads->queue_head = item;
	}
	g_threads->queue_tail = item;
	g_threads->queue_size++;

	/* Signal workers */
	pthread_cond_signal(&g_threads->work_available);
	pthread_mutex_unlock(&g_threads->queue_mutex);

	log_message(DEBUG, "Submitted command execution for %s to thread pool (queue size: %d)",
	    				event->path, g_threads->queue_size);

	return true;
}

/* Wait for all queued work to complete */
void threads_wait_all(void) {
	if (!g_threads) return;

	pthread_mutex_lock(&g_threads->queue_mutex);
	while (g_threads->queue_size > 0) {
		pthread_cond_wait(&g_threads->work_done, &g_threads->queue_mutex);
	}
	pthread_mutex_unlock(&g_threads->queue_mutex);
}
