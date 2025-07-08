#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "threads.h"
#include "command.h"
#include "logger.h"

/* Global thread pool instance */
static thread_pool_t *g_thread_pool = NULL;

/* Deep copy a watch entry for thread safety */
static watch_entry_t *copy_watch_entry(const watch_entry_t *watch) {
	if (!watch) return NULL;

	watch_entry_t *copy = calloc(1, sizeof(watch_entry_t));
	if (!copy) return NULL;

	copy->name = watch->name ? strdup(watch->name) : NULL;
	copy->path = watch->path ? strdup(watch->path) : NULL;
	copy->command = watch->command ? strdup(watch->command) : NULL;
	copy->type = watch->type;
	copy->events = watch->events;
	copy->log_output = watch->log_output;
	copy->buffer_output = watch->buffer_output;
	copy->recursive = watch->recursive;
	copy->hidden = watch->hidden;
	copy->complexity = watch->complexity;
	copy->processing_delay = watch->processing_delay;

	return copy;
}

/* Free a copied watch entry */
static void free_watch_entry(watch_entry_t *watch) {
	if (!watch) return;

	free(watch->name);
	free(watch->path);
	free(watch->command);
	free(watch);
}

/* Deep copy a file event for thread safety */
static file_event_t *copy_file_event(const file_event_t *event) {
	if (!event) return NULL;

	file_event_t *copy = calloc(1, sizeof(file_event_t));
	if (!copy) return NULL;

	copy->path = event->path ? strdup(event->path) : NULL;
	copy->type = event->type;
	copy->time = event->time;
	copy->wall_time = event->wall_time;
	copy->user_id = event->user_id;

	return copy;
}

/* Free a copied file event */
static void free_file_event(file_event_t *event) {
	if (!event) return;

	free((char *) event->path);
	free(event);
}

/* Worker thread function */
static void *worker_thread(void *arg) {
	thread_pool_t *pool = (thread_pool_t *) arg;

	while (true) {
		work_item_t *item = NULL;

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
			command_execute_sync(item->watch, item->event);

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
bool thread_pool_init(void) {
	if (g_thread_pool != NULL) {
		thread_safe_log(LOG_LEVEL_WARNING, "Thread pool already initialized");
		return true;
	}

	g_thread_pool = calloc(1, sizeof(thread_pool_t));
	if (!g_thread_pool) {
		thread_safe_log(LOG_LEVEL_ERR, "Failed to allocate memory for thread pool");
		return false;
	}

	/* Initialize mutex and condition variables */
	if (pthread_mutex_init(&g_thread_pool->queue_mutex, NULL) != 0) {
		thread_safe_log(LOG_LEVEL_ERR, "Failed to initialize queue mutex");
		free(g_thread_pool);
		g_thread_pool = NULL;
		return false;
	}

	if (pthread_cond_init(&g_thread_pool->work_available, NULL) != 0) {
		thread_safe_log(LOG_LEVEL_ERR, "Failed to initialize work_available condition");
		pthread_mutex_destroy(&g_thread_pool->queue_mutex);
		free(g_thread_pool);
		g_thread_pool = NULL;
		return false;
	}

	if (pthread_cond_init(&g_thread_pool->work_done, NULL) != 0) {
		thread_safe_log(LOG_LEVEL_ERR, "Failed to initialize work_done condition");
		pthread_cond_destroy(&g_thread_pool->work_available);
		pthread_mutex_destroy(&g_thread_pool->queue_mutex);
		free(g_thread_pool);
		g_thread_pool = NULL;
		return false;
	}

	/* Initialize queue */
	g_thread_pool->queue_head = NULL;
	g_thread_pool->queue_tail = NULL;
	g_thread_pool->queue_size = 0;
	g_thread_pool->shutdown = false;

	/* Create worker threads */
	g_thread_pool->thread_count = MAX_WORKER_THREADS;
	for (int i = 0; i < MAX_WORKER_THREADS; i++) {
		if (pthread_create(&g_thread_pool->threads[i], NULL, worker_thread, g_thread_pool) != 0) {
			thread_safe_log(LOG_LEVEL_ERR, "Failed to create worker thread %d", i);
			g_thread_pool->thread_count = i;
			thread_pool_destroy();
			return false;
		}
	}

	thread_safe_log(LOG_LEVEL_DEBUG, "Thread pool initialized with %d worker threads", MAX_WORKER_THREADS);
	return true;
}

/* Destroy thread pool */
void thread_pool_destroy(void) {
	if (!g_thread_pool) return;

	/* Signal shutdown */
	pthread_mutex_lock(&g_thread_pool->queue_mutex);
	g_thread_pool->shutdown = true;
	pthread_cond_broadcast(&g_thread_pool->work_available);
	pthread_mutex_unlock(&g_thread_pool->queue_mutex);

	/* Wait for all threads to finish */
	for (int i = 0; i < g_thread_pool->thread_count; i++) {
		pthread_join(g_thread_pool->threads[i], NULL);
	}

	/* Clean up remaining work items */
	work_item_t *item = g_thread_pool->queue_head;
	while (item) {
		work_item_t *next = item->next;
		free_watch_entry(item->watch);
		free_file_event(item->event);
		free(item);
		item = next;
	}

	/* Destroy synchronization objects */
	pthread_cond_destroy(&g_thread_pool->work_done);
	pthread_cond_destroy(&g_thread_pool->work_available);
	pthread_mutex_destroy(&g_thread_pool->queue_mutex);

	free(g_thread_pool);
	g_thread_pool = NULL;

	thread_safe_log(LOG_LEVEL_DEBUG, "Thread pool destroyed");
}

/* Submit work to thread pool */
bool thread_pool_submit(const watch_entry_t *watch, const file_event_t *event) {
	if (!g_thread_pool || !watch || !event) {
		thread_safe_log(LOG_LEVEL_ERR, "Invalid parameters for thread_pool_submit");
		return false;
	}

	/* Create work item */
	work_item_t *item = calloc(1, sizeof(work_item_t));
	if (!item) {
		thread_safe_log(LOG_LEVEL_ERR, "Failed to allocate memory for work item");
		return false;
	}

	item->watch = copy_watch_entry(watch);
	item->event = copy_file_event(event);
	item->next = NULL;

	if (!item->watch || !item->event) {
		thread_safe_log(LOG_LEVEL_ERR, "Failed to copy watch/event data for work item");
		free_watch_entry(item->watch);
		free_file_event(item->event);
		free(item);
		return false;
	}

	/* Add to queue */
	pthread_mutex_lock(&g_thread_pool->queue_mutex);

	if (g_thread_pool->queue_size >= MAX_WORK_QUEUE_SIZE) {
		pthread_mutex_unlock(&g_thread_pool->queue_mutex);
		thread_safe_log(LOG_LEVEL_WARNING, "Work queue is full, dropping command execution for %s", event->path);
		free_watch_entry(item->watch);
		free_file_event(item->event);
		free(item);
		return false;
	}

	/* Add to tail of queue */
	if (g_thread_pool->queue_tail) {
		g_thread_pool->queue_tail->next = item;
	} else {
		g_thread_pool->queue_head = item;
	}
	g_thread_pool->queue_tail = item;
	g_thread_pool->queue_size++;

	/* Signal workers */
	pthread_cond_signal(&g_thread_pool->work_available);
	pthread_mutex_unlock(&g_thread_pool->queue_mutex);

	thread_safe_log(LOG_LEVEL_DEBUG, "Submitted command execution for %s to thread pool (queue size: %d)",
	                event->path, g_thread_pool->queue_size);

	return true;
}

/* Wait for all queued work to complete */
void thread_pool_wait_all(void) {
	if (!g_thread_pool) return;

	pthread_mutex_lock(&g_thread_pool->queue_mutex);
	while (g_thread_pool->queue_size > 0) {
		pthread_cond_wait(&g_thread_pool->work_done, &g_thread_pool->queue_mutex);
	}
	pthread_mutex_unlock(&g_thread_pool->queue_mutex);
}
