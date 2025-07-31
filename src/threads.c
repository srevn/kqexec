#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "threads.h"
#include "command.h"
#include "logger.h"
#include "registry.h"

/* Deep copy a file event for thread safety */
static event_t *threads_copy_event(const event_t *event) {
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
static void threads_free_event(event_t *event) {
	if (!event) return;

	free((char *) event->path);
	free(event);
}

/* Worker thread function */
static void *threads_worker(void *arg) {
	threads_t *threads = (threads_t *) arg;

	while (true) {
		task_t *task = NULL;

		/* Get work task from queue */
		pthread_mutex_lock(&threads->queue_mutex);

		while (threads->queue_head == NULL && !threads->shutdown) {
			pthread_cond_wait(&threads->work_available, &threads->queue_mutex);
		}

		if (threads->shutdown) {
			pthread_mutex_unlock(&threads->queue_mutex);
			break;
		}

		/* Dequeue work task */
		task = threads->queue_head;
		threads->queue_head = task->next;
		if (threads->queue_head == NULL) {
			threads->queue_tail = NULL;
		}
		threads->queue_size--;
		threads->active_tasks++;

		pthread_mutex_unlock(&threads->queue_mutex);

		/* Execute the command */
		if (task) {
			/* Resolve watch reference at execution time */
			watch_t *watch = registry_get(task->monitor->registry, task->watchref);
			if (watch) {
				log_message(DEBUG, "Executing async command for %s (watch: %s)", 
				            task->event->path, watch->name);
				command_execute(task->monitor, task->watchref, task->event, false);
			} else {
				/* Watch was deactivated while task was queued */
				log_message(DEBUG, "Skipping async command for %s - watch was deactivated", 
				            task->event->path);
			}

			/* Clean up work task */
			threads_free_event(task->event);
			free(task);
		}

		/* Signal that work is done */
		pthread_mutex_lock(&threads->queue_mutex);
		threads->active_tasks--;
		pthread_cond_signal(&threads->work_done);
		pthread_mutex_unlock(&threads->queue_mutex);
	}

	return NULL;
}

/* Create thread pool */
threads_t *threads_create(void) {
	threads_t *threads = calloc(1, sizeof(threads_t));
	if (!threads) {
		log_message(ERROR, "Failed to allocate memory for thread pool");
		return NULL;
	}

	/* Initialize mutex and condition variables */
	if (pthread_mutex_init(&threads->queue_mutex, NULL) != 0) {
		log_message(ERROR, "Failed to initialize queue mutex");
		free(threads);
		return NULL;
	}

	if (pthread_cond_init(&threads->work_available, NULL) != 0) {
		log_message(ERROR, "Failed to initialize work_available condition");
		pthread_mutex_destroy(&threads->queue_mutex);
		free(threads);
		return NULL;
	}

	if (pthread_cond_init(&threads->work_done, NULL) != 0) {
		log_message(ERROR, "Failed to initialize work_done condition");
		pthread_cond_destroy(&threads->work_available);
		pthread_mutex_destroy(&threads->queue_mutex);
		free(threads);
		return NULL;
	}

	/* Initialize queue */
	threads->queue_head = NULL;
	threads->queue_tail = NULL;
	threads->queue_size = 0;
	threads->active_tasks = 0;
	threads->shutdown = false;

	/* Create worker threads */
	threads->thread_count = MAX_WORKER_THREADS;
	for (int i = 0; i < MAX_WORKER_THREADS; i++) {
		if (pthread_create(&threads->threads[i], NULL, threads_worker, threads) != 0) {
			log_message(ERROR, "Failed to create worker thread %d", i);
			threads->thread_count = i;
			threads_destroy(threads);
			return NULL;
		}
	}

	log_message(DEBUG, "Thread pool initialized with %d worker threads", MAX_WORKER_THREADS);
	return threads;
}

/* Destroy thread pool */
void threads_destroy(threads_t *threads) {
	if (!threads) return;

	/* Signal shutdown */
	pthread_mutex_lock(&threads->queue_mutex);
	threads->shutdown = true;
	pthread_cond_broadcast(&threads->work_available);
	pthread_mutex_unlock(&threads->queue_mutex);

	/* Wait for all threads to finish */
	for (int i = 0; i < threads->thread_count; i++) {
		pthread_join(threads->threads[i], NULL);
	}

	/* Clean up remaining work items */
	task_t *task = threads->queue_head;
	while (task) {
		task_t *next = task->next;
		threads_free_event(task->event);
		free(task);
		task = next;
	}

	/* Destroy synchronization objects */
	pthread_cond_destroy(&threads->work_done);
	pthread_cond_destroy(&threads->work_available);
	pthread_mutex_destroy(&threads->queue_mutex);

	free(threads);

	log_message(DEBUG, "Thread pool destroyed");
}

/* Submit work to thread pool */
bool threads_submit(threads_t *threads, monitor_t *monitor, watchref_t watchref, const event_t *event) {
	if (!threads || !watchref_valid(watchref) || !event) {
		log_message(ERROR, "Invalid parameters for threads_submit");
		return false;
	}

	/* Validate watch reference before queuing */
	if (!registry_valid(monitor->registry, watchref)) {
		log_message(WARNING, "Skipping async command submission - watch reference is invalid");
		return false;
	}

	/* Create work task */
	task_t *task = calloc(1, sizeof(task_t));
	if (!task) {
		log_message(ERROR, "Failed to allocate memory for work task");
		return false;
	}

	task->monitor = monitor;
	task->watchref = watchref;
	task->event = threads_copy_event(event);
	task->next = NULL;

	if (!task->event) {
		log_message(ERROR, "Failed to copy event data for work task");
		threads_free_event(task->event);
		free(task);
		return false;
	}

	/* Add to queue */
	pthread_mutex_lock(&threads->queue_mutex);

	if (threads->queue_size >= MAX_WORK_QUEUE_SIZE) {
		pthread_mutex_unlock(&threads->queue_mutex);
		log_message(WARNING, "Work queue is full, dropping command execution for %s", event->path);
		threads_free_event(task->event);
		free(task);
		return false;
	}

	/* Add to tail of queue */
	if (threads->queue_tail) {
		threads->queue_tail->next = task;
	} else {
		threads->queue_head = task;
	}
	threads->queue_tail = task;
	threads->queue_size++;

	/* Signal workers */
	pthread_cond_signal(&threads->work_available);
	pthread_mutex_unlock(&threads->queue_mutex);

	log_message(DEBUG, "Submitted command execution for %s to thread pool (queue size: %d)",
	            event->path, threads->queue_size);

	return true;
}

/* Wait for all queued work to complete */
void threads_wait(threads_t *threads) {
	if (!threads) return;

	pthread_mutex_lock(&threads->queue_mutex);
	while (threads->queue_size > 0 || threads->active_tasks > 0) {
		pthread_cond_wait(&threads->work_done, &threads->queue_mutex);
	}
	pthread_mutex_unlock(&threads->queue_mutex);
}
