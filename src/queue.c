#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>

#include "queue.h"
#include "monitor.h"
#include "config.h"
#include "logger.h"

/* Initialize the priority queue */
queue_t *queue_create(int initial_capacity) {
	if (initial_capacity < 8) initial_capacity = 8;

	queue_t *queue = calloc(1, sizeof(queue_t));
	if (!queue) {
		log_message(ERROR, "Failed to allocate memory for queue structure");
		return NULL;
	}

	/* Allocate memory for the queue items and zero it out */
	queue->items = calloc(initial_capacity, sizeof(check_t));
	if (!queue->items) {
		log_message(ERROR, "Failed to allocate memory for deferred check queue");
		free(queue);
		return NULL;
	}

	queue->size = 0;
	queue->items_capacity = initial_capacity;
	log_message(DEBUG, "Initialized deferred check queue with capacity %d", initial_capacity);
	return queue;
}

/* Cleanup the priority queue */
void queue_destroy(queue_t *queue) {
	if (!queue) return;

	/* Free path strings and watch arrays */
	for (int i = 0; i < queue->size; i++) {
		if (queue->items[i].path) {
			free(queue->items[i].path);
			queue->items[i].path = NULL;
		}
		if (queue->items[i].watch_names) {
			for (int j = 0; j < queue->items[i].num_watches; j++) {
				free(queue->items[i].watch_names[j]);
			}
			free(queue->items[i].watch_names);
			queue->items[i].watch_names = NULL;
		}

		/* Clear the struct to prevent double-free issues */
		memset(&queue->items[i], 0, sizeof(check_t));
	}

	free(queue->items);
	free(queue);

	log_message(DEBUG, "Cleaned up deferred check queue");
}

/* Add a watch to a queue entry */
bool queue_add(check_t *check, const char *watch_name) {
	if (!check || !watch_name) {
		log_message(ERROR, "Invalid parameters for queue_add");
		return false;
	}

	/* Check if this watch is already in the array */
	for (int i = 0; i < check->num_watches; i++) {
		if (check->watch_names && strcmp(check->watch_names[i], watch_name) == 0) {
			return true; /* Already present */
		}
	}

	/* Ensure capacity */
	if (check->num_watches >= check->watches_capacity) {
		int new_capacity = check->watches_capacity == 0 ? 4 : check->watches_capacity * 2;
		char **new_watches = realloc(check->watch_names, new_capacity * sizeof(char *));
		if (!new_watches) {
			log_message(ERROR, "Failed to resize watches array in queue entry");
			return false;
		}
		check->watch_names = new_watches;
		check->watches_capacity = new_capacity;

		/* Zero out new memory */
		if (check->num_watches < new_capacity) {
			memset(&check->watch_names[check->num_watches], 0, (new_capacity - check->num_watches) * sizeof(char *));
		}
	}

	/* Add the new watch */
	check->watch_names[check->num_watches] = strdup(watch_name);
	if (!check->watch_names[check->num_watches]) {
		log_message(ERROR, "Failed to duplicate watch name for queue entry");
		return false;
	}
	check->num_watches++;
	return true;
}

/* Compare two timespec values for priority queue ordering */
int time_compare(struct timespec *a, struct timespec *b) {
	if (!a || !b) return 0; /* Handle NULL pointers */

	if (a->tv_sec < b->tv_sec) return -1;
	if (a->tv_sec > b->tv_sec) return 1;
	if (a->tv_nsec < b->tv_nsec) return -1;
	if (a->tv_nsec > b->tv_nsec) return 1;
	return 0;
}

/* Restore heap property upward */
void heap_up(check_t *queue, int heap_index) {
	if (!queue || heap_index <= 0) return;

	int parent = (heap_index - 1) / 2;

	/* Ensure both queue entries have valid paths to avoid crash */
	if (!queue[heap_index].path || !queue[parent].path) {
		log_message(WARNING, "Heapify up encountered invalid path at index %d or parent %d", heap_index, parent);
		return;
	}

	if (time_compare(&queue[heap_index].next_check, &queue[parent].next_check) < 0) {
		/* Swap with parent using a temporary copy */
		check_t temp;
		memcpy(&temp, &queue[heap_index], sizeof(check_t));
		memcpy(&queue[heap_index], &queue[parent], sizeof(check_t));
		memcpy(&queue[parent], &temp, sizeof(check_t));

		/* Recursively heapify up */
		heap_up(queue, parent);
	}
}

/* Restore heap property downward */
void heap_down(check_t *queue, int queue_size, int heap_index) {
	if (!queue || heap_index < 0 || queue_size <= 0 || heap_index >= queue_size) {
		return;
	}

	int smallest = heap_index;
	int left = 2 * heap_index + 1;
	int right = 2 * heap_index + 2;

	/* First validate that the current entry has a valid path */
	if (!queue[heap_index].path) {
		log_message(WARNING, "Heapify down encountered NULL path at index %d", heap_index);
		return;
	}

	/* Check left child with validation */
	if (left < queue_size) {
		if (!queue[left].path) {
			log_message(WARNING, "Left child at index %d has NULL path", left);
		} else if (time_compare(&queue[left].next_check, &queue[smallest].next_check) < 0) {
			smallest = left;
		}
	}

	/* Check right child with validation */
	if (right < queue_size) {
		if (!queue[right].path) {
			log_message(WARNING, "Right child at index %d has NULL path", right);
		} else if (time_compare(&queue[right].next_check, &queue[smallest].next_check) < 0) {
			smallest = right;
		}
	}

	if (smallest != heap_index) {
		/* Swap with smallest child using a temporary copy to properly preserve pointers */
		check_t temp;
		memcpy(&temp, &queue[heap_index], sizeof(check_t));
		memcpy(&queue[heap_index], &queue[smallest], sizeof(check_t));
		memcpy(&queue[smallest], &temp, sizeof(check_t));

		/* Recursively heapify down */
		heap_down(queue, queue_size, smallest);
	}
}

/* Find a queue entry by path */
int queue_find(queue_t *queue, const char *path) {
	if (!queue || !queue->items) {
		return -1;
	}

	/* Special case for handling NULL paths */
	if (!path) {
		for (int i = 0; i < queue->size; i++) {
			if (!queue->items[i].path) {
				return i; /* Found a NULL path entry */
			}
		}
		return -1; /* No NULL path entries */
	}

	/* Normal case - search for a matching path */
	for (int i = 0; i < queue->size; i++) {
		/* Skip entries with NULL paths */
		if (!queue->items[i].path) {
			continue;
		}

		if (strcmp(queue->items[i].path, path) == 0) {
			return i;
		}
	}
	return -1; /* Not found */
}

/* Add or update an entry in the queue */
void queue_upsert(queue_t *queue, const char *path,
                  watch_t *watch, struct timespec next_check) {
	if (!queue || !queue->items || !path || !watch) {
		log_message(WARNING, "Invalid parameters for queue_upsert");
		return;
	}

	/* Check if entry already exists for this path (regardless of watch) */
	int queue_index = queue_find(queue, path);

	if (queue_index >= 0) {
		/* Entry exists - update it */
		check_t *check = &queue->items[queue_index];

		/* Add this watch if not already present */
		if (!queue_add(check, watch->name)) {
			log_message(WARNING, "Failed to add watch to existing queue entry for %s", path);
		}

		/* Update check time - always update to the new time */
		check->next_check = next_check;

		/* Restore heap property by trying both up and down heapify */
		heap_up(queue->items, queue_index);
		heap_down(queue->items, queue->size, queue_index);

		log_message(DEBUG, "Updated check time for %s (new time: %ld.%09ld)",
		            path, (long) next_check.tv_sec, next_check.tv_nsec);
		return;
	}

	/* Entry not found, add new one */

	/* Ensure capacity */
	if (queue->size >= queue->items_capacity) {
		int old_capacity = queue->items_capacity;
		int new_capacity = old_capacity == 0 ? 8 : old_capacity * 2;
		check_t *new_items = realloc(queue->items, new_capacity * sizeof(check_t));
		if (!new_items) {
			log_message(ERROR, "Failed to resize deferred check queue");
			return;
		}
		queue->items = new_items;
		queue->items_capacity = new_capacity;

		/* Zero out new memory */
		if (new_capacity > old_capacity) {
			memset(&queue->items[old_capacity], 0, (new_capacity - old_capacity) * sizeof(check_t));
		}
	}

	/* Add new entry */
	int new_index = queue->size;

	/* Initialize the new entry */
	char *path_copy = strdup(path);
	if (!path_copy) {
		log_message(ERROR, "Failed to duplicate path for queue entry");
		return;
	}

	/* Clear the new entry first to avoid garbage data */
	memset(&queue->items[new_index], 0, sizeof(check_t));

	queue->items[new_index].path = path_copy;
	queue->items[new_index].next_check = next_check;
	queue->items[new_index].watch_names = NULL;
	queue->items[new_index].num_watches = 0;
	queue->items[new_index].watches_capacity = 0;
	queue->items[new_index].verifying = false;
	queue->items[new_index].scheduled_quiet = 0;

	/* Add the watch */
	if (!queue_add(&queue->items[new_index], watch->name)) {
		log_message(ERROR, "Failed to add watch to new queue entry");
		free(queue->items[new_index].path);
		queue->items[new_index].path = NULL;
		return;
	}

	queue->size++;

	/* Restore heap property */
	heap_up(queue->items, new_index);

	log_message(DEBUG, "Added new deferred check for %s (next check at %ld.%09ld)",
	            path, (long) next_check.tv_sec, next_check.tv_nsec);
}

/* Remove an entry from the queue */
void queue_remove(queue_t *queue, const char *path) {
	if (!queue || !queue->items || queue->size <= 0) return;

	int queue_index;

	/* Special case for empty path - handle corrupted queue entry removal */
	if (!path || path[0] == '\0') {
		/* Find first entry with NULL path */
		for (queue_index = 0; queue_index < queue->size; queue_index++) {
			if (!queue->items[queue_index].path) {
				log_message(WARNING, "Removing corrupted queue entry at index %d", queue_index);
				break;
			}
		}
		if (queue_index >= queue->size) {
			/* No corrupted entries found */
			return;
		}
	} else {
		/* Normal case - find by path */
		queue_index = queue_find(queue, path);
		if (queue_index < 0) return; /* Not found */
	}

	/* Store a copy of the path for logging if available */
	char path_copy[PATH_MAX] = "<corrupted>";
	if (queue->items[queue_index].path) {
		strncpy(path_copy, queue->items[queue_index].path, PATH_MAX - 1);
		path_copy[PATH_MAX - 1] = '\0';
	}

	/* Free resources */
	if (queue->items[queue_index].path) {
		free(queue->items[queue_index].path);
		queue->items[queue_index].path = NULL;
	}

	if (queue->items[queue_index].watch_names) {
		for (int i = 0; i < queue->items[queue_index].num_watches; i++) {
			free(queue->items[queue_index].watch_names[i]);
		}
		free(queue->items[queue_index].watch_names);
		queue->items[queue_index].watch_names = NULL;
	}

	/* Replace with the last element and restore heap property */
	queue->size--;
	if (queue_index < queue->size) {
		/* Move the last element to the removed position */
		memcpy(&queue->items[queue_index], &queue->items[queue->size], sizeof(check_t));

		/* Clear the last element which was just moved */
		memset(&queue->items[queue->size], 0, sizeof(check_t));

		/* Restore heap property for the moved element */
		heap_down(queue->items, queue->size, queue_index);
	} else {
		/* Removed the last element, just clear it */
		memset(&queue->items[queue_index], 0, sizeof(check_t));
	}

	log_message(DEBUG, "Removed deferred check for %s", path_copy);
}
