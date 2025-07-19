#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>

#include "queue.h"
#include "monitor.h"
#include "config.h"
#include "logger.h"

/* Add a watch to a queue entry */
bool queue_watch_add(deferred_check_t *entry, watch_entry_t *watch) {
	if (!entry || !watch) {
		log_message(ERROR, "Invalid parameters for queue_watch_add");
		return false;
	}

	/* Check if this watch is already in the array */
	for (int i = 0; i < entry->watch_count; i++) {
		if (entry->watches && entry->watches[i] == watch) {
			return true; /* Already present */
		}
	}

	/* Ensure capacity */
	if (entry->watch_count >= entry->watch_capacity) {
		int new_capacity = entry->watch_capacity == 0 ? 4 : entry->watch_capacity * 2;
		watch_entry_t **new_watches = realloc(entry->watches, new_capacity * sizeof(watch_entry_t *));
		if (!new_watches) {
			log_message(ERROR, "Failed to resize watches array in queue entry");
			return false;
		}
		entry->watches = new_watches;
		entry->watch_capacity = new_capacity;

		/* Zero out new memory */
		if (entry->watch_count < new_capacity) {
			memset(&entry->watches[entry->watch_count], 0, (new_capacity - entry->watch_count) * sizeof(watch_entry_t *));
		}
	}

	/* Add the new watch */
	entry->watches[entry->watch_count++] = watch;
	return true;
}

/* Cleanup the priority queue */
void queue_destroy(defer_queue_t *queue) {
	if (!queue) return;

	/* Free path strings and watch arrays */
	for (int i = 0; i < queue->size; i++) {
		if (queue->items[i].path) {
			free(queue->items[i].path);
			queue->items[i].path = NULL;
		}
		if (queue->items[i].watches) {
			free(queue->items[i].watches);
			queue->items[i].watches = NULL;
		}

		/* Clear the struct to prevent double-free issues */
		memset(&queue->items[i], 0, sizeof(deferred_check_t));
	}

	free(queue->items);
	free(queue);

	log_message(DEBUG, "Cleaned up deferred check queue");
}

/* Initialize the priority queue */
defer_queue_t *queue_create(int initial_capacity) {
	if (initial_capacity < 8) initial_capacity = 8;

	defer_queue_t *queue = calloc(1, sizeof(defer_queue_t));
	if (!queue) {
		log_message(ERROR, "Failed to allocate memory for queue structure");
		return NULL;
	}

	/* Allocate memory for the queue items and zero it out */
	queue->items = calloc(initial_capacity, sizeof(deferred_check_t));
	if (!queue->items) {
		log_message(ERROR, "Failed to allocate memory for deferred check queue");
		free(queue);
		return NULL;
	}

	queue->size = 0;
	queue->capacity = initial_capacity;
	log_message(DEBUG, "Initialized deferred check queue with capacity %d", initial_capacity);
	return queue;
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
void heap_up(deferred_check_t *queue, int index) {
	if (!queue || index <= 0) return;

	int parent = (index - 1) / 2;

	/* Ensure both queue entries have valid paths to avoid crash */
	if (!queue[index].path || !queue[parent].path) {
		log_message(WARNING, "Heapify up encountered invalid path at index %d or parent %d", index, parent);
		return;
	}

	if (time_compare(&queue[index].next_check, &queue[parent].next_check) < 0) {
		/* Swap with parent using a temporary copy */
		deferred_check_t temp;
		memcpy(&temp, &queue[index], sizeof(deferred_check_t));
		memcpy(&queue[index], &queue[parent], sizeof(deferred_check_t));
		memcpy(&queue[parent], &temp, sizeof(deferred_check_t));

		/* Recursively heapify up */
		heap_up(queue, parent);
	}
}

/* Restore heap property downward */
void heap_down(deferred_check_t *queue, int size, int index) {
	if (!queue || index < 0 || size <= 0 || index >= size) {
		return;
	}

	int smallest = index;
	int left = 2 * index + 1;
	int right = 2 * index + 2;

	/* First validate that the current entry has a valid path */
	if (!queue[index].path) {
		log_message(WARNING, "Heapify down encountered NULL path at index %d", index);
		return;
	}

	/* Check left child with validation */
	if (left < size) {
		if (!queue[left].path) {
			log_message(WARNING, "Left child at index %d has NULL path", left);
		} else if (time_compare(&queue[left].next_check, &queue[smallest].next_check) < 0) {
			smallest = left;
		}
	}

	/* Check right child with validation */
	if (right < size) {
		if (!queue[right].path) {
			log_message(WARNING, "Right child at index %d has NULL path", right);
		} else if (time_compare(&queue[right].next_check, &queue[smallest].next_check) < 0) {
			smallest = right;
		}
	}

	if (smallest != index) {
		/* Swap with smallest child using a temporary copy to properly preserve pointers */
		deferred_check_t temp;
		memcpy(&temp, &queue[index], sizeof(deferred_check_t));
		memcpy(&queue[index], &queue[smallest], sizeof(deferred_check_t));
		memcpy(&queue[smallest], &temp, sizeof(deferred_check_t));

		/* Recursively heapify down */
		heap_down(queue, size, smallest);
	}
}

/* Find a queue entry by path */
int queue_find(defer_queue_t *queue, const char *path) {
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
void queue_upsert(defer_queue_t *queue, const char *path,
                  watch_entry_t *watch, struct timespec next_check) {
	if (!queue || !queue->items || !path || !watch) {
		log_message(WARNING, "Invalid parameters for queue_upsert");
		return;
	}

	/* Check if entry already exists for this path (regardless of watch) */
	int index = queue_find(queue, path);

	if (index >= 0) {
		/* Entry exists - update it */
		deferred_check_t *entry = &queue->items[index];

		/* Add this watch if not already present */
		if (!queue_watch_add(entry, watch)) {
			log_message(WARNING, "Failed to add watch to existing queue entry for %s", path);
		}

		/* Update check time - always update to the new time */
		entry->next_check = next_check;

		/* Restore heap property by trying both up and down heapify */
		heap_up(queue->items, index);
		heap_down(queue->items, queue->size, index);

		log_message(DEBUG, "Updated check time for %s (new time: %ld.%09ld)",
		        			path, (long) next_check.tv_sec, next_check.tv_nsec);
		return;
	}

	/* Entry not found, add new one */

	/* Ensure capacity */
	if (queue->size >= queue->capacity) {
		int old_capacity = queue->capacity;
		int new_capacity = old_capacity == 0 ? 8 : old_capacity * 2;
		deferred_check_t *new_items = realloc(queue->items, new_capacity * sizeof(deferred_check_t));
		if (!new_items) {
			log_message(ERROR, "Failed to resize deferred check queue");
			return;
		}
		queue->items = new_items;
		queue->capacity = new_capacity;

		/* Zero out new memory */
		if (new_capacity > old_capacity) {
			memset(&queue->items[old_capacity], 0, (new_capacity - old_capacity) * sizeof(deferred_check_t));
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
	memset(&queue->items[new_index], 0, sizeof(deferred_check_t));

	queue->items[new_index].path = path_copy;
	queue->items[new_index].next_check = next_check;
	queue->items[new_index].watches = NULL;
	queue->items[new_index].watch_count = 0;
	queue->items[new_index].watch_capacity = 0;
	queue->items[new_index].in_verification = false;
	queue->items[new_index].scheduled_period = 0;

	/* Add the watch */
	if (!queue_watch_add(&queue->items[new_index], watch)) {
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
void queue_remove(defer_queue_t *queue, const char *path) {
	if (!queue || !queue->items || queue->size <= 0) return;

	int index;

	/* Special case for empty path - handle corrupted queue entry removal */
	if (!path || path[0] == '\0') {
		/* Find first entry with NULL path */
		for (index = 0; index < queue->size; index++) {
			if (!queue->items[index].path) {
				log_message(WARNING, "Removing corrupted queue entry at index %d", index);
				break;
			}
		}
		if (index >= queue->size) {
			/* No corrupted entries found */
			return;
		}
	} else {
		/* Normal case - find by path */
		index = queue_find(queue, path);
		if (index < 0) return; /* Not found */
	}

	/* Store a copy of the path for logging if available */
	char path_copy[PATH_MAX] = "<corrupted>";
	if (queue->items[index].path) {
		strncpy(path_copy, queue->items[index].path, PATH_MAX - 1);
		path_copy[PATH_MAX - 1] = '\0';
	}

	/* Free resources */
	if (queue->items[index].path) {
		free(queue->items[index].path);
		queue->items[index].path = NULL;
	}

	if (queue->items[index].watches) {
		free(queue->items[index].watches);
		queue->items[index].watches = NULL;
	}

	/* Replace with the last element and restore heap property */
	queue->size--;
	if (index < queue->size) {
		/* Move the last element to the removed position */
		memcpy(&queue->items[index], &queue->items[queue->size], sizeof(deferred_check_t));

		/* Clear the last element which was just moved */
		memset(&queue->items[queue->size], 0, sizeof(deferred_check_t));

		/* Restore heap property for the moved element */
		heap_down(queue->items, queue->size, index);
	} else {
		/* Removed the last element, just clear it */
		memset(&queue->items[index], 0, sizeof(deferred_check_t));
	}

	log_message(DEBUG, "Removed deferred check for %s", path_copy);
}
