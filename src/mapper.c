#include "mapper.h"

#include <stdlib.h>
#include <string.h>

#include "logger.h"

#define MAPPER_INITIAL_SIZE 1024
#define MAPPER_GROWTH_FACTOR 2

/* Resize the mapper's internal array if fd is out of bounds */
static bool mapper_resize(mapper_t *mapper, int fd) {
	if (fd < mapper->size) return true;

	int new_size = mapper->size;
	while (new_size <= fd) {
		new_size *= MAPPER_GROWTH_FACTOR;
	}

	map_entry_t *new_entries = realloc(mapper->entries, new_size * sizeof(map_entry_t));
	if (!new_entries) {
		log_message(ERROR, "Failed to resize mapper to %d entries", new_size);
		return false;
	}

	/* Zero out the new memory */
	memset(new_entries + mapper->size, 0, (new_size - mapper->size) * sizeof(map_entry_t));

	mapper->entries = new_entries;
	mapper->size = new_size;

	log_message(DEBUG, "Resized mapper to %d entries", new_size);
	return true;
}

/* Create a new mapper */
mapper_t *mapper_create(int initial_size) {
	if (initial_size <= 0) {
		initial_size = MAPPER_INITIAL_SIZE;
	}

	mapper_t *mapper = calloc(1, sizeof(mapper_t));
	if (!mapper) {
		log_message(ERROR, "Failed to allocate memory for mapper");
		return NULL;
	}

	mapper->entries = calloc(initial_size, sizeof(map_entry_t));
	if (!mapper->entries) {
		log_message(ERROR, "Failed to allocate memory for mapper entries");
		free(mapper);
		return NULL;
	}

	mapper->size = initial_size;
	return mapper;
}

/* Destroy a mapper and all its resources */
void mapper_destroy(mapper_t *mapper) {
	if (!mapper) return;

	for (int fd_index = 0; fd_index < mapper->size; fd_index++) {
		if (mapper->entries[fd_index].type == MAP_TYPE_WATCHER) {
			watcher_node_t *current_node = mapper->entries[fd_index].ptr.watchers;
			while (current_node) {
				watcher_node_t *next_node = current_node->next;
				free(current_node);
				current_node = next_node;
			}
		}
	}

	free(mapper->entries);
	free(mapper);
}

/* Get an entry from the mapper */
map_entry_t *mapper_get(mapper_t *mapper, int fd) {
	if (!mapper || fd < 0) return NULL;

	/* This function is on the critical path, so we don't resize here */
	if (fd >= mapper->size) return NULL;

	return &mapper->entries[fd];
}

/* Add a file tracker to the map */
bool map_tracker(mapper_t *mapper, int fd, struct tracker *tracker) {
	if (!mapper || fd < 0 || !tracker) return false;
	if (!mapper_resize(mapper, fd)) return false;

	if (mapper->entries[fd].type != MAP_TYPE_NONE) {
		log_message(WARNING, "Overwriting existing map entry for fd %d", fd);
	}

	mapper->entries[fd].type = MAP_TYPE_TRACKER;
	mapper->entries[fd].ptr.tracker = tracker;
	return true;
}

/* Remove a file tracker from the map */
void unmap_tracker(mapper_t *mapper, int fd) {
	if (!mapper || fd < 0 || fd >= mapper->size) return;

	if (mapper->entries[fd].type == MAP_TYPE_TRACKER) {
		mapper->entries[fd].type = MAP_TYPE_NONE;
		mapper->entries[fd].ptr.tracker = NULL;
	} else {
		log_message(WARNING, "Attempted to remove tracker from fd %d, but it's not a tracker", fd);
	}
}

/* Add a directory watcher to the map */
bool map_watcher(mapper_t *mapper, int fd, struct watcher *watcher) {
	if (!mapper || fd < 0 || !watcher) return false;
	if (!mapper_resize(mapper, fd)) return false;

	map_entry_t *entry = &mapper->entries[fd];

	if (entry->type == MAP_TYPE_TRACKER) {
		log_message(ERROR, "Cannot add directory watcher to fd %d, it's already a file tracker", fd);
		return false;
	}

	watcher_node_t *watcher_node = calloc(1, sizeof(watcher_node_t));
	if (!watcher_node) {
		log_message(ERROR, "Failed to allocate memory for watcher_node");
		return false;
	}
	watcher_node->watcher = watcher;

	/* Add to the front of the list */
	watcher_node->next = entry->ptr.watchers;
	entry->ptr.watchers = watcher_node;
	entry->type = MAP_TYPE_WATCHER;

	return true;
}

/* Remove a directory watcher from the map */
bool unmap_watcher(mapper_t *mapper, int fd, struct watcher *watcher) {
	if (!mapper || fd < 0 || fd >= mapper->size || !watcher) return false;

	map_entry_t *entry = &mapper->entries[fd];
	if (entry->type != MAP_TYPE_WATCHER) {
		return false; /* Not a watcher list or empty */
	}

	watcher_node_t **node_ptr = &entry->ptr.watchers;
	while (*node_ptr) {
		if ((*node_ptr)->watcher == watcher) {
			watcher_node_t *target_node = *node_ptr;
			*node_ptr = target_node->next; /* Unlink */
			free(target_node);

			/* If the list is now empty, mark the entry as NONE */
			if (entry->ptr.watchers == NULL) {
				entry->type = MAP_TYPE_NONE;
				return true; /* Was the last one */
			}
			return false; /* Not the last one */
		}
		node_ptr = &(*node_ptr)->next;
	}

	return false; /* Watcher not found in list */
}
