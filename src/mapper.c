#include "mapper.h"

#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "logger.h"
#include "monitor.h"

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

	for (int i = 0; i < mapper->size; i++) {
		if (mapper->entries[i].type == MAP_TYPE_WATCHER) {
			watcher_node_t *node = mapper->entries[i].ptr.watchers;
			while (node) {
				watcher_node_t *next = node->next;
				free(node);
				node = next;
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

/* Add a file watcher to the map */
bool mapper_add_fwatcher(mapper_t *mapper, int fd, struct fwatcher *fw) {
	if (!mapper || fd < 0 || !fw) return false;
	if (!mapper_resize(mapper, fd)) return false;

	if (mapper->entries[fd].type != MAP_TYPE_NONE) {
		log_message(WARNING, "Overwriting existing map entry for fd %d", fd);
	}

	mapper->entries[fd].type = MAP_TYPE_FWATCHER;
	mapper->entries[fd].ptr.fw = fw;
	return true;
}

/* Remove a file watcher from the map */
void mapper_remove_fwatcher(mapper_t *mapper, int fd) {
	if (!mapper || fd < 0 || fd >= mapper->size) return;

	if (mapper->entries[fd].type == MAP_TYPE_FWATCHER) {
		mapper->entries[fd].type = MAP_TYPE_NONE;
		mapper->entries[fd].ptr.fw = NULL;
	} else {
		log_message(WARNING, "Attempted to remove fwatcher from fd %d, but it's not an fwatcher", fd);
	}
}

/* Add a directory watcher to the map */
bool mapper_add_watcher(mapper_t *mapper, int fd, struct watcher *w) {
	if (!mapper || fd < 0 || !w) return false;
	if (!mapper_resize(mapper, fd)) return false;

	map_entry_t *entry = &mapper->entries[fd];

	if (entry->type == MAP_TYPE_FWATCHER) {
		log_message(ERROR, "Cannot add watcher to fd %d, it's already an fwatcher", fd);
		return false;
	}

	watcher_node_t *new_node = calloc(1, sizeof(watcher_node_t));
	if (!new_node) {
		log_message(ERROR, "Failed to allocate memory for watcher_node");
		return false;
	}
	new_node->w = w;

	/* Add to the front of the list */
	new_node->next = entry->ptr.watchers;
	entry->ptr.watchers = new_node;
	entry->type = MAP_TYPE_WATCHER;

	return true;
}

/* Remove a directory watcher from the map */
bool mapper_remove_watcher(mapper_t *mapper, int fd, struct watcher *w) {
	if (!mapper || fd < 0 || fd >= mapper->size || !w) return false;

	map_entry_t *entry = &mapper->entries[fd];
	if (entry->type != MAP_TYPE_WATCHER) {
		return false; /* Not a watcher list or empty */
	}

	watcher_node_t **node_ptr = &entry->ptr.watchers;
	while (*node_ptr) {
		if ((*node_ptr)->w == w) {
			watcher_node_t *to_remove = *node_ptr;
			*node_ptr = to_remove->next; /* Unlink */
			free(to_remove);

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
