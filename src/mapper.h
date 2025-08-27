#ifndef MAPPER_H
#define MAPPER_H

#include <stdbool.h>

/* File descriptor mapper configuration */
#define MAPPER_INITIAL_SIZE 1024           /* Initial size for file descriptor mapping array */
#define MAPPER_GROWTH_FACTOR 2             /* Factor by which to grow array when needed */

/* A node in a linked list for watchers that share a file descriptor */
typedef struct watcher_node {
	struct watcher *watcher;               /* The watcher instance */
	struct watcher_node *next;             /* Next node in the linked list */
} watcher_node_t;

/* An entry in the unified file descriptor map */
typedef struct map_entry {
	enum {
		MAP_TYPE_NONE,                     /* Empty slot */
		MAP_TYPE_TRACKER,                  /* Fine-grained file tracker */
		MAP_TYPE_WATCHER                   /* Coarse-grained directory/path watcher */
	} type;
	
	union {
		struct tracker *tracker;           /* Used for MAP_TYPE_TRACKER */
		watcher_node_t *watchers;          /* Head of linked list for MAP_TYPE_WATCHER */
	} ptr;
} map_entry_t;

/* The main mapper structure that holds the map */
typedef struct mapper {
	map_entry_t *entries;                  /* Array of map entries indexed by fd */
	int size;                              /* Current size of the entries array */
} mapper_t;

/* Mapper lifecycle */
mapper_t* mapper_create(int initial_size);
void mapper_destroy(mapper_t *mapper);

/* Event dispatch lookup */
map_entry_t* mapper_get(mapper_t *mapper, int fd);

/* Directory watcher management */
bool map_watcher(mapper_t *mapper, int fd, struct watcher *watcher);
bool unmap_watcher(mapper_t *mapper, int fd, struct watcher *watcher);

/* File tracker management */
bool map_tracker(mapper_t *mapper, int fd, struct tracker *tracker);
void unmap_tracker(mapper_t *mapper, int fd);

#endif /* MAPPER_H */
