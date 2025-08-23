#ifndef MAPPER_H
#define MAPPER_H

#include <stdbool.h>

/* Forward declarations to avoid circular header dependencies */
struct watcher;
struct fwatcher;

/* A node in a linked list for watchers that share a file descriptor */
typedef struct watcher_node {
	struct watcher *w;                     /* The watcher instance */
	struct watcher_node *next;             /* Next node in the linked list */
} watcher_node_t;

/* An entry in the unified file descriptor map */
typedef struct map_entry {
	enum {
		MAP_TYPE_NONE,                     /* Empty slot */
		MAP_TYPE_FWATCHER,                 /* Fine-grained file watcher */
		MAP_TYPE_WATCHER                   /* Coarse-grained directory/path watcher */
	} type;

	union {
		struct fwatcher *fw;               /* Used for MAP_TYPE_FWATCHER */
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
bool mapper_add_watcher(mapper_t *mapper, int fd, struct watcher *w);
bool mapper_remove_watcher(mapper_t *mapper, int fd, struct watcher *w);

/* File watcher management */
bool mapper_add_fwatcher(mapper_t *mapper, int fd, struct fwatcher *fw);
void mapper_remove_fwatcher(mapper_t *mapper, int fd);

#endif /* MAPPER_H */
