#ifndef STATES_H
#define STATES_H

#include <stdint.h>
#include <time.h>

#include "config.h"
#include "scanner.h"
#include "registry.h"

/* Forward declarations */
typedef struct stability stability_t;

/* States configuration */
#define PATH_HASH_SIZE 1024
#define ENTITY_STATE_MAGIC 0x4B514558      /* "KQEX" */

/* State for a given path, holding a list of all watches on that path */
typedef struct node {
	char *path;                            /* The path being watched */
	entity_t *entities;                    /* Head of the list of states for this path */
	bool executing;                        /* Flag indicating command is currently executing on this path */
	struct node *next;                     /* Next node in the hash bucket */
} node_t;

/* State table structure */
typedef struct states {
	node_t **buckets;                      /* Hash table buckets for path states */
	size_t bucket_count;                   /* Number of buckets in the hash table */
	pthread_mutex_t *mutexes;              /* Array of mutexes, one per bucket */
	registry_t *registry;                  /* Registry reference for lookups */
	observer_t observer;                   /* Observer registration for cleanup */
} states_t;

/* Entity state tracking structure */
typedef struct entity {
	/* Core identity */
	uint32_t magic;                        /* Magic number for corruption detection */
	struct node *node;                     /* Back-pointer to the parent path state */
	kind_t kind;                           /* File or directory */
	watchref_t watchref;                   /* Watch reference for this state */

	/* Basic state flags */
	bool exists;                           /* Entity currently exists */
	bool content_changed;                  /* Content has changed */
	bool metadata_changed;                 /* Metadata has changed */
	bool structure_changed;                /* Structural change occurred */

	/* Command & Trigger tracking */
	time_t command_time;                   /* When a command was last triggered */
	char *trigger;                         /* Path of the specific file that triggered a directory event */

	/* Composed state */
	scanner_t *scanner;                    /* NULL if not tracking activity */
	stability_t *stability;                /* NULL if not checking stability */
	
	/* Timestamps */
	struct timespec last_time;             /* When state was last updated (MONOTONIC) */
	struct timespec wall_time;             /* Wall clock time (REALTIME) */
	struct timespec op_time;               /* Timestamp of the last operation to prevent duplicates */
	
	/* Linkage for all states under the same path */
	struct entity *next;                   /* Next state for the same path */
} entity_t;

/* Function prototypes */
states_t *states_create(size_t bucket_count, registry_t *registry);
void states_destroy(states_t *states);
bool state_corrupted(const entity_t *state);
entity_t *states_get(states_t *states, const char *path, kind_t kind, watchref_t watchref, registry_t *registry);

unsigned int states_hash(const char *path, size_t bucket_count);

#endif /* STATES_H */
