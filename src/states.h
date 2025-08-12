#ifndef STATES_H
#define STATES_H

#include <pthread.h>
#include <stdint.h>
#include <time.h>

#include "config.h"
#include "registry.h"
#include "scanner.h"

/* Forward declarations */
typedef struct stability stability_t;
typedef struct group group_t;

/* States configuration */
#define PATH_HASH_SIZE 1024
#define ENTITY_STATE_MAGIC 0x4B514558      /* "KQEX" */

/* Stability group for watches with compatible scan configurations */
typedef struct group {
	uint64_t config_hash;                  /* Hash of the scan configuration (recursive, hidden, excludes) */
	pthread_mutex_t mutex;                 /* Mutex to protect this group's shared state */
	stability_t *stability;                /* Shared stability state for this group */
	scanner_t *scanner;                    /* Shared scanner state for this group */
	entity_t *entities;                    /* Head of list of entities that belong to this group */
	struct group *next;                    /* Next group for the same node */
} group_t;

/* State for a given path, holding a list of all watches on that path */
typedef struct node {
	char *path;                            /* The path being watched */
	bool executing;                        /* Flag indicating command is currently executing on this path */
	
	/* Resource state */
	kind_t kind;                           /* File or directory */
	
	/* Basic state flags */
	bool exists;                           /* Resource currently exists */
	bool content_changed;                  /* Content has changed */
	bool metadata_changed;                 /* Metadata has changed */
	bool structure_changed;                /* Structural change occurred */
	
	/* Timestamps */
	struct timespec last_time;             /* When state was last updated (MONOTONIC) */
	struct timespec wall_time;             /* Wall clock time (REALTIME) */
	struct timespec op_time;               /* Timestamp of the last operation to prevent duplicates */
	
	/* Stability groups */
	group_t *groups;                       /* Head of list of stability groups */
	
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
	watchref_t watchref;                   /* Watch reference for this state */

	/* Command & Trigger tracking */
	time_t command_time;                   /* When a command was last triggered */
	char *trigger;                         /* Path of the specific file that triggered a directory event */
	
	/* Stability group association */
	group_t *group;                        /* The stability group this entity belongs to */

	/* Linkage for all states under the same path */
	struct entity *next;                   /* Next state for the same path */
} entity_t;

/* Function prototypes */
states_t *states_create(size_t bucket_count, registry_t *registry);
void states_destroy(states_t *states);
bool state_corrupted(const entity_t *state);
entity_t *states_get(states_t *states, registry_t *registry, const char *path, watchref_t watchref, kind_t kind);
unsigned int states_hash(const char *path, size_t bucket_count);

/* Stability group management */
uint64_t config_hash(const watch_t *watch);
group_t *group_create(uint64_t hash);
void group_destroy(group_t *group);

#endif /* STATES_H */
