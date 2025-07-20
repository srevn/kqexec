#ifndef STATES_H
#define STATES_H

#include <stdint.h>
#include <time.h>

#include "config.h"
#include "scanner.h"

/* Hash table size for storing path states */
#define PATH_HASH_SIZE 1024

/* Magic number for entity state corruption detection */
#define ENTITY_STATE_MAGIC 0x4B514558      /* "KQEX" */

/* Forward declarations */
typedef struct activity_state activity_state_t;
typedef struct stability_state stability_state_t;

/* State for a given path, holding a list of all watches on that path */
typedef struct path_state {
	char *path;                            /* The path being watched */
	entity_state_t *entity_head;           /* Head of the list of states for this path */
	struct path_state *bucket_next;        /* Next path_state in the hash bucket */
} path_state_t;

/* State table structure - replaces global state */
typedef struct {
	path_state_t **buckets;                /* Hash table buckets for path states */
	size_t bucket_count;                   /* Number of buckets in the hash table */
	pthread_mutex_t mutex;                 /* Mutex for thread-safe access */
} state_table_t;

/* Entity state tracking structure (per watch) */
typedef struct entity_state {
	/* Core Identity */
	uint32_t magic;                        /* Magic number for corruption detection */
	struct path_state *path_state;         /* Back-pointer to the parent path state */
	entity_type_t type;                    /* File or directory */
	watch_entry_t *watch;                  /* The watch entry for this state */

	/* Timestamps */
	struct timespec last_update;           /* When state was last updated (MONOTONIC) */
	struct timespec wall_time;             /* Wall clock time (REALTIME) */
	struct timespec last_op_time;          /* Timestamp of the last operation to prevent duplicates */

	/* Basic state flags */
	bool exists;                           /* Entity currently exists */
	bool content_changed;                  /* Content has changed */
	bool metadata_changed;                 /* Metadata has changed */
	bool structure_changed;                /* Structural change occurred */

	/* Command & Trigger tracking */
	time_t command_time;                   /* When a command was last triggered */
	char *trigger_path;                    /* Path of the specific file that triggered a directory event */

	/* Composed state */
	activity_state_t *activity;            /* NULL if not tracking activity */
	stability_state_t *stability;          /* NULL if not checking stability */

	/* Linkage for all states under the same path */
	struct entity_state *path_next;        /* Next state for the same path */
} entity_state_t;

/* Function prototypes */
state_table_t *state_table_create(size_t bucket_count);
void state_table_destroy(state_table_t *table);
bool states_corrupted(const entity_state_t *state);
entity_state_t *state_table_get(state_table_t *table, const char *path, entity_type_t type, watch_entry_t *watch);

#endif /* STATES_H */
