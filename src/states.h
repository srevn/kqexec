#ifndef STATES_H
#define STATES_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <sys/types.h>

#include "config.h"
#include "scanner.h"
#include "events.h"
#include "monitor.h"

/* Hash table size for storing path states */
#define PATH_HASH_SIZE 1024

/* Magic number for entity state corruption detection */
#define ENTITY_STATE_MAGIC 0x4B514558    /* "KQEX" */

/* Forward declaration for path_state */
struct path_state;

/* Entity state tracking structure (per watch) */
typedef struct entity_state {
    uint32_t magic;                      /* Magic number for corruption detection */
    struct path_state *path_state;       /* Back-pointer to the parent path state */
    entity_type_t type;                  /* File or directory */
    watch_entry_t *watch;                /* The watch entry for this state */
    struct timespec last_update;         /* When state was last updated (MONOTONIC) */
    struct timespec wall_time;           /* Wall clock time (REALTIME) */
    
    /* Current state */
    bool exists;                         /* Entity currently exists */
    bool content_changed;                /* Content has changed */
    bool metadata_changed;               /* Metadata has changed */
    bool structure_changed;              /* Structural change occurred */
    
    /* Command tracking */
    time_t command_time;                 /* When a command was last triggered */
    
    /* Activity tracking for coalescing events */
    activity_sample_t recent_activity[MAX_ACTIVITY_SAMPLES];
    bool activity_active;                /* Flag indicating a burst of activity */
    int activity_count;                  /* Number of activity samples */
    int activity_index;                  /* Circular buffer index */
    
    /* Directory statistics for adaptive processing */
    dir_stats_t dir_stats;               /* Current directory statistics */
    dir_stats_t prev_stats;              /* Previous stats for comparison */
    int checks_count;                    /* Number of stability checks */
    int checks_failed;                   /* Number of consecutive failed stability checks */
    int instability_count;               /* Number of times found unstable in a row */
    
    /* Stable reference state tracking */
    dir_stats_t reference_stats;         /* Last known stable state statistics */
    bool reference_init;                 /* Whether reference stats are initialized */
    int cumulative_file;                 /* Running total of file changes since stability */
    int cumulative_dir;                  /* Running total of directory changes */
    int cumulative_depth;                /* Running total of depth changes */
    
    bool check_pending;                  /* Flag indicating a deferred check is scheduled */
    bool stability_lost;                 /* Flag indicating stability was previously achieved and lost */
    
    struct timespec tree_activity;       /* Latest activity anywhere in the tree */
    char *active_path;                   /* Path of the most recent activity */
    char *trigger_path;                  /* Path of the specific file that triggered a directory event */
    
    /* Linkage for all states under the same path */
    struct entity_state *path_next;      /* Next state for the same path */
} entity_state_t;

/* State for a given path, holding a list of all watches on that path */
typedef struct path_state {
    char *path;                          /* The path being watched */
    entity_state_t *entity_head;         /* Head of the list of states for this path */
    struct path_state *bucket_next;      /* Next path_state in the hash bucket */
} path_state_t;

/* External variables */
extern pthread_mutex_t states_mutex;

/* Function prototypes */
bool states_init(void);
void states_cleanup(void);
bool states_corrupted(const entity_state_t *state);
entity_state_t *states_get(const char *path, entity_type_t type, watch_entry_t *watch);
void states_update(config_t *new_config);
void states_prune(config_t *new_config);

#endif /* STATES_H */
