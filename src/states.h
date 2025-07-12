#ifndef STATES_H
#define STATES_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <sys/types.h>

#include "config.h"
#include "scanner.h"

/* Forward declaration for monitor_t */
struct monitor;
typedef struct monitor monitor_t;

/* Forward declaration for file_event_t */
struct file_event;
typedef struct file_event file_event_t;

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
    bool structure_changed;              /* Structural change occurred */
    bool metadata_changed;               /* Metadata has changed */
    bool content_changed;                /* Content has changed */
    int failed_checks;                   /* Number of consecutive failed stability checks */
    
    /* Command tracking */
    time_t last_command_time;            /* When a command was last triggered */
    
    /* Activity tracking for coalescing events */
    activity_sample_t recent_activity[MAX_ACTIVITY_SAMPLES];
    int activity_sample_count;  
    int activity_index;                  /* Circular buffer index */
    bool activity_in_progress;           /* Flag indicating a burst of activity */
    
    /* Directory statistics for adaptive processing */
    dir_stats_t dir_stats;               /* Current directory statistics */
    dir_stats_t prev_stats;              /* Previous stats for comparison */
    int stability_check_count;           /* Number of stability checks */
    int instability_count;               /* Number of times found unstable in a row */
    
    /* Stable reference state tracking */
    dir_stats_t stable_reference_stats;  /* Last known stable state statistics */
    bool reference_stats_initialized;    /* Whether reference stats are initialized */
    int cumulative_file_change;          /* Running total of file changes since stability */
    int cumulative_dir_change;           /* Running total of directory changes */
    int cumulative_depth_change;         /* Running total of depth changes */
    bool stability_lost;                 /* Flag indicating stability was previously achieved and lost */
    bool checking_scheduled;             /* Flag indicating a deferred check is scheduled */
    
    struct timespec last_activity_in_tree;  /* Latest activity anywhere in the tree */
    char *last_activity_path;            /* Path of the most recent activity */
    char *trigger_file_path;             /* Path of the specific file that triggered a directory event */
    
    /* Linkage for all states under the same path */
    struct entity_state *next_for_path;  /* Next state for the same path */
} entity_state_t;

/* State for a given path, holding a list of all watches on that path */
typedef struct path_state {
    char *path;                          /* The path being watched */
    entity_state_t *head_entity_state;   /* Head of the list of states for this path */
    struct path_state *next_in_bucket;   /* Next path_state in the hash bucket */
} path_state_t;

/* External variables */
extern pthread_mutex_t entity_states_mutex;

/* Function prototypes */
bool entity_state_init(void);
void entity_state_cleanup(void);
bool is_entity_state_corrupted(const entity_state_t *state);
entity_state_t *get_entity_state(const char *path, entity_type_t type, watch_entry_t *watch);
void update_entity_states_after_reload(config_t *new_config);
void cleanup_orphaned_entity_states(config_t *new_config);

#endif /* STATES_H */
