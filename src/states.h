#ifndef STATES_H
#define STATES_H

#include <stdbool.h>
#include <stddef.h> 
#include <time.h>
#include <sys/types.h>

#include "config.h"

/* Forward declaration for monitor_t */
struct monitor;
typedef struct monitor monitor_t;

/* Forward declaration for file_event_t */
struct file_event;
typedef struct file_event file_event_t;

/* Activity window size for detecting quiet periods (in milliseconds) */
#define QUIET_PERIOD_MS 500            /* Default quiet period */
#define DIR_QUIET_PERIOD_MS 1000       /* Longer quiet period for directory operations */
#define MAX_ACTIVITY_SAMPLES 5         /* Number of recent events to track for activity analysis */

/* Magic number for entity state corruption detection */
#define ENTITY_STATE_MAGIC 0x4B514558  /* "KQEX" */

/* Entity type for clarity in handling */
typedef enum {
    ENTITY_UNKNOWN,                    /* Unknown type, to be determined */
    ENTITY_FILE,                       /* Regular file */
    ENTITY_DIRECTORY,                  /* Directory */
} entity_type_t;

/* Logical operation types */
typedef enum {
    OP_NONE = 0,                       /* No operation */
    
    /* File operations */
    OP_FILE_CONTENT_CHANGED,           /* File content was modified */
    OP_FILE_CREATED,                   /* File was created */
    OP_FILE_DELETED,                   /* File was deleted */
    OP_FILE_RENAMED,                   /* File was renamed/moved */
    OP_FILE_METADATA_CHANGED,          /* File attributes changed */
    
    /* Directory operations */
    OP_DIR_CONTENT_CHANGED,            /* Directory content changed */
    OP_DIR_CREATED,                    /* Directory was created */
    OP_DIR_DELETED,                    /* Directory was deleted */
    OP_DIR_METADATA_CHANGED            /* Directory attributes changed */
} operation_type_t;

/* Activity sample for analyzing bursts of events */
typedef struct {
    struct timespec timestamp;          /* When the event occurred */
    operation_type_t operation;         /* Type of operation */
} activity_sample_t;

/* Directory statistics for stability verification */
typedef struct {
    int depth;                          /* Directory tree depth */
    int file_count;                     /* Number of files in the directory */
    int dir_count;                      /* Number of subdirectories */
    size_t total_size;                  /* Total size of files in the directory */
    time_t latest_mtime;                /* Latest modification time */
    bool has_temp_files;                /* Flag for temporary files */
    
    /* Recursive stats */
    int max_depth;                      /* Maximum depth reached from this dir */
    int recursive_file_count;           /* Total number of files in this dir and all subdirs */
    int recursive_dir_count;            /* Total number of dirs in this dir and all subdirs */
    size_t recursive_total_size;        /* Total size of all files in tree */
} dir_stats_t;

/* Entity state tracking structure */
typedef struct entity_state {
    uint32_t magic;                      /* Magic number for corruption detection */
    char *path;                          /* Path to the entity */
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
    
    /* Hash table linkage */
    struct entity_state *next;            /* Next entity in hash bucket */
} entity_state_t;

/* Function prototypes */
bool entity_state_init(void);
void entity_state_cleanup(void);
entity_state_t *get_entity_state(const char *path, entity_type_t type, watch_entry_t *watch);
operation_type_t determine_operation(entity_state_t *state, event_type_t new_event_type);
event_type_t operation_to_event_type(operation_type_t op);
bool should_execute_command(entity_state_t *state, operation_type_t op, int debounce_ms);
bool process_event(watch_entry_t *watch, file_event_t *event, entity_type_t entity_type);
void synchronize_activity_states(const char *path, entity_state_t *trigger_state);
bool gather_basic_directory_stats(const char *dir_path, dir_stats_t *stats, int recursion_depth);
bool is_quiet_period_elapsed(entity_state_t *state, struct timespec *now);
long get_required_quiet_period(entity_state_t *state);
bool is_activity_burst(entity_state_t *state);
entity_state_t *find_root_state(entity_state_t *state);
bool verify_directory_stability(entity_state_t *context_state, const char *dir_path, dir_stats_t *stats, int recursion_depth);
bool compare_dir_stats(dir_stats_t *prev, dir_stats_t *current);
void update_cumulative_changes(entity_state_t *state);
void init_change_tracking(entity_state_t *state);
void update_entity_states_after_reload(config_t *new_config);
void cleanup_orphaned_entity_states(config_t *new_config);
char *find_most_recent_file_in_dir(const char *dir_path);

#endif /* STATES_H */
