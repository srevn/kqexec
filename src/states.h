#ifndef STATES_H
#define STATES_H

#include <stdbool.h>
#include <time.h>
#include <sys/types.h>

#include "config.h"
#include "monitor.h"

/* Activity window size for detecting quiet periods (in milliseconds) */
#define QUIET_PERIOD_MS 1000      /* Default quiet period */
#define DIR_QUIET_PERIOD_MS 2000  /* Longer quiet period for directory operations */
#define MAX_ACTIVITY_SAMPLES 5    /* Number of recent events to track for activity analysis */

/* Entity type for clarity in handling */
typedef enum {
    ENTITY_UNKNOWN,
    ENTITY_FILE,
    ENTITY_DIRECTORY
} entity_type_t;

/* Logical operation types */
typedef enum {
    OP_NONE = 0,
    
    /* File operations */
    OP_FILE_CONTENT_CHANGED,    /* File content was modified */
    OP_FILE_CREATED,            /* File was created */
    OP_FILE_DELETED,            /* File was deleted */
    OP_FILE_RENAMED,            /* File was renamed/moved */
    OP_FILE_METADATA_CHANGED,   /* File attributes changed */
    
    /* Directory operations */
    OP_DIR_CONTENT_CHANGED,     /* Directory content changed */
    OP_DIR_CREATED,             /* Directory was created */
    OP_DIR_DELETED,             /* Directory was deleted */
    OP_DIR_METADATA_CHANGED     /* Directory attributes changed */
} operation_type_t;

/* Activity sample for analyzing bursts of events */
typedef struct {
    struct timespec timestamp;      /* When the event occurred */
    operation_type_t operation;     /* Type of operation */
} activity_sample_t;

/* Entity state tracking */
typedef struct entity_state {
    char *path;                      /* Path to the entity */
    entity_type_t type;              /* File or directory */
    watch_entry_t *watch;            /* The watch entry for this state */
    struct timespec last_update;     /* When state was last updated (MONOTONIC) */
    struct timespec wall_time;       /* Wall clock time (REALTIME) */
    
    /* Current state */
    bool exists;                     /* Entity currently exists */
    bool content_changed;            /* Content has changed */
    bool metadata_changed;           /* Metadata has changed */
    bool structure_changed;          /* Structural change occurred */
    
    /* Command tracking */
    time_t last_command_time;        /* When a command was last triggered */
    
    /* Activity tracking for coalescing events */
    activity_sample_t recent_activity[MAX_ACTIVITY_SAMPLES];
    int activity_sample_count;  
    int activity_index;             /* Circular buffer index */
    bool activity_in_progress;      /* Flag indicating a burst of activity */
    
    /* Hash table linkage */
    struct entity_state *next;       /* Next entity in hash bucket */
} entity_state_t;

/* Function prototypes */
void entity_state_init(void);
void entity_state_cleanup(void);
entity_state_t *get_entity_state(const char *path, entity_type_t type, watch_entry_t *watch);
operation_type_t determine_operation(entity_state_t *state, event_type_t new_event_type);
event_type_t operation_to_event_type(operation_type_t op);
bool should_execute_command(entity_state_t *state, operation_type_t op, int debounce_ms);
bool process_event(watch_entry_t *watch, file_event_t *event, entity_type_t entity_type);
bool is_quiet_period_elapsed(entity_state_t *state, struct timespec *now);
void set_quiet_period(int milliseconds);
int get_quiet_period(void);

#endif /* STATES_H */
