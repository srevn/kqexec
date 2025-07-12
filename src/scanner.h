#ifndef SCANNER_H
#define SCANNER_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <sys/types.h>

#include "events.h"
#include "config.h"

/* Forward declarations */
struct monitor;
typedef struct monitor monitor_t;

/* Forward declarations to avoid circular dependency with states.h */
typedef struct entity_state entity_state_t;
typedef struct path_state path_state_t;

/* Activity window size for detecting quiet periods (in milliseconds) */
#define QUIET_PERIOD_MS 500              /* Default quiet period */
#define DIR_QUIET_PERIOD_MS 1000         /* Longer quiet period for directory operations */

/* Directory statistics for stability verification */
typedef struct {
    int depth;                           /* Directory tree depth */
    int file_count;                      /* Number of files in the directory */
    int dir_count;                       /* Number of subdirectories */
    size_t total_size;                   /* Total size of files in the directory */
    time_t latest_mtime;                 /* Latest modification time */
    bool has_temp_files;                 /* Flag for temporary files */
    
    /* Recursive stats */
    int max_depth;                       /* Maximum depth reached from this dir */
    int recursive_file_count;            /* Total number of files in this dir and all subdirs */
    int recursive_dir_count;             /* Total number of dirs in this dir and all subdirs */
    size_t recursive_total_size;         /* Total size of all files in tree */
} dir_stats_t;

/* Function prototypes - new naming scheme */

/* Directory statistics and scanning */
bool scanner_gather_directory_stats(const char *dir_path, dir_stats_t *stats, int recursion_depth);
bool scanner_verify_directory_stability(entity_state_t *context_state, const char *dir_path, dir_stats_t *stats, int recursion_depth);
bool scanner_compare_directory_stats(dir_stats_t *prev, dir_stats_t *current);
char *scanner_find_recent_file(const char *dir_path);
void scanner_update_cumulative_changes(entity_state_t *state);

/* Activity tracking and timing */
void scanner_record_activity(entity_state_t *state, operation_type_t op);
void scanner_synchronize_activity_states(path_state_t *path_state, entity_state_t *trigger_state);
long scanner_get_quiet_period(entity_state_t *state);
bool scanner_is_quiet_period_elapsed(entity_state_t *state, struct timespec *now);

#endif /* SCANNER_H */
