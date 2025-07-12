#ifndef SCANNER_H
#define SCANNER_H

#include <stdbool.h>
#include <sys/types.h>

#include "monitor.h"
#include "events.h"

/* Forward declarations */
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
    time_t last_mtime;                   /* Latest modification time */
    bool has_temps;                      /* Flag for temporary files */
    
    /* Recursive stats */
    int max_depth;                       /* Maximum depth reached from this dir */
    int tree_files;                      /* Total number of files in this dir and all subdirs */
    int tree_dirs;                       /* Total number of dirs in this dir and all subdirs */
    size_t tree_size;                    /* Total size of all files in tree */
} dir_stats_t;

/* Directory statistics and scanning */
bool scanner_scan(const char *dir_path, dir_stats_t *stats);
bool scanner_stable(entity_state_t *context_state, const char *dir_path, dir_stats_t *stats);
bool scanner_compare(dir_stats_t *prev, dir_stats_t *current);
char *scanner_newest(const char *dir_path);
void scanner_update(entity_state_t *state);

/* Activity tracking and timing */
void scanner_track(entity_state_t *state, operation_type_t op);
void scanner_sync(path_state_t *path_state, entity_state_t *trigger_state);
long scanner_delay(entity_state_t *state);
bool scanner_ready(entity_state_t *state, struct timespec *now);

#endif /* SCANNER_H */
