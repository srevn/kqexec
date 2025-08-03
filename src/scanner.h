#ifndef SCANNER_H
#define SCANNER_H

#include <stdbool.h>
#include <sys/types.h>

#include "config.h"
#include "events.h"

/* Forward declarations */
typedef struct entity entity_t;
typedef struct node node_t;

/* Activity window size for detecting quiet periods (in milliseconds) */
#define MAX_SAMPLES 5                      /* Number of recent events to track for activity analysis */
#define QUIET_PERIOD_MS 500                /* Default quiet period */
#define DIR_QUIET_PERIOD_MS 1000           /* Longer quiet period for directory operations */

/* Activity sample for analyzing bursts of events */
typedef struct sample {
	struct timespec timestamp;             /* When the event occurred */
	optype_t operation;                    /* Type of operation */
} sample_t;

/* Scanner state tracking structure */
typedef struct scanner {
	sample_t samples[MAX_SAMPLES];         /* Circular buffer of recent events */
	bool active;                           /* Whether there is ongoing activity */
	int sample_count;                      /* Number of samples in the buffer */
	int sample_index;                      /* Current index in the circular buffer */
	struct timespec latest_time;           /* Timestamp of the last activity in the directory tree */
	char *active_path;                     /* Path of the most recent activity */
} scanner_t;

/* Directory statistics for stability verification */
typedef struct stats {
	/* Direct stats for the current directory */
	bool temp_files;                       /* Flag for temporary files */
	time_t last_mtime;                     /* Latest modification time */
	int local_files;                       /* Number of files in the directory */
	int local_dirs;                        /* Number of subdirectories */
	size_t local_size;                     /* Total size of files in the directory */

	/* Recursive stats for the entire directory tree */
	int depth;                             /* Directory tree depth */
	int max_depth;                         /* Maximum depth reached from this dir */
	int tree_files;                        /* Total number of files in this dir and all subdirs */
	int tree_dirs;                         /* Total number of dirs in this dir and all subdirs */
	size_t tree_size;                      /* Total size of all files in tree */
} stats_t;

/* Scanner state management */
scanner_t *scanner_create(const char *path);
void scanner_destroy(scanner_t *scanner);

/* Directory statistics and scanning */
bool scanner_scan(const char *dir_path, const watch_t *watch, stats_t *stats);
bool scanner_stable(monitor_t *monitor, entity_t *context, const char *dir_path, stats_t *stats);
bool scanner_compare(stats_t *prev_stats, stats_t *current_stats);
char *scanner_newest(const char *dir_path, const watch_t *watch);
char *scanner_modified(const char *base_path, const watch_t *watch, time_t since_time, bool recursive, bool basename);
void scanner_update(entity_t *state);

/* Activity tracking and timing */
void scanner_track(monitor_t *monitor, entity_t *state, optype_t optype);
void scanner_sync(monitor_t *monitor, node_t *node, entity_t *source);
long scanner_delay(monitor_t *monitor, entity_t *state);
bool scanner_ready(monitor_t *monitor, entity_t *state, struct timespec *current_time, long required_quiet);

#endif /* SCANNER_H */
