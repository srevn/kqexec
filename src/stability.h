#ifndef STABILITY_H
#define STABILITY_H

#include <stdbool.h>

#include "states.h"
#include "queue.h"
#include "scanner.h"

/* Scan failure handling */
typedef enum {
    SCAN_FAILURE_DIRECTORY_DELETED,        /* Directory was deleted during scan */
    SCAN_FAILURE_TEMPORARY_ERROR,          /* Scan failed for other reasons (e.g., temp files) */
    SCAN_FAILURE_MAX_ATTEMPTS_REACHED      /* Maximum attempts reached without success */
} failure_type_t;

/* Stability tracking structure */
typedef struct stability_state {
	/* Directory statistics for adaptive processing */
	dir_stats_t dir_stats;                 /* Current directory statistics */
	dir_stats_t prev_stats;                /* Previous stats for comparison */
	dir_stats_t reference_stats;           /* Last known stable state statistics */

	/* Stability verification tracking */
	int required_checks;                   /* Required number of stability checks (locked in) */
	int checks_count;                      /* Number of stability checks */
	int checks_failed;                     /* Number of consecutive failed stability checks */
	int unstable_count;                    /* Number of times found unstable in a row */
	bool stability_lost;                   /* Flag indicating stability was previously achieved and lost */
	bool reference_init;                   /* Whether reference stats are initialized */

	/* Stable reference state tracking */
	int cumulative_file;                   /* Running total of file changes since stability */
	int cumulative_dirs;                   /* Running total of directory changes */
	int cumulative_depth;                  /* Running total of depth changes */
	ssize_t cumulative_size;               /* Running total of size changes since stability */
} stability_state_t;

/* Main stability processing function */
void stability_process(monitor_t *monitor, struct timespec *current_time);
entity_state_t* stability_root(monitor_t *monitor, entity_state_t *state);
watch_entry_t *stability_watch(deferred_check_t *entry);
entity_state_t *stability_entry(monitor_t *monitor, deferred_check_t *entry);

/* Quiet period checking */
void stability_defer(monitor_t *monitor, entity_state_t *state);
void stability_delay(monitor_t *monitor, deferred_check_t *entry, entity_state_t *root_state, struct timespec *current_time, long required_quiet);
bool stability_quiet(monitor_t *monitor, entity_state_t *root_state, struct timespec *current_time, long *elapsed_ms_out, long required_quiet);
bool stability_ready(monitor_t *monitor, entity_state_t *state, operation_type_t op, int debounce_ms);

/* Directory stability verification */
bool stability_scan(entity_state_t *root_state, const char *path, dir_stats_t *stats_out);
bool stability_new(monitor_t *monitor, deferred_check_t *entry);
failure_type_t stability_fail(monitor_t *monitor, deferred_check_t *entry, entity_state_t *root_state, struct timespec *current_time);

/* Stability calculation */
int stability_require(entity_state_t *root_state, const dir_stats_t *current_stats);
bool stability_stable(entity_state_t *root_state, const dir_stats_t *current_stats, bool scan_completed);

/* Command execution */
bool stability_execute(monitor_t *monitor, deferred_check_t *entry, entity_state_t *root_state, struct timespec *current_time, int *count);
void stability_reset(monitor_t *monitor, entity_state_t *root_state);

/* Stability state management */
stability_state_t *stability_state_create(void);
void stability_state_destroy(stability_state_t *stability);

#endif /* STABILITY_H */
