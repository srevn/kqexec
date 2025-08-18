#ifndef STABILITY_H
#define STABILITY_H

#include <stdbool.h>

#include "queue.h"
#include "scanner.h"
#include "resource.h"

/* Maximum allowed failures before giving up */
#define MAX_CHECKS_FAILED 3

/* Scan failure handling */
typedef enum failure {
    SCAN_FAILURE_DIRECTORY_DELETED,        /* Directory was deleted during scan */
    SCAN_FAILURE_TEMPORARY_ERROR,          /* Scan failed for other reasons (e.g., temp files) */
    SCAN_FAILURE_MAX_ATTEMPTS_REACHED      /* Maximum attempts reached without success */
} failure_t;

/* Stability tracking structure */
typedef struct stability {
	/* Directory statistics for adaptive processing */
	stats_t stats;                         /* Current directory statistics */
	stats_t prev_stats;                    /* Previous stats for comparison */
	stats_t ref_stats;                     /* Last known stable state statistics */

	/* Stable reference state tracking */
	int delta_files;                       /* Running total of file changes since stability */
	int delta_dirs;                        /* Running total of directory changes */
	int delta_depth;                       /* Running total of depth changes */
	ssize_t delta_size;                    /* Running total of size changes since stability */

	/* Stability verification tracking */
	int checks_count;                      /* Number of stability checks */
	int checks_failed;                     /* Number of consecutive failed stability checks */
	int checks_required;                   /* Required number of stability checks (locked in) */
	int unstable_count;                    /* Number of times found unstable in a row */
	bool stability_lost;                   /* Flag indicating stability was previously achieved and lost */
	bool reference_init;                   /* Whether reference stats are initialized */
} stability_t;

/* Stability state management */
stability_t *stability_create(void);
void stability_destroy(stability_t *stability);

/* Main stability processing function */
void stability_process(monitor_t *monitor, struct timespec *current_time);
subscription_t* stability_root(monitor_t *monitor, subscription_t *subscription);
subscription_t *stability_entry(monitor_t *monitor, check_t *check);

/* Quiet period checking */
void stability_queue(monitor_t *monitor, subscription_t *subscription);
void stability_delay(monitor_t *monitor, check_t *check, subscription_t *root, struct timespec *current_time, long required_quiet);
bool stability_quiet(monitor_t *monitor, subscription_t *root, struct timespec *current_time, long required_quiet);
bool stability_ready(monitor_t *monitor, subscription_t *subscription, optype_t optype, int base_debounce_ms);

/* Directory stability verification */
bool stability_scan(monitor_t *monitor, subscription_t *root, const char *path, stats_t *stats_out);
bool stability_new(monitor_t *monitor, check_t *check);
failure_t stability_fail(monitor_t *monitor, check_t *check, subscription_t *root, struct timespec *current_time);

/* Stability calculation */
int stability_require(subscription_t *root, const stats_t *current_stats);
bool stability_stable(subscription_t *root, const stats_t *current_stats, bool scan_completed);

/* Command execution */
bool stability_execute(monitor_t *monitor, check_t *check, subscription_t *root, struct timespec *current_time, int *commands_executed);
void stability_reset(monitor_t *monitor, subscription_t *root);

#endif /* STABILITY_H */
