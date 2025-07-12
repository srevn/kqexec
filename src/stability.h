#ifndef STABILITY_H
#define STABILITY_H

#include <stdbool.h>

#include "states.h"
#include "queue.h"

/* Scan failure handling */
typedef enum {
    SCAN_FAILURE_DIRECTORY_DELETED,
    SCAN_FAILURE_TEMPORARY_ERROR,
    SCAN_FAILURE_MAX_ATTEMPTS_REACHED
} scan_failure_type_t;

/* Main stability processing function */
void stability_process(monitor_t *monitor, struct timespec *current_time);
entity_state_t* stability_root(entity_state_t *state);
watch_entry_t *stability_watch(deferred_check_t *entry);
entity_state_t *stability_entry(deferred_check_t *entry);

/* Quiet period checking */
void stability_defer(monitor_t *monitor, entity_state_t *state);
void stability_delay(monitor_t *monitor, deferred_check_t *entry, entity_state_t *root_state, struct timespec *current_time);
bool stability_quiet(entity_state_t *root_state, struct timespec *current_time, long *elapsed_ms_out);
bool stability_ready(monitor_t *monitor, entity_state_t *state, operation_type_t op, int debounce_ms);

/* Directory stability verification */
bool stability_scan(entity_state_t *root_state, const char *path, dir_stats_t *current_stats_out);
bool stability_new(monitor_t *monitor, deferred_check_t *entry);
scan_failure_type_t stability_fail(monitor_t *monitor, deferred_check_t *entry, entity_state_t *root_state, struct timespec *current_time);

/* Stability calculation */
int stability_require(entity_state_t *root_state, const dir_stats_t *current_stats);
bool stability_stable(entity_state_t *root_state, const dir_stats_t *current_stats, bool scan_completed);

/* Command execution */
bool stability_execute(monitor_t *monitor, deferred_check_t *entry, entity_state_t *root_state, struct timespec *current_time, int *count);
void stability_reset(entity_state_t *root_state);

#endif /* STABILITY_H */
