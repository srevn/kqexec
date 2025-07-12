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

/* Main stability processing function - coordinator that replaces process_deferred_dir_scans */
void stability_process_queue(monitor_t *monitor, struct timespec *current_time);

/* Root state management */
entity_state_t* stability_get_root(entity_state_t *state);

/* Command execution logic */
bool stability_can_execute(monitor_t *monitor, entity_state_t *state, 
                             operation_type_t op, int debounce_ms);

/* Deferred checking */
void stability_schedule(monitor_t *monitor, entity_state_t *state);

/* Entry validation functions */
bool stability_validate(deferred_check_t *entry);
watch_entry_t *stability_get_watch(deferred_check_t *entry);
entity_state_t *stability_get_root_for_entry(deferred_check_t *entry);

/* Quiet period checking */
bool stability_is_quiet(entity_state_t *root_state, struct timespec *current_time, long *elapsed_ms_out);
void stability_reschedule(monitor_t *monitor, deferred_check_t *entry, entity_state_t *root_state, struct timespec *current_time);

/* Directory stability verification */
bool stability_scan(entity_state_t *root_state, const char *path, dir_stats_t *current_stats_out);
bool stability_check_new_dirs(monitor_t *monitor, deferred_check_t *entry);
scan_failure_type_t stability_handle_failure(monitor_t *monitor, deferred_check_t *entry, entity_state_t *root_state, struct timespec *current_time);

/* Stability calculation */
int stability_calc_checks(entity_state_t *root_state, const dir_stats_t *current_stats);
bool stability_is_stable(entity_state_t *root_state, const dir_stats_t *current_stats, bool scan_completed);

/* Command execution */
bool stability_execute(monitor_t *monitor, deferred_check_t *entry, entity_state_t *root_state, struct timespec *current_time, int *count);

/* Utility functions */
void stability_reset(entity_state_t *root_state);

#endif /* STABILITY_H */
