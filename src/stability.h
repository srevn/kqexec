#ifndef STABILITY_H
#define STABILITY_H

#include <stdbool.h>
#include "monitor.h"
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

/* Entry validation functions */
bool validate_entry(deferred_check_t *entry);
watch_entry_t *get_primary_watch(deferred_check_t *entry);
entity_state_t *get_root_state_for_entry(deferred_check_t *entry);

/* Quiet period checking */
bool check_quiet_elapsed(entity_state_t *root_state, struct timespec *current_time, long *elapsed_ms_out);
void reschedule_check(monitor_t *monitor, deferred_check_t *entry, entity_state_t *root_state, struct timespec *current_time);

/* Directory stability verification */
bool scan_directory_stability(entity_state_t *root_state, const char *path, dir_stats_t *current_stats_out);
bool check_for_new_directories(monitor_t *monitor, deferred_check_t *entry);
scan_failure_type_t handle_scan_failure(monitor_t *monitor, deferred_check_t *entry, entity_state_t *root_state, struct timespec *current_time);

/* Stability calculation */
int calculate_required_checks(entity_state_t *root_state, const dir_stats_t *current_stats);
bool is_directory_stable(entity_state_t *root_state, const dir_stats_t *current_stats, bool scan_completed);

/* Command execution */
bool execute_deferred_commands(monitor_t *monitor, deferred_check_t *entry, entity_state_t *root_state, struct timespec *current_time, int *count);

/* Utility functions */
void reset_stability_tracking(entity_state_t *root_state);

#endif /* STABILITY_H */
