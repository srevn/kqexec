#ifndef SCANNER_H
#define SCANNER_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <sys/types.h>

#include "states.h"
#include "config.h"

/* Forward declaration for monitor_t */
struct monitor;
typedef struct monitor monitor_t;

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
