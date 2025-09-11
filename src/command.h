#ifndef COMMAND_H
#define COMMAND_H

#include <stdbool.h>

#include "monitor.h"
#include "threads.h"

/* Command execution configuration */
#define DEFAULT_COOLDOWN_TIME_MS 500             /* Default cooldown time in milliseconds */

/* Command system lifecycle */
bool command_init(threads_t *threads);
void command_cleanup(threads_t *threads);

/* Cooldown configuration */
int command_get_cooldown_time(void);
void command_cooldown_time(int milliseconds);

/* Command execution */
bool command_execute(monitor_t *monitor, watchref_t watchref, const event_t *event, bool async);

#endif /* COMMAND_H */
