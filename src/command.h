#ifndef COMMAND_H
#define COMMAND_H

#include <stdbool.h>

#include "config.h"
#include "monitor.h"
#include "threads.h"

/* Command execution configuration */
#define DEFAULT_DEBOUNCE_TIME_MS 500       /* Default debounce time in milliseconds */

/* Command system lifecycle */
bool command_init(threads_t *threads);
void command_cleanup(threads_t *threads);

/* Debounce configuration */
int command_get_debounce_time(void);
void command_debounce_time(int milliseconds);

/* Command execution */
bool command_execute(monitor_t *monitor, const watch_t *watch, const event_t *event, bool async);
char *command_placeholders(monitor_t *monitor, const watch_t *watch, const char *command, const event_t *event);
void command_environment(monitor_t *monitor, const watch_t *watch, const event_t *event);

#endif /* COMMAND_H */
