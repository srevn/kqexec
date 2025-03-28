#ifndef COMMAND_H
#define COMMAND_H

#include <stdbool.h>
#include "config.h"
#include "monitor.h"

/* Function prototypes */
bool command_execute(const watch_entry_t *watch, const file_event_t *event);
char *command_substitute_placeholders(const char *command, const file_event_t *event);

#endif /* COMMAND_H */
