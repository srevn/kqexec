#ifndef DAEMON_H
#define DAEMON_H

#include <stdbool.h>

#include "config.h"
#include "monitor.h"

/* Function prototypes */
bool daemon_start(config_t *config);
bool daemon_setup_signals(void);
void daemon_set_monitor(monitor_t *monitor);

#endif /* DAEMON_H */
