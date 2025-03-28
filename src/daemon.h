#ifndef DAEMON_H
#define DAEMON_H

#include <stdbool.h>

#include "config.h"

/* Function prototypes */
bool daemon_start(config_t *config);
void daemon_setup_signals(void);

#endif /* DAEMON_H */
