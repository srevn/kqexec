#ifndef COMMAND_H
#define COMMAND_H

#include <stdbool.h>

#include "monitor.h"
#include "threads.h"

/* Command execution configuration */
#define MAX_CMD_LEN 4096			       /* Maximum length of command */
#define DEFAULT_COOLDOWN_TIME_MS 500       /* Default cooldown time in milliseconds */
#define MAX_BUFFER_SIZE (1024 * 1024)      /* Output buffer memory limit (1MB) */
#define INITIAL_BUFFER_SIZE 8192           /* Initial buffer allocation size */

/* Command output buffer structure */
typedef struct output {
	char *data;                            /* Buffer data */
	size_t used;                           /* Bytes currently used */
	size_t capacity;                       /* Total buffer capacity */
	bool failed;                           /* Buffer allocation failed flag */
} output_t;

/* Command system lifecycle */
bool command_init(threads_t *threads);
void command_cleanup(threads_t *threads);

/* Cooldown configuration */
int cooldown_get(void);
void cooldown_set(int milliseconds);

/* Command execution */
bool command_execute(monitor_t *monitor, watchref_t watchref, const event_t *event, bool async);

#endif /* COMMAND_H */
