#ifndef COMMAND_H
#define COMMAND_H

#include <stdbool.h>

#include "config.h"
#include "monitor.h"
#include "threads.h"

/* Command execution configuration */
#define DEFAULT_DEBOUNCE_TIME_MS 500       /* Default debounce time in milliseconds */
#define MAX_AFFECTED_PATHS 32              /* Maximum number of paths affected by a command */
#define MAX_AFFECTED_PATH_LEN 1024         /* Maximum length of an affected path */

/* Command intent tracking structure */
typedef struct intent {
	pid_t pid;                             /* Process ID of the executed command */
	time_t start;                          /* When the command started */
	time_t expire;                         /* Estimated completion time */
	char **paths;                          /* Paths that will be affected by this command */
	int num_paths;                         /* Number of affected paths */
	bool active;                           /* Whether this intent is still active */
} intent_t;

/* Command system lifecycle */
bool command_init(threads_t *threads);
void command_cleanup(threads_t *threads);

/* Debounce configuration */
int command_get_debounce_time(void);
void command_debounce_time(int milliseconds);

/* Command execution */
bool command_execute(monitor_t *monitor, const watch_t *watch, const event_t *event, bool synchronous);
char *command_placeholders(monitor_t *monitor, const watch_t *watch, const char *command, const event_t *event);
void command_environment(monitor_t *monitor, const watch_t *watch, const event_t *event);

/* Intent tracking management */
intent_t *intent_create(pid_t pid, const char *command, const char *base_path);
bool intent_complete(pid_t pid);
void intent_expire(void);
void intent_cleanup(void);
bool command_affects(const char *path);

#endif /* COMMAND_H */
