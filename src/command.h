#ifndef COMMAND_H
#define COMMAND_H

#include <stdbool.h>

#include "config.h"
#include "monitor.h"

/* Command execution configuration */
#define DEFAULT_DEBOUNCE_TIME_MS 500       /* Default debounce time in milliseconds */
#define MAX_AFFECTED_PATHS 32              /* Maximum number of paths affected by a command */
#define MAX_AFFECTED_PATH_LEN 1024         /* Maximum length of an affected path */

/* Command intent tracking structure */
typedef struct {
	pid_t command_pid;                     /* Process ID of the executed command */
	time_t start_time;                     /* When the command started */
	time_t expected_end_time;              /* Estimated completion time */
	char **affected_paths;                 /* Paths that will be affected by this command */
	int affected_path_count;               /* Number of affected paths */
	bool active;                           /* Whether this intent is still active */
} command_intent_t;

/* Function prototypes */
bool command_init(void);
int command_get_debounce_time(void);
void command_debounce_time(int milliseconds);
bool command_execute(monitor_t *monitor, const watch_entry_t *watch, const file_event_t *event, bool synchronous);
char *command_placeholders(monitor_t *monitor, const watch_entry_t *watch, const char *command, const file_event_t *event);
void command_environment(monitor_t *monitor, const watch_entry_t *watch, const file_event_t *event);
void command_cleanup(void);

/* Function prototypes for command intent tracking */
void command_intent_cleanup(void);
void command_intent_expire(void);
command_intent_t *command_intent_create(pid_t pid, const char *command, const char *base_path);
bool command_intent_complete(pid_t pid);
bool command_affects(const char *path);

#endif /* COMMAND_H */
