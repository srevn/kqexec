#ifndef COMMAND_H
#define COMMAND_H

#include <stdbool.h>
#include <time.h>
#include <pthread.h>

#include "config.h"
#include "monitor.h"
#include "threads.h"

/* Command execution configuration */
#define DEFAULT_DEBOUNCE_TIME_MS 500    /* Default debounce time in milliseconds */
#define MAX_AFFECTED_PATHS 32           /* Maximum number of paths affected by a command */
#define MAX_AFFECTED_PATH_LEN 1024      /* Maximum length of an affected path */

/* Command intent tracking structure */
typedef struct {
	pid_t command_pid;                  /* Process ID of the executed command */
	time_t start_time;                  /* When the command started */
	time_t expected_end_time;           /* Estimated completion time */
	char **affected_paths;              /* Paths that will be affected by this command */
	int affected_path_count;            /* Number of affected paths */
	bool active;                        /* Whether this intent is still active */
} command_intent_t;

/* Function prototypes */
bool command_init(void);
int command_get_debounce_time(void);
void command_debounce_time(int milliseconds);
bool command_execute(const watch_entry_t *watch, const file_event_t *event);
bool command_execute_sync(const watch_entry_t *watch, const file_event_t *event);
char *command_substitute_placeholders(const watch_entry_t *watch, const char *command, const file_event_t *event);
void thread_safe_log(int level, const char *format, ...);
void command_cleanup(void);

/* Function prototypes for command intent tracking */
void command_intent_cleanup(void);
void command_intent_cleanup_expired(void);
command_intent_t *command_intent_create(pid_t pid, const char *command, const char *base_path);
bool command_intent_mark_complete(pid_t pid);
bool is_path_affected_by_command(const char *path);

#endif /* COMMAND_H */
