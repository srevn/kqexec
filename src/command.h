#ifndef COMMAND_H
#define COMMAND_H

#include <stdbool.h>
#include <time.h>

#include "config.h"
#include "monitor.h"

/* Debounce time in milliseconds (default: 500ms) */
#define DEFAULT_DEBOUNCE_TIME_MS 500

/* Hash table size for storing recently executed commands */
#define COMMAND_HASH_SIZE 64

/* Maximum number of paths affected by a command */
#define MAX_AFFECTED_PATHS 32

/* Maximum length of an affected path */
#define MAX_AFFECTED_PATH_LEN 1024

/* Key structure for command execution tracking */
typedef struct {
	char *path;              /* Path where the event occurred */
	event_type_t event_type; /* Type of event */
	char *command;           /* Command that was executed */
} command_key_t;

/* Command execution entry for debouncing */
typedef struct command_entry {
	command_key_t key;          /* Command identification key */
	struct timespec last_exec;  /* Time of last execution */
	struct command_entry *next; /* Next entry in hash chain */
} command_entry_t;

/* Command intent tracking structure */
typedef struct {
	pid_t command_pid;               /* Process ID of the executed command */
	time_t start_time;               /* When the command started */
	time_t expected_end_time;        /* Estimated completion time */
	char **affected_paths;           /* Paths that will be affected by this command */
	int affected_path_count;         /* Number of affected paths */
	bool active;                     /* Whether this intent is still active */
} command_intent_t;

/* Function prototypes */
bool command_execute(const watch_entry_t *watch, const file_event_t *event);
char *command_substitute_placeholders(const char *command, const file_event_t *event);

/* Initialize command subsystem */
void command_init(void);

/* Get debounce time */
int command_get_debounce_time(void);

/* Indicates if the last command execution was skipped due to debouncing */
bool command_was_debounced(void);

/* Clean up command subsystem */
void command_cleanup(void);

/* Set debounce time */
void command_debounce_time(int milliseconds);

/* Function prototypes for command intent tracking */
void command_intent_init(void);
void command_intent_cleanup(void);
command_intent_t *command_intent_create(pid_t pid, const char *command, const char *base_path);
bool command_intent_mark_complete(pid_t pid);
bool is_path_affected_by_command(const char *path);

#endif /* COMMAND_H */
