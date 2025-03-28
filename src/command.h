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

#endif /* COMMAND_H */
