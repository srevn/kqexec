#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pwd.h>
#include <errno.h>
#include <sys/wait.h>

#include "command.h"
#include "log.h"

/* Maximum length of command */
#define MAX_CMD_LEN 4096

/* Hash table for command debouncing */
static command_entry_t *command_hash[COMMAND_HASH_SIZE] = {NULL};

/* Debounce time in milliseconds */
static int debounce_time_ms = DEFAULT_DEBOUNCE_TIME_MS;

/* Track if the last command was debounced */
static bool last_command_debounced = false;

/* Initialize command subsystem */
void command_init(void) {
	/* Initialize hash table */
	memset(command_hash, 0, sizeof(command_hash));
}

/* Clean up command subsystem */
void command_cleanup(void) {
	/* Free all entries in the hash table */
	for (int i = 0; i < COMMAND_HASH_SIZE; i++) {
		command_entry_t *entry = command_hash[i];
		while (entry != NULL) {
			command_entry_t *next = entry->next;
			free(entry->key.path);
			free(entry->key.command);
			free(entry);
			entry = next;
		}
		command_hash[i] = NULL;
	}
}

/* Function to check if the last command was debounced */
bool command_was_debounced(void) {
	bool result = last_command_debounced;
	last_command_debounced = false;  /* Reset after read */
	return result;
}

/* Set debounce time */
void command_debounce_time(int milliseconds) {
	if (milliseconds >= 0) {
		debounce_time_ms = milliseconds;
		log_message(LOG_LEVEL_INFO, "Command debounce time set to %d ms", debounce_time_ms);
	}
}

/* Get debounce time */
int command_get_debounce_time(void) {
	return debounce_time_ms;
}

/* Calculate simple hash for a command key */
static unsigned int hash_command_key(const char *path, event_type_t event_type, const char *command) {
	unsigned int hash = 0;
	const char *str;
	
	/* Hash the path */
	for (str = path; *str; str++) {
		hash = hash * 31 + *str;
	}
	
	/* Incorporate the event type */
	hash = hash * 31 + event_type;
	
	/* Hash the command */
	for (str = command; *str; str++) {
		hash = hash * 31 + *str;
	}
	
	return hash % COMMAND_HASH_SIZE;
}

/* Check if enough time has passed since last command execution */
static bool should_execute_command(const char *path, event_type_t event_type, const char *command) {
	struct timespec now;
	unsigned int hash;
	command_entry_t *entry, *prev = NULL;
	long elapsed_ms;
	
	/* Get current time */
	clock_gettime(CLOCK_MONOTONIC, &now);
	
	/* Calculate hash */
	hash = hash_command_key(path, event_type, command);
	
	/* Look for existing entry */
	entry = command_hash[hash];
	while (entry != NULL) {
		if (strcmp(entry->key.path, path) == 0 && 
			entry->key.event_type == event_type && 
			strcmp(entry->key.command, command) == 0) {
			/* Found an entry, check if enough time has passed */
			elapsed_ms = (now.tv_sec - entry->last_exec.tv_sec) * 1000 + 
						(now.tv_nsec - entry->last_exec.tv_nsec) / 1000000;
			
			if (elapsed_ms < debounce_time_ms) {
				log_message(LOG_LEVEL_DEBUG, "Debouncing command for %s (elapsed: %ld ms, required: %d ms)",
						  path, elapsed_ms, debounce_time_ms);
				last_command_debounced = true;  /* Set the debounce flag */
				return false;
			}
			
			/* Update last execution time */
			entry->last_exec = now;
			last_command_debounced = false;  /* Clear the debounce flag */
			return true;
		}
		
		prev = entry;
		entry = entry->next;
	}
	
	/* No existing entry, create a new one */
	entry = malloc(sizeof(command_entry_t));
	if (entry == NULL) {
		log_message(LOG_LEVEL_ERR, "Failed to allocate memory for command entry");
		last_command_debounced = false;  /* Clear the debounce flag */
		return true; /* Execute anyway */
	}
	
	entry->key.path = strdup(path);
	entry->key.event_type = event_type;
	entry->key.command = strdup(command);
	entry->last_exec = now;
	entry->next = NULL;
	
	/* Add to hash table */
	if (prev == NULL) {
		command_hash[hash] = entry;
	} else {
		prev->next = entry;
	}
	
	last_command_debounced = false;  /* Clear the debounce flag */
	return true;
}

/* Substitutes placeholders in the command string:
 * %p: Path where the event occurred
 * %t: Time of the event
 * %u: User who triggered the event
 * %e: Event type
 */
char *command_substitute_placeholders(const char *command, const file_event_t *event) {
	char *result, *pos;
	char time_str[64];
	char user_str[64];
	char *event_str;
	struct passwd *pwd;
	struct tm tm;
	
	if (command == NULL || event == NULL) {
		return NULL;
	}
	
	/* Allocate memory for the result */
	result = malloc(MAX_CMD_LEN);
	if (result == NULL) {
		log_message(LOG_LEVEL_ERR, "Failed to allocate memory for command");
		return NULL;
	}
	
	/* Initialize the result with the command */
	strncpy(result, command, MAX_CMD_LEN - 1);
	result[MAX_CMD_LEN - 1] = '\0';
	
	/* Substitute %p with the path */
	while ((pos = strstr(result, "%p")) != NULL) {
		char temp[MAX_CMD_LEN];
		
		/* Copy everything before the placeholder */
		*pos = '\0';
		strcpy(temp, result);
		
		/* Append the path and the rest of the command */
		snprintf(temp + strlen(temp), MAX_CMD_LEN - strlen(temp), "%s%s", 
				event->path, pos + 2);
		
		strcpy(result, temp);
	}
	
	/* Substitute %t with the time */
	localtime_r(&event->wall_time.tv_sec, &tm);
	strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm);
	
	while ((pos = strstr(result, "%t")) != NULL) {
		char temp[MAX_CMD_LEN];
		
		/* Copy everything before the placeholder */
		*pos = '\0';
		strcpy(temp, result);
		
		/* Append the time and the rest of the command */
		snprintf(temp + strlen(temp), MAX_CMD_LEN - strlen(temp), "%s%s", 
				time_str, pos + 2);
		
		strcpy(result, temp);
	}
	
	/* Substitute %u with the user */
	pwd = getpwuid(event->user_id);
	if (pwd != NULL) {
		snprintf(user_str, sizeof(user_str), "%s", pwd->pw_name);
	} else {
		snprintf(user_str, sizeof(user_str), "%d", event->user_id);
	}
	
	while ((pos = strstr(result, "%u")) != NULL) {
		char temp[MAX_CMD_LEN];
		
		/* Copy everything before the placeholder */
		*pos = '\0';
		strcpy(temp, result);
		
		/* Append the user and the rest of the command */
		snprintf(temp + strlen(temp), MAX_CMD_LEN - strlen(temp), "%s%s", 
				user_str, pos + 2);
		
		strcpy(result, temp);
	}
	
	/* Substitute %e with the event type */
	event_str = (char *)event_type_to_string(event->type);
	
	while ((pos = strstr(result, "%e")) != NULL) {
		char temp[MAX_CMD_LEN];
		
		/* Copy everything before the placeholder */
		*pos = '\0';
		strcpy(temp, result);
		
		/* Append the event type and the rest of the command */
		snprintf(temp + strlen(temp), MAX_CMD_LEN - strlen(temp), "%s%s", 
				event_str, pos + 2);
		
		strcpy(result, temp);
	}
	
	return result;
}

/* Execute a command */
bool command_execute(const watch_entry_t *watch, const file_event_t *event) {
    pid_t pid;
    char *command;
    
    if (watch == NULL || event == NULL) {
        log_message(LOG_LEVEL_ERR, "Invalid arguments to command_execute");
        last_command_debounced = false;  /* Clear the debounce flag */
        return false;
    }
    
    /* Substitute placeholders in the command */
    command = command_substitute_placeholders(watch->command, event);
    if (command == NULL) {
        last_command_debounced = false;  /* Clear the debounce flag */
        return false;
    }
    
    /* Check if we should execute this command (debouncing) */
    if (!should_execute_command(event->path, event->type, command)) {
        free(command);
        return false;  /* Return false, but last_command_debounced will be set */
    }
    
    log_message(LOG_LEVEL_INFO, "Executing command: %s", command);
	
	/* Fork a child process */
	pid = fork();
	if (pid == -1) {
		log_message(LOG_LEVEL_ERR, "Failed to fork: %s", strerror(errno));
		free(command);
		return false;
	}
	
	/* Child process */
	if (pid == 0) {
		/* Execute the command */
		execl("/bin/sh", "sh", "-c", command, NULL);
		
		/* If we get here, execl failed */
		log_message(LOG_LEVEL_ERR, "Failed to execute command: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	/* Parent process */
	free(command);
	
	return true;
}
