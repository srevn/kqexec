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
	localtime_r(&event->time.tv_sec, &tm);
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
		return false;
	}
	
	/* Substitute placeholders in the command */
	command = command_substitute_placeholders(watch->command, event);
	if (command == NULL) {
		return false;
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
