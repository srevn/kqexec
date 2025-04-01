#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pwd.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>

#include "command.h"
#include "states.h"
#include "log.h"

/* Maximum length of command */
#define MAX_CMD_LEN 4096

/* Global array of active command intents */
#define MAX_COMMAND_INTENTS 10
static command_intent_t command_intents[MAX_COMMAND_INTENTS];
static int active_intent_count = 0;

/* Debounce time in milliseconds */
static int debounce_time_ms = DEFAULT_DEBOUNCE_TIME_MS;

/* SIGCHLD handler to reap child processes and mark command intents as complete */
static void command_sigchld_handler(int sig) {
	(void)sig;
	pid_t pid;
	int status;
	
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		/* Mark the command intent as complete */
		command_intent_mark_complete(pid);
	}
}

/* Initialize command subsystem */
void command_init(void) {
	/* Set up SIGCHLD handler */
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = command_sigchld_handler;
	sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
	sigaction(SIGCHLD, &sa, NULL);
}

/* Initialize command intent tracking */
void command_intent_init(void) {
	memset(command_intents, 0, sizeof(command_intents));
	active_intent_count = 0;
}

/* Clean up command intent tracking */
void command_intent_cleanup(void) {
	for (int i = 0; i < MAX_COMMAND_INTENTS; i++) {
		if (command_intents[i].active && command_intents[i].affected_paths) {
			for (int j = 0; j < command_intents[i].affected_path_count; j++) {
				free(command_intents[i].affected_paths[j]);
			}
			free(command_intents[i].affected_paths);
		}
	}
	memset(command_intents, 0, sizeof(command_intents));
	active_intent_count = 0;
}

/* Check if a path is affected by any active command */
bool is_path_affected_by_command(const char *path) {
	time_t now;
	time(&now);
	
	/* Iterate through all active command intents */
	for (int i = 0; i < MAX_COMMAND_INTENTS; i++) {
		if (!command_intents[i].active) continue;
		
		/* Check if the command has expired */
		if (now > command_intents[i].expected_end_time) {
			log_message(LOG_LEVEL_DEBUG, "Command intent %d expired", i);
			command_intents[i].active = false;
			continue;
		}
		
		/* Check if the path matches any affected path */
		for (int j = 0; j < command_intents[i].affected_path_count; j++) {
			const char *affected_path = command_intents[i].affected_paths[j];
			
			/* Check for exact match */
			if (strcmp(path, affected_path) == 0) {
				log_message(LOG_LEVEL_DEBUG, "Path %s is directly affected by command %d", 
						  path, i);
				return true;
			}
			
			/* Check if path is a subdirectory of affected_path */
			size_t affected_len = strlen(affected_path);
			if (strncmp(path, affected_path, affected_len) == 0 &&
				(path[affected_len] == '/' || path[affected_len] == '\0')) {
				log_message(LOG_LEVEL_DEBUG, "Path %s is within affected path %s (command %d)", 
						  path, affected_path, i);
				return true;
			}
			
			/* Check if affected_path is a subdirectory of path */
			size_t path_len = strlen(path);
			if (strncmp(affected_path, path, path_len) == 0 &&
				(affected_path[path_len] == '/' || affected_path[path_len] == '\0')) {
				log_message(LOG_LEVEL_DEBUG, "Path %s contains affected path %s (command %d)", 
						  path, affected_path, i);
				return true;
			}
		}
	}
	
	return false;
}

/* Analyze a command to determine what paths it will affect */
command_intent_t *command_intent_create(pid_t pid, const char *command, const char *base_path) {
	/* Find a free slot in the command_intents array */
	int slot = -1;
	for (int i = 0; i < MAX_COMMAND_INTENTS; i++) {
		if (!command_intents[i].active) {
			slot = i;
			break;
		}
	}
	
	if (slot == -1) {
		log_message(LOG_LEVEL_WARNING, "No free slots for command intent tracking");
		return NULL;
	}
	
	/* Initialize the command intent */
	command_intent_t *intent = &command_intents[slot];
	memset(intent, 0, sizeof(command_intent_t));
	intent->command_pid = pid;
	time(&intent->start_time);
	
	/* Set a default expected end time (10 seconds) */
	intent->expected_end_time = intent->start_time + 10;
	
	/* Allocate memory for affected paths */
	intent->affected_paths = calloc(MAX_AFFECTED_PATHS, sizeof(char *));
	if (!intent->affected_paths) {
		log_message(LOG_LEVEL_ERR, "Failed to allocate memory for affected paths");
		return NULL;
	}
	
	/* Add the base path as the first affected path */
	intent->affected_paths[0] = strdup(base_path);
	intent->affected_path_count = 1;
	
	/* Simple command analysis - parse the command for common operations */
	/* Check for file moves */
	if (strstr(command, "mv ") || strstr(command, " mv ") || 
		strstr(command, "-exec mv") || strstr(command, " move ")) {
		log_message(LOG_LEVEL_DEBUG, "Command contains file move operation");
		
		/* Find target directories in common move patterns */
		const char *move_targets[] = {
			/* Common move target patterns */
			"mv * ", "mv .* ", "mv %p", "-exec mv {} ", " move ", NULL
		};
		
		for (int i = 0; move_targets[i] != NULL; i++) {
			const char *target = strstr(command, move_targets[i]);
			if (target) {
				/* Skip to the end of the move command */
				target += strlen(move_targets[i]);
				
				/* Find the end of the target path */
				const char *end = strpbrk(target, " \t\n;|&");
				if (end) {
					/* Extract the target path */
					int len = end - target;
					if (len > 0 && len < MAX_AFFECTED_PATH_LEN) {
						char path[MAX_AFFECTED_PATH_LEN];
						strncpy(path, target, len);
						path[len] = '\0';
						
						/* Remove quotes if present */
						if (path[0] == '"' && path[len-1] == '"') {
							memmove(path, path+1, len-2);
							path[len-2] = '\0';
						}
						
						/* Add the target path if it's not already in the list */
						bool already_added = false;
						for (int j = 0; j < intent->affected_path_count; j++) {
							if (strcmp(intent->affected_paths[j], path) == 0) {
								already_added = true;
								break;
							}
						}
						
						if (!already_added && intent->affected_path_count < MAX_AFFECTED_PATHS) {
							intent->affected_paths[intent->affected_path_count] = strdup(path);
							intent->affected_path_count++;
							log_message(LOG_LEVEL_DEBUG, "Added target path %s to affected paths", path);
						}
					}
				}
			}
		}
	}
	
	/* Check for file deletions */
	if (strstr(command, "rm ") || strstr(command, " rm ") || 
		strstr(command, "-delete") || strstr(command, " delete ")) {
		log_message(LOG_LEVEL_DEBUG, "Command contains file delete operation");
		/* Delete operations affect the base path and its parents */
		/* Already added base path, so no additional paths needed */
	}
	
	/* Mark the intent as active */
	intent->active = true;
	active_intent_count++;
	
	log_message(LOG_LEVEL_DEBUG, "Created command intent for PID %d with %d affected paths",
			  pid, intent->affected_path_count);
	
	return intent;
}

/* Mark a command intent as complete */
bool command_intent_mark_complete(pid_t pid) {
	for (int i = 0; i < MAX_COMMAND_INTENTS; i++) {
		if (command_intents[i].active && command_intents[i].command_pid == pid) {
			command_intents[i].active = false;
			active_intent_count--;
			
			log_message(LOG_LEVEL_DEBUG, "Marked command intent for PID %d as complete",
					  pid);
			
			/* Free affected paths */
			for (int j = 0; j < command_intents[i].affected_path_count; j++) {
				free(command_intents[i].affected_paths[j]);
			}
			free(command_intents[i].affected_paths);
			command_intents[i].affected_paths = NULL;
			
			return true;
		}
	}
	
	return false;
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
	int stdout_pipe[2] = {-1, -1}, stderr_pipe[2] = {-1, -1};
	bool capture_output = watch->log_output;
	
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
	log_message(LOG_LEVEL_NOTICE, "[%s]: %s", watch->name, command);
	
	/* Create pipes for stdout and stderr if configured to capture output */
	if (capture_output) {
		if (pipe(stdout_pipe) < 0 || pipe(stderr_pipe) < 0) {
			log_message(LOG_LEVEL_ERR, "Failed to create pipes: %s", strerror(errno));
			free(command);
			return false;
		}
	}
	
	/* Fork a child process */
	pid = fork();
	if (pid == -1) {
		log_message(LOG_LEVEL_ERR, "Failed to fork: %s", strerror(errno));
		if (capture_output) {
			close(stdout_pipe[0]); close(stdout_pipe[1]);
			close(stderr_pipe[0]); close(stderr_pipe[1]);
		}
		free(command);
		return false;
	}
	
	/* Child process */
	if (pid == 0) {
		/* Redirect stdout and stderr to pipes if configured */
		if (capture_output) {
			/* Close read ends of pipes */
			close(stdout_pipe[0]);
			close(stderr_pipe[0]);
			
			/* Redirect stdout and stderr to pipes */
			dup2(stdout_pipe[1], STDOUT_FILENO);
			dup2(stderr_pipe[1], STDERR_FILENO);
			
			/* Close write ends after dup2 */
			close(stdout_pipe[1]);
			close(stderr_pipe[1]);
		}
		
		/* Execute the command */
		execl("/bin/sh", "sh", "-c", command, NULL);
		
		/* If we get here, execl failed */
		log_message(LOG_LEVEL_ERR, "Failed to execute command: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	/* Read and log output line by line */
	if (capture_output) {
		char buffer[4096] = {0};
		char line_buffer[4096] = {0};
		size_t line_pos = 0;
		ssize_t bytes_read;
		fd_set read_fds;
		struct timeval timeout;
		int max_fd = (stdout_pipe[0] > stderr_pipe[0]) ? stdout_pipe[0] : stderr_pipe[0];
		bool stdout_open = true, stderr_open = true;
		int empty_read_count = 0;
		bool last_line_was_empty = false;
		
		/* Process all output until both pipes are closed or timeout */
		while (stdout_open || stderr_open) {
			FD_ZERO(&read_fds);
			if (stdout_open) FD_SET(stdout_pipe[0], &read_fds);
			if (stderr_open) FD_SET(stderr_pipe[0], &read_fds);
			
			timeout.tv_sec = 0;
			timeout.tv_usec = 100000; /* 100ms timeout */
			
			int select_result = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
			
			/* Timeout or error */
			if (select_result <= 0) {
				empty_read_count++;
				
				/* Log any partial lines remaining */
				if (line_pos > 0) {
					line_buffer[line_pos] = '\0';
					log_message(LOG_LEVEL_NOTICE, "[%s]: %s", watch->name, line_buffer);
					line_pos = 0;
				}
				
				/* Break after several consecutive empty reads */
				if (empty_read_count >= 5) {
					break;  /* Exit the loop after 5 consecutive timeouts */
				}
				
				continue;
			}
			
			/* Reset counter when we get data */
			empty_read_count = 0;
			
			/* Process stdout */
			if (stdout_open && FD_ISSET(stdout_pipe[0], &read_fds)) {
				bytes_read = read(stdout_pipe[0], buffer, sizeof(buffer) - 1);
				
				if (bytes_read <= 0) {
					stdout_open = false;
				} else {
					buffer[bytes_read] = '\0';
					
					/* Process line by line */
					for (size_t i = 0; i < (size_t)bytes_read; i++) {
						if (buffer[i] == '\n') {
							/* Avoid consecutive empty lines */
							line_buffer[line_pos] = '\0';
							
							if (line_pos > 0 || !last_line_was_empty) {
								log_message(LOG_LEVEL_NOTICE, "[%s]: %s", watch->name, line_buffer);
							}
							
							last_line_was_empty = (line_pos == 0);
							line_pos = 0;
						} else if (line_pos < sizeof(line_buffer) - 1) {
							/* Add character to buffer */
							line_buffer[line_pos++] = buffer[i];
						}
					}
				}
			}
			
			/* Process stderr */
			if (stderr_open && FD_ISSET(stderr_pipe[0], &read_fds)) {
				bytes_read = read(stderr_pipe[0], buffer, sizeof(buffer) - 1);
				
				if (bytes_read <= 0) {
					stderr_open = false;
				} else {
					buffer[bytes_read] = '\0';
					/* Log stderr directly */
					log_message(LOG_LEVEL_WARNING, "[%s]: %s", watch->name, buffer);
				}
			}
		}
		
		/* Close read ends of pipes */
		close(stdout_pipe[0]);
		close(stderr_pipe[0]);
	}
	
	/* Parent process - create command intent */
	command_intent_create(pid, command, event->path);
	
	/* Mark the entity state with the command execution */
	entity_state_t *state = get_entity_state(event->path, ENTITY_UNKNOWN, (watch_entry_t *)watch);
	if (state) {
		state->last_command_time = time(NULL);
	}
	
	free(command);
	
	return true;
}
