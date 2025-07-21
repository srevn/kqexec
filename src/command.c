#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pwd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/select.h>

#include "command.h"
#include "threads.h"
#include "states.h"
#include "stability.h"
#include "logger.h"
#include "scanner.h"

/* Module-scoped threads reference */
static threads_t *command_threads = NULL;

/* Maximum length of command */
#define MAX_CMD_LEN 4096

/* Global array of active command intents */
#define MAX_INTENTS 10
static int intent_count = 0;
static intent_t intents[MAX_INTENTS];

/* Debounce time in milliseconds */
static int debounce_ms = DEFAULT_DEBOUNCE_TIME_MS;

/* SIGCHLD handler to reap child processes and mark command intents as complete */
static void command_sigchld(int sig) {
	(void) sig;
	pid_t pid;
	int status;
	sigset_t mask, oldmask;

	/* Block SIGCHLD during handler execution to prevent reentrancy */
	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	pthread_sigmask(SIG_BLOCK, &mask, &oldmask);

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		/* Mark the command intent as complete */
		intent_complete(pid);
	}

	/* Restore original signal mask */
	pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
}

/* Initialize command subsystem */
bool command_init(threads_t *threads) {
	if (!threads) {
		log_message(ERROR, "Invalid threads parameter");
		return false;
	}

	/* Store threads reference */
	command_threads = threads;

	/* Set up SIGCHLD handler */
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = command_sigchld;
	sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		log_message(ERROR, "Failed to set up SIGCHLD handler: %s", strerror(errno));
		return false;
	}

	/* Initialize command intent tracking */
	memset(intents, 0, sizeof(intents));
	intent_count = 0;

	return true;
}

/* Clean up command intent tracking */
void intent_cleanup(void) {
	sigset_t mask, oldmask;

	/* Block SIGCHLD to prevent race condition with signal handler */
	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &mask, &oldmask);

	for (int i = 0; i < MAX_INTENTS; i++) {
		if (intents[i].active && intents[i].paths) {
			for (int j = 0; j < intents[i].num_paths; j++) {
				free(intents[i].paths[j]);
			}
			free(intents[i].paths);
			intents[i].paths = NULL;
		}
	}
	memset(intents, 0, sizeof(intents));
	intent_count = 0;

	/* Restore previous signal mask */
	sigprocmask(SIG_SETMASK, &oldmask, NULL);
}

/* Check if a path is affected by any active command */
bool command_affects(const char *path) {
	time_t current_time;
	time(&current_time);
	sigset_t mask, oldmask;

	/* Block SIGCHLD while accessing intents array */
	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	pthread_sigmask(SIG_BLOCK, &mask, &oldmask);

	/* Iterate through all active command intents */
	for (int i = 0; i < MAX_INTENTS; i++) {
		if (!intents[i].active) continue;

		/* Check if the command has expired */
		if (current_time > intents[i].expire) {
			log_message(DEBUG, "Command intent %d expired", i);

			/* Mark as inactive but don't free memory here to prevent race conditions */
			intents[i].active = false;
			intent_count--;
			continue;
		}

		/* Check if the path matches any affected path */
		if (!intents[i].paths) {
			continue;
		}

		for (int j = 0; j < intents[i].num_paths; j++) {
			const char *affected_path = intents[i].paths[j];

			if (!affected_path) {
				continue;
			}

			/* Check for exact match */
			if (strcmp(path, affected_path) == 0) {
				log_message(DEBUG, "Path %s is directly affected by command %d", path, i);
				/* Restore signal mask before returning */
				pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
				return true;
			}

			/* Check if path is a subdirectory of affected_path */
			size_t affected_len = strlen(affected_path);
			if (strncmp(path, affected_path, affected_len) == 0 &&
			    (path[affected_len] == '/' || path[affected_len] == '\0')) {
				log_message(DEBUG, "Path %s is within affected path %s (command %d)", path, affected_path, i);
				/* Restore signal mask before returning */
				pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
				return true;
			}

			/* Check if affected_path is a subdirectory of path */
			size_t path_len = strlen(path);
			if (strncmp(affected_path, path, path_len) == 0 &&
			    (affected_path[path_len] == '/' || affected_path[path_len] == '\0')) {
				log_message(DEBUG, "Path %s contains affected path %s (command %d)", path, affected_path, i);
				/* Restore signal mask before returning */
				pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
				return true;
			}
		}
	}

	/* Restore signal mask before returning */
	pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
	return false;
}

/* Clean up expired command intents - call this periodically and safely */
void intent_expire(void) {
	sigset_t mask, oldmask;
	time_t current_time;
	time(&current_time);

	/* Block SIGCHLD to prevent race condition with signal handler */
	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &mask, &oldmask);

	for (int i = 0; i < MAX_INTENTS; i++) {
		if (!intents[i].active) continue;

		/* Check if the command has expired */
		if (current_time > intents[i].expire) {
			/* Free affected paths memory */
			if (intents[i].paths) {
				for (int j = 0; j < intents[i].num_paths; j++) {
					if (intents[i].paths[j]) {
						free(intents[i].paths[j]);
						intents[i].paths[j] = NULL;
					}
				}
				free(intents[i].paths);
				intents[i].paths = NULL;
			}
			intents[i].num_paths = 0;

			/* Mark as inactive if not already */
			if (intents[i].active) {
				intents[i].active = false;
				intent_count--;
			}
		}
	}

	/* Restore previous signal mask */
	sigprocmask(SIG_SETMASK, &oldmask, NULL);
}

/* Analyze a command to determine what paths it will affect */
intent_t *intent_create(pid_t pid, const char *command, const char *base_path) {
	sigset_t mask, oldmask;

	/* Block SIGCHLD while accessing intents array */
	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	pthread_sigmask(SIG_BLOCK, &mask, &oldmask);

	/* Find a free slot in the intents array */
	int slot = -1;
	for (int i = 0; i < MAX_INTENTS; i++) {
		if (!intents[i].active) {
			slot = i;
			break;
		}
	}

	if (slot == -1) {
		log_message(WARNING, "No free slots for command intent tracking");
		/* Restore signal mask before returning */
		pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
		return NULL;
	}

	/* Initialize the command intent */
	intent_t *intent = &intents[slot];
	memset(intent, 0, sizeof(intent_t));
	intent->pid = pid;
	time(&intent->start);

	/* Set a default expected end time (10 seconds) */
	intent->expire = intent->start + 10;

	/* Allocate memory for affected paths */
	intent->paths = calloc(MAX_AFFECTED_PATHS, sizeof(char *));
	if (!intent->paths) {
		log_message(ERROR, "Failed to allocate memory for affected paths");
		return NULL;
	}

	/* Add the base path as the first affected path */
	intent->paths[0] = strdup(base_path);
	intent->num_paths = 1;

	/* Simple command analysis - parse the command for common operations */
	/* Check for file moves */
	if (strstr(command, "mv ") || strstr(command, " mv ") ||
	    strstr(command, "-exec mv") || strstr(command, " move ")) {
		log_message(DEBUG, "Command contains file move operation");

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
						if (path[0] == '"' && path[len - 1] == '"') {
							memmove(path, path+1, len-2);
							path[len - 2] = '\0';
						}

						/* Add the target path if it's not already in the list */
						bool already_added = false;
						for (int j = 0; j < intent->num_paths; j++) {
							if (strcmp(intent->paths[j], path) == 0) {
								already_added = true;
								break;
							}
						}

						if (!already_added && intent->num_paths < MAX_AFFECTED_PATHS) {
							intent->paths[intent->num_paths] = strdup(path);
							intent->num_paths++;
							log_message(DEBUG, "Added target path %s to affected paths", path);
						}
					}
				}
			}
		}
	}

	/* Check for file deletions */
	if (strstr(command, "rm ") || strstr(command, " rm ") ||
	    strstr(command, "-delete") || strstr(command, " delete ")) {
		log_message(DEBUG, "Command contains file delete operation");
		/* Delete operations affect the base path and its parents */
		/* Already added base path, so no additional paths needed */
	}

	/* Mark the intent as active */
	intent->active = true;
	intent_count++;

	log_message(DEBUG, "Created command intent for PID %d with %d affected paths", pid, intent->num_paths);

	/* Restore signal mask before returning */
	pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
	return intent;
}

/* Mark a command intent as complete */
bool intent_complete(pid_t pid) {
	sigset_t mask, oldmask;

	/* Block SIGCHLD while accessing intents array */
	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	pthread_sigmask(SIG_BLOCK, &mask, &oldmask);

	for (int i = 0; i < MAX_INTENTS; i++) {
		if (intents[i].active && intents[i].pid == pid) {
			intents[i].active = false;
			intent_count--;

			log_message(DEBUG, "Marked command intent for PID %d as complete", pid);

			/* Free affected paths */
			if (intents[i].paths) {
				for (int j = 0; j < intents[i].num_paths; j++) {
					if (intents[i].paths[j]) {
						free(intents[i].paths[j]);
						intents[i].paths[j] = NULL;
					}
				}
				free(intents[i].paths);
				intents[i].paths = NULL;
			}
			intents[i].num_paths = 0;

			/* Restore signal mask before returning */
			pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
			return true;
		}
	}

	/* Restore signal mask before returning */
	pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
	return false;
}

/* Set debounce time */
void command_debounce_time(int milliseconds) {
	if (milliseconds >= 0) {
		debounce_ms = milliseconds;
		log_message(INFO, "Command debounce time set to %d ms", debounce_ms);
	}
}

/* Get debounce time */
int command_get_debounce_time(void) {
	return debounce_ms;
}

/* Helper function to substitute a placeholder in a string */
static void command_substitute(char *result, const char *placeholder, const char *value) {
	char *current_pos;
	while ((current_pos = strstr(result, placeholder)) != NULL) {
		char temp[MAX_CMD_LEN];
		*current_pos = '\0';
		strcpy(temp, result);
		snprintf(temp + strlen(temp), MAX_CMD_LEN - strlen(temp), "%s%s",
		         value, current_pos + strlen(placeholder));
		strcpy(result, temp);
	}
}

/* Substitutes placeholders in the command string:
 * %p: Path where the event occurred
 * %n: Filename (for files) or subdirectory name (for directories) which triggered the event
 * %d: Directory containing the path that triggered the event
 * %b: Base path of the watch from the config
 * %w: Name of the watch from the config
 * %r: Event path relative to the watch path
 * %f: The file that triggered a directory event (most recent)
 * %F: The basename of the file that triggered a directory event (most recent)
 * %l: List of filenames (without paths) modified within one second of current event
 * %L: List of files modified within one second of current event (newline-separated)
 * %s: Size of the file in bytes (recursive for directories)
 * %S: Human-readable size (e.g., 1.2M, 512K)
 * %t: Time of the event (format: YYYY-MM-DD HH:MM:SS)
 * %u: User who triggered the event
 * %e: Event type which occurred
 */
char *command_placeholders(monitor_t *monitor, const watch_t *watch, const char *command, const event_t *event) {
	char *result;
	char time_str[64];
	char user_str[64];
	char size_str[32];
	char *event_str;
	struct passwd *pwd;
	struct tm tm;
	struct stat info;

	if (command == NULL || event == NULL || watch == NULL) {
		return NULL;
	}

	/* Allocate memory for the result */
	result = malloc(MAX_CMD_LEN);
	if (result == NULL) {
		log_message(ERROR, "Failed to allocate memory for command");
		return NULL;
	}

	/* Initialize the result with the command */
	strncpy(result, command, MAX_CMD_LEN - 1);
	result[MAX_CMD_LEN - 1] = '\0';

	/* Substitute %p with the path */
	command_substitute(result, "%p", event->path);

	/* Substitute %n with the filename/dirname */
	if (strstr(result, "%n")) {
		char *path_copy = strdup(event->path);
		command_substitute(result, "%n", basename(path_copy));
		free(path_copy);
	}

	/* Substitute %d with the directory */
	if (strstr(result, "%d")) {
		char *path_copy = strdup(event->path);
		command_substitute(result, "%d", dirname(path_copy));
		free(path_copy);
	}

	/* Substitute %b with the base watch path */
	command_substitute(result, "%b", watch->path);

	/* Substitute %w with the watch name */
	command_substitute(result, "%w", watch->name);

	/* Substitute %r with the relative path */
	if (strstr(result, "%r")) {
		const char *relative_path = event->path + strlen(watch->path);
		if (*relative_path == '/') {
			relative_path++;
		}
		command_substitute(result, "%r", relative_path);
	}

	/* Get entity state for size and trigger file placeholders */
	entity_t *state = state_get(monitor->states, event->path, ENTITY_UNKNOWN, (watch_t *) watch);

	/* Substitute %f and %F with trigger file path and name */
	if (strstr(result, "%f") || strstr(result, "%F")) {
		const char *trigger = event->path; /* Default to event path */
		if (state) {
			entity_t *root = stability_root(monitor, state);
			if (root && root->trigger) {
				trigger = root->trigger;
			}
		}

		command_substitute(result, "%f", trigger);

		if (strstr(result, "%F")) {
			char *path_copy = strdup(trigger);
			if (path_copy) {
				command_substitute(result, "%F", basename(path_copy));
				free(path_copy);
			}
		}
	}

	/* Substitute %l with list of filenames (without paths) modified since processing began */
	if (strstr(result, "%l")) {
		/* Use current event time with 1-second buffer to catch files modified around this event */
		time_t since_time = event->wall_time.tv_sec - 1;
		char *modified_files = scanner_modified(watch->path, since_time, watch->recursive, true);
		if (modified_files) {
			command_substitute(result, "%l", modified_files);
			free(modified_files);
		} else {
			command_substitute(result, "%l", "");
		}
	}

	/* Substitute %L with list of files modified since processing began */
	if (strstr(result, "%L")) {
		/* Use current event time with 1-second buffer to catch files modified around this event */
		time_t since_time = event->wall_time.tv_sec - 1;
		char *modified_files = scanner_modified(watch->path, since_time, watch->recursive, false);
		if (modified_files) {
			command_substitute(result, "%L", modified_files);
			free(modified_files);
		} else {
			command_substitute(result, "%L", "");
		}
	}

	/* Handle size placeholders %s and %S */
	if (strstr(result, "%s") || strstr(result, "%S")) {
		size_t size = 0;
		if (state && state->kind == ENTITY_DIRECTORY) {
			entity_t *size_state = stability_root(monitor, state);
			size = size_state ? size_state->stability->stats.tree_size : state->stability->stats.tree_size;
		} else if (stat(event->path, &info) == 0) {
			size = info.st_size;
		}

		snprintf(size_str, sizeof(size_str), "%zu", size);
		command_substitute(result, "%s", size_str);
		command_substitute(result, "%S", format_size((ssize_t)size, false));
	}

	/* Substitute %t with the time */
	localtime_r(&event->wall_time.tv_sec, &tm);
	strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm);
	command_substitute(result, "%t", time_str);

	/* Substitute %u with the user */
	pwd = getpwuid(event->user_id);
	if (pwd != NULL) {
		snprintf(user_str, sizeof(user_str), "%s", pwd->pw_name);
	} else {
		snprintf(user_str, sizeof(user_str), "%d", event->user_id);
	}
	command_substitute(result, "%u", user_str);

	/* Substitute %e with the event type */
	event_str = (char *) filter_to_string(event->type);
	command_substitute(result, "%e", event_str);

	return result;
}

/* Add line to output buffer */
static bool buffer_append(char ***buffer, int *buffer_count, int *buffer_capacity, const char *line) {
	if (*buffer_count >= *buffer_capacity) {
		int new_capacity = *buffer_capacity == 0 ? 16 : *buffer_capacity * 2;
		char **new_buffer = realloc(*buffer, new_capacity * sizeof(char *));
		if (!new_buffer) {
			return false;
		}
		*buffer = new_buffer;
		*buffer_capacity = new_capacity;
	}

	(*buffer)[*buffer_count] = strdup(line);
	if (!(*buffer)[*buffer_count]) {
		return false;
	}
	(*buffer_count)++;
	return true;
}

/* Flush buffered output */
static void buffer_flush(const watch_t *watch, char **buffer, int buffer_count) {
	if (buffer_count == 0) return;

	for (int i = 0; i < buffer_count; i++) {
		if (buffer[i]) {
			log_message(NOTICE, "[%s]: %s", watch->name, buffer[i]);
		}
	}
}

/* Command execution synchronous or asynchronous */
bool command_execute(monitor_t *monitor, const watch_t *watch, const event_t *event, bool async) {
	if (watch == NULL || event == NULL) {
		log_message(ERROR, "Invalid arguments to command_execute");
		return false;
	}

	/* For asynchronous execution, delegate to thread pool */
	if (async) {
		return threads_submit(command_threads, monitor, watch, event);
	}

	/* Synchronous execution with robust output capture */
	pid_t pid;
	char *command;
	int stdout_pipe[2] = {-1, -1}, stderr_pipe[2] = {-1, -1};
	bool capture_output = watch->log_output;
	bool buffer_output = watch->buffer_output;
	time_t start, end_time;

	/* Output buffering variables */
	char **output_buffer = NULL;
	int output_count = 0;
	int output_capacity = 0;

	/* Handle special config reload command */
	if (strcmp(watch->command, "__config_reload__") == 0) {
		/* This is handled by the monitor, not executed as a shell command */
		return true;
	}

	/* Record start time */
	time(&start);

	/* Substitute placeholders in the command */
	command = command_placeholders(monitor, watch, watch->command, event);
	if (command == NULL) {
		return false;
	}

	log_message(INFO, "Executing command: %s", command);

	/* Create pipes for stdout and stderr if configured to capture output */
	if (capture_output) {
		if (pipe(stdout_pipe) < 0 || pipe(stderr_pipe) < 0) {
			log_message(ERROR, "Failed to create pipes: %s", strerror(errno));
			free(command);
			return false;
		}
	}

	/* Fork a child process */
	pid = fork();
	if (pid == -1) {
		log_message(ERROR, "Failed to fork: %s", strerror(errno));
		if (capture_output) {
			close(stdout_pipe[0]);
			close(stdout_pipe[1]);
			close(stderr_pipe[0]);
			close(stderr_pipe[1]);
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

		/* Set environment variables for the command if enabled */
		if (watch->environment) {
			command_environment(monitor, watch, event);
		}

		/* Execute the command */
		execl("/bin/sh", "sh", "-c", command, NULL);

		/* If we get here, exec failed */
		log_message(ERROR, "Failed to execute command: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Parent process - create command intent */
	intent_create(pid, command, event->path);

	/* Read and log output if configured - robust version */
	if (capture_output) {
		/* Close write ends in parent */
		close(stdout_pipe[1]);
		close(stderr_pipe[1]);

		char buffer[8192] = {0};
		char line_buffer[8192] = {0};
		size_t line_pos = 0;
		ssize_t bytes_read;
		fd_set read_fds;
		int max_fd = (stdout_pipe[0] > stderr_pipe[0]) ? stdout_pipe[0] : stderr_pipe[0];
		bool stdout_open = true, stderr_open = true;

		/* Read until both pipes are closed */
		while (stdout_open || stderr_open) {
			FD_ZERO(&read_fds);
			if (stdout_open)
				FD_SET(stdout_pipe[0], &read_fds);
			if (stderr_open)
				FD_SET(stderr_pipe[0], &read_fds);

			/* No timeout - wait until data is available or pipes close */
			int select_result = select(max_fd + 1, &read_fds, NULL, NULL, NULL);

			if (select_result <= 0) {
				if (select_result < 0 && errno != EINTR) {
					log_message(WARNING, "select() failed: %s", strerror(errno));
				}
				continue;
			}

			/* Process stdout */
			if (stdout_open && FD_ISSET(stdout_pipe[0], &read_fds)) {
				bytes_read = read(stdout_pipe[0], buffer, sizeof(buffer) - 1);

				if (bytes_read <= 0) {
					stdout_open = false;
				} else {
					buffer[bytes_read] = '\0';

					/* Process line by line */
					for (size_t i = 0; i < (size_t) bytes_read; i++) {
						if (buffer[i] == '\n') {
							line_buffer[line_pos] = '\0';
							if (line_pos > 0) {
								if (buffer_output) {
									/* Add to buffer */
									if (!buffer_append(&output_buffer, &output_count, &output_capacity, line_buffer)) {
										log_message(WARNING, "[%s]: Failed to buffer output, switching to real-time",
															  watch->name);
										buffer_output = false;
										log_message(NOTICE, "[%s]: %s", watch->name, line_buffer);
									}
								} else {
									/* Real-time logging */
									log_message(NOTICE, "[%s]: %s", watch->name, line_buffer);
								}
							}
							line_pos = 0;
						} else if (line_pos < sizeof(line_buffer) - 1) {
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
					log_message(WARNING, "[%s]: %s", watch->name, buffer);
				}
			}
		}

		/* Log any remaining partial line */
		if (line_pos > 0) {
			line_buffer[line_pos] = '\0';
			if (buffer_output) {
				if (!buffer_append(&output_buffer, &output_count, &output_capacity, line_buffer)) {
					log_message(NOTICE, "[%s]: %s", watch->name, line_buffer);
				}
			} else {
				log_message(NOTICE, "[%s]: %s", watch->name, line_buffer);
			}
		}

		/* Close read ends */
		close(stdout_pipe[0]);
		close(stderr_pipe[0]);
	}

	/* Block SIGCHLD to prevent race condition with signal handler */
	sigset_t mask, oldmask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &mask, &oldmask);

	/* Wait for child process to complete */
	int status;
	waitpid(pid, &status, 0);

	/* Mark the command intent as complete immediately */
	intent_complete(pid);

	/* Restore previous signal mask */
	sigprocmask(SIG_SETMASK, &oldmask, NULL);

	/* Record end time */
	time(&end_time);

	/* Flush buffered output if buffering was enabled */
	if (capture_output && buffer_output && output_buffer) {
		buffer_flush(watch, output_buffer, output_count);

		/* Clean up buffer */
		for (int i = 0; i < output_count; i++) {
			free(output_buffer[i]);
		}
		free(output_buffer);
	}

	/* Log command completion */
	log_message(INFO, "[%s] Finished execution (pid %d, duration: %lds, exit: %d)",
	        		   watch->name, pid, end_time - start, WEXITSTATUS(status));

	/* Mark the entity state with the command execution */
	entity_t *state = state_get(monitor->states, event->path, ENTITY_UNKNOWN, (watch_t *) watch);
	if (state) {
		state->command_time = time(NULL);
	}

	free(command);
	return true;
}

/* Set environment variables for command execution */
void command_environment(monitor_t *monitor, const watch_t *watch, const event_t *event) {
	char buffer[1024];
	struct passwd *pwd;
	struct tm tm;

	if (watch == NULL || event == NULL) {
		return;
	}

	/* KQ_EVENT_TYPE - event type which occurred */
	setenv("KQ_EVENT_TYPE", filter_to_string(event->type), 1);

	/* KQ_TRIGGER_PATH - full path where the event occurred */
	setenv("KQ_TRIGGER_PATH", event->path, 1);

	/* KQ_WATCH_NAME - name of the watch from the configuration */
	setenv("KQ_WATCH_NAME", watch->name, 1);

	/* KQ_WATCH_PATH - base path being monitored */
	setenv("KQ_WATCH_PATH", watch->path, 1);

	/* KQ_RELATIVE_PATH - event path relative to the watch base*/
	const char *relative_path = event->path + strlen(watch->path);
	if (*relative_path == '/') {
		relative_path++;
	}
	setenv("KQ_RELATIVE_PATH", relative_path, 1);

	/* KQ_TRIGGER_FILE - basename of trigger path */
	char *path_copy = strdup(event->path);
	if (path_copy) {
		setenv("KQ_TRIGGER_FILE", basename(path_copy), 1);
		free(path_copy);
	}

	/* KQ_TRIGGER_DIR - directory containing trigger */
	path_copy = strdup(event->path);
	if (path_copy) {
		setenv("KQ_TRIGGER_DIR", dirname(path_copy), 1);
		free(path_copy);
	}

	/* KQ_TRIGGER_FILE_PATH - full path of the file that triggered the event */
	const char *trigger_file_path = event->path; /* Default to event path */
	entity_t *state = state_get(monitor->states, event->path, ENTITY_UNKNOWN, (watch_t *) watch);
	if (state) {
		entity_t *root = stability_root(monitor, state);
		if (root && root->trigger) {
			trigger_file_path = root->trigger;
		}
	}
	setenv("KQ_TRIGGER_FILE_PATH", trigger_file_path, 1);

	/* KQ_USER_ID - numeric user ID that caused the event*/
	snprintf(buffer, sizeof(buffer), "%d", event->user_id);
	setenv("KQ_USER_ID", buffer, 1);

	/* KQ_USERNAME - try to resolve user ID to name */
	pwd = getpwuid(event->user_id);
	if (pwd) {
		setenv("KQ_USERNAME", pwd->pw_name, 1);
	} else {
		snprintf(buffer, sizeof(buffer), "%d", event->user_id);
		setenv("KQ_USERNAME", buffer, 1);
	}

	/* KQ_TIMESTAMP - ISO 8601 format */
	if (localtime_r(&event->wall_time.tv_sec, &tm)) {
		strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", &tm);
		setenv("KQ_TIMESTAMP", buffer, 1);
	}

	/* KQ_MODIFIED_FILES - recent files modified around this event */
	time_t since_time = event->wall_time.tv_sec - 1;
	char *modified_files = scanner_modified(watch->path, since_time, watch->recursive, true);
	if (modified_files) {
		setenv("KQ_MODIFIED_FILES", modified_files, 1);
		free(modified_files);
	}
}

/* Clean up command subsystem */
void command_cleanup(threads_t *threads) {
	/* Wait for all pending commands to complete */
	if (threads) {
		threads_wait(threads);
	}

	/* Clean up command intents */
	intent_cleanup();

	/* Clear threads reference */
	command_threads = NULL;
}
