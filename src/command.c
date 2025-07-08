#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pwd.h>
#include <signal.h>
#include <errno.h>
#include <stdarg.h>
#include <pthread.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/select.h>

#include "command.h"
#include "threads.h"
#include "states.h"
#include "logger.h"

/* Maximum length of command */
#define MAX_CMD_LEN 4096

/* Global array of active command intents */
#define MAX_COMMAND_INTENTS 10
static int active_intent_count = 0;
static command_intent_t command_intents[MAX_COMMAND_INTENTS];

/* Debounce time in milliseconds */
static int debounce_time_ms = DEFAULT_DEBOUNCE_TIME_MS;

/* Thread-safe logging wrapper */
void thread_safe_log(int level, const char *format, ...) {
	static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
	va_list args;

	pthread_mutex_lock(&log_mutex);
	va_start(args, format);

	/* Use a buffer for thread-safe logging */
	char buffer[2048];
	vsnprintf(buffer, sizeof(buffer), format, args);
	log_message(level, "%s", buffer);

	va_end(args);
	pthread_mutex_unlock(&log_mutex);
}

/* SIGCHLD handler to reap child processes and mark command intents as complete */
static void command_sigchld_handler(int sig) {
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
		command_intent_mark_complete(pid);
	}

	/* Restore original signal mask */
	pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
}

/* Initialize command subsystem */
bool command_init(void) {
	/* Set up SIGCHLD handler */
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = command_sigchld_handler;
	sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		log_message(LOG_LEVEL_ERR, "Failed to set up SIGCHLD handler: %s", strerror(errno));
		return false;
	}

	/* Initialize thread pool */
	if (!thread_pool_init()) {
		log_message(LOG_LEVEL_ERR, "Failed to initialize thread pool");
		return false;
	}

	/* Initialize command intent tracking */
	memset(command_intents, 0, sizeof(command_intents));
	active_intent_count = 0;

	return true;
}

/* Clean up command intent tracking */
void command_intent_cleanup(void) {
	sigset_t mask, oldmask;

	/* Block SIGCHLD to prevent race condition with signal handler */
	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &mask, &oldmask);

	for (int i = 0; i < MAX_COMMAND_INTENTS; i++) {
		if (command_intents[i].active && command_intents[i].affected_paths) {
			for (int j = 0; j < command_intents[i].affected_path_count; j++) {
				free(command_intents[i].affected_paths[j]);
			}
			free(command_intents[i].affected_paths);
			command_intents[i].affected_paths = NULL;
		}
	}
	memset(command_intents, 0, sizeof(command_intents));
	active_intent_count = 0;

	/* Restore previous signal mask */
	sigprocmask(SIG_SETMASK, &oldmask, NULL);
}

/* Check if a path is affected by any active command */
bool is_path_affected_by_command(const char *path) {
	time_t now;
	time(&now);
	sigset_t mask, oldmask;

	/* Block SIGCHLD while accessing command_intents array */
	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	pthread_sigmask(SIG_BLOCK, &mask, &oldmask);

	/* Iterate through all active command intents */
	for (int i = 0; i < MAX_COMMAND_INTENTS; i++) {
		if (!command_intents[i].active) continue;

		/* Check if the command has expired */
		if (now > command_intents[i].expected_end_time) {
			log_message(LOG_LEVEL_DEBUG, "Command intent %d expired", i);

			/* Mark as inactive but don't free memory here to prevent race conditions */
			command_intents[i].active = false;
			active_intent_count--;
			continue;
		}

		/* Check if the path matches any affected path */
		if (!command_intents[i].affected_paths) {
			continue;
		}

		for (int j = 0; j < command_intents[i].affected_path_count; j++) {
			const char *affected_path = command_intents[i].affected_paths[j];

			if (!affected_path) {
				continue;
			}

			/* Check for exact match */
			if (strcmp(path, affected_path) == 0) {
				log_message(LOG_LEVEL_DEBUG, "Path %s is directly affected by command %d",
				            path, i);
				/* Restore signal mask before returning */
				pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
				return true;
			}

			/* Check if path is a subdirectory of affected_path */
			size_t affected_len = strlen(affected_path);
			if (strncmp(path, affected_path, affected_len) == 0 &&
			    (path[affected_len] == '/' || path[affected_len] == '\0')) {
				log_message(LOG_LEVEL_DEBUG, "Path %s is within affected path %s (command %d)",
				            path, affected_path, i);
				/* Restore signal mask before returning */
				pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
				return true;
			}

			/* Check if affected_path is a subdirectory of path */
			size_t path_len = strlen(path);
			if (strncmp(affected_path, path, path_len) == 0 &&
			    (affected_path[path_len] == '/' || affected_path[path_len] == '\0')) {
				log_message(LOG_LEVEL_DEBUG, "Path %s contains affected path %s (command %d)",
				            path, affected_path, i);
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
void command_intent_cleanup_expired(void) {
	sigset_t mask, oldmask;
	time_t now;
	time(&now);

	/* Block SIGCHLD to prevent race condition with signal handler */
	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &mask, &oldmask);

	for (int i = 0; i < MAX_COMMAND_INTENTS; i++) {
		if (!command_intents[i].active) continue;

		/* Check if the command has expired */
		if (now > command_intents[i].expected_end_time) {
			/* Free affected paths memory */
			if (command_intents[i].affected_paths) {
				for (int j = 0; j < command_intents[i].affected_path_count; j++) {
					if (command_intents[i].affected_paths[j]) {
						free(command_intents[i].affected_paths[j]);
						command_intents[i].affected_paths[j] = NULL;
					}
				}
				free(command_intents[i].affected_paths);
				command_intents[i].affected_paths = NULL;
			}
			command_intents[i].affected_path_count = 0;

			/* Mark as inactive if not already */
			if (command_intents[i].active) {
				command_intents[i].active = false;
				active_intent_count--;
			}
		}
	}

	/* Restore previous signal mask */
	sigprocmask(SIG_SETMASK, &oldmask, NULL);
}

/* Analyze a command to determine what paths it will affect */
command_intent_t *command_intent_create(pid_t pid, const char *command, const char *base_path) {
	sigset_t mask, oldmask;

	/* Block SIGCHLD while accessing command_intents array */
	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	pthread_sigmask(SIG_BLOCK, &mask, &oldmask);

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
		/* Restore signal mask before returning */
		pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
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
						if (path[0] == '"' && path[len - 1] == '"') {
							memmove(path, path+1, len-2);
							path[len - 2] = '\0';
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

	/* Restore signal mask before returning */
	pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
	return intent;
}

/* Mark a command intent as complete */
bool command_intent_mark_complete(pid_t pid) {
	sigset_t mask, oldmask;

	/* Block SIGCHLD while accessing command_intents array */
	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	pthread_sigmask(SIG_BLOCK, &mask, &oldmask);

	for (int i = 0; i < MAX_COMMAND_INTENTS; i++) {
		if (command_intents[i].active && command_intents[i].command_pid == pid) {
			command_intents[i].active = false;
			active_intent_count--;

			log_message(LOG_LEVEL_DEBUG, "Marked command intent for PID %d as complete", pid);

			/* Free affected paths */
			if (command_intents[i].affected_paths) {
				for (int j = 0; j < command_intents[i].affected_path_count; j++) {
					if (command_intents[i].affected_paths[j]) {
						free(command_intents[i].affected_paths[j]);
						command_intents[i].affected_paths[j] = NULL;
					}
				}
				free(command_intents[i].affected_paths);
				command_intents[i].affected_paths = NULL;
			}
			command_intents[i].affected_path_count = 0;

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
		debounce_time_ms = milliseconds;
		log_message(LOG_LEVEL_INFO, "Command debounce time set to %d ms", debounce_time_ms);
	}
}

/* Get debounce time */
int command_get_debounce_time(void) {
	return debounce_time_ms;
}

/* Helper function to substitute a placeholder in a string */
static void substitute(char *result, const char *placeholder, const char *value) {
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

/* Helper function to format size in a human-readable way */
static const char *format_size_human_readable(size_t size, char *buf, size_t buf_size) {
	const char *suffixes[] = {"B", "K", "M", "G", "T"};
	int i = 0;
	double d_size = (double) size;

	while (d_size >= 1024 && i < 4) {
		d_size /= 1024;
		i++;
	}

	snprintf(buf, buf_size, "%.1f%s", d_size, suffixes[i]);
	return buf;
}

/* Substitutes placeholders in the command string:
 * %p: Path where the event occurred
 * %n: Filename (for files) or subdirectory name (for directories) which triggered the event
 * %d: Directory containing the path that triggered the event
 * %b: Base path of the watch from the config
 * %w: Name of the watch from the config
 * %r: Event path relative to the watch path
 * %f: The file that triggered a directory event (most recent)
 * %s: Size of the file in bytes (recursive for directories)
 * %S: Human-readable size (e.g., 1.2M, 512K)
 * %t: Time of the event (format: YYYY-MM-DD HH:MM:SS)
 * %u: User who triggered the event
 * %e: Event type which occurred
 */
char *command_substitute_placeholders(const watch_entry_t *watch, const char *command, const file_event_t *event) {
	char *result;
	char time_str[64];
	char user_str[64];
	char size_str[32];
	char human_size_str[32];
	char *event_str;
	struct passwd *pwd;
	struct tm tm;
	struct stat st;

	if (command == NULL || event == NULL || watch == NULL) {
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
	substitute(result, "%p", event->path);

	/* Substitute %n with the filename/dirname */
	if (strstr(result, "%n")) {
		char *path_copy = strdup(event->path);
		substitute(result, "%n", basename(path_copy));
		free(path_copy);
	}

	/* Substitute %d with the directory */
	if (strstr(result, "%d")) {
		char *path_copy = strdup(event->path);
		substitute(result, "%d", dirname(path_copy));
		free(path_copy);
	}

	/* Substitute %b with the base watch path */
	substitute(result, "%b", watch->path);

	/* Substitute %w with the watch name */
	substitute(result, "%w", watch->name);

	/* Substitute %r with the relative path */
	if (strstr(result, "%r")) {
		const char *relative_path = event->path + strlen(watch->path);
		if (*relative_path == '/') {
			relative_path++;
		}
		substitute(result, "%r", relative_path);
	}

	/* Get entity state for size and trigger file placeholders */
	entity_state_t *state = get_entity_state(event->path, ENTITY_UNKNOWN, (watch_entry_t *) watch);

	/* Substitute %f with the trigger file path */
	if (state) {
		entity_state_t *root_state = find_root_state(state);
		if (root_state && root_state->trigger_file_path) {
			substitute(result, "%f", root_state->trigger_file_path);
		} else {
			substitute(result, "%f", event->path); /* Fallback to event path */
		}
	} else {
		substitute(result, "%f", event->path); /* Fallback if no state */
	}

	/* Handle size placeholders %s and %S */
	if (strstr(result, "%s") || strstr(result, "%S")) {
		size_t size = 0;
		if (state && state->type == ENTITY_DIRECTORY) {
			size = state->dir_stats.recursive_total_size;
		} else if (stat(event->path, &st) == 0) {
			size = st.st_size;
		}

		snprintf(size_str, sizeof(size_str), "%zu", size);
		substitute(result, "%s", size_str);

		format_size_human_readable(size, human_size_str, sizeof(human_size_str));
		substitute(result, "%S", human_size_str);
	}

	/* Substitute %t with the time */
	localtime_r(&event->wall_time.tv_sec, &tm);
	strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm);
	substitute(result, "%t", time_str);

	/* Substitute %u with the user */
	pwd = getpwuid(event->user_id);
	if (pwd != NULL) {
		snprintf(user_str, sizeof(user_str), "%s", pwd->pw_name);
	} else {
		snprintf(user_str, sizeof(user_str), "%d", event->user_id);
	}
	substitute(result, "%u", user_str);

	/* Substitute %e with the event type */
	event_str = (char *) event_type_to_string(event->type);
	substitute(result, "%e", event_str);

	return result;
}

/* Add line to output buffer */
static bool add_to_output_buffer(char ***buffer, int *count, int *capacity, const char *line) {
	if (*count >= *capacity) {
		int new_capacity = *capacity == 0 ? 16 : *capacity * 2;
		char **new_buffer = realloc(*buffer, new_capacity * sizeof(char *));
		if (!new_buffer) {
			return false;
		}
		*buffer = new_buffer;
		*capacity = new_capacity;
	}

	(*buffer)[*count] = strdup(line);
	if (!(*buffer)[*count]) {
		return false;
	}
	(*count)++;
	return true;
}

/* Flush buffered output */
static void flush_output_buffer(const watch_entry_t *watch, char **buffer, int count) {
	if (count == 0) return;

	for (int i = 0; i < count; i++) {
		if (buffer[i]) {
			thread_safe_log(LOG_LEVEL_NOTICE, "[%s]: %s", watch->name, buffer[i]);
		}
	}
}

/* Synchronous command execution with robust output capture */
bool command_execute_sync(const watch_entry_t *watch, const file_event_t *event) {
	pid_t pid;
	char *command;
	int stdout_pipe[2] = {-1, -1}, stderr_pipe[2] = {-1, -1};
	bool capture_output = watch->log_output;
	bool buffer_output = watch->buffer_output;
	time_t start_time, end_time;

	/* Output buffering variables */
	char **output_buffer = NULL;
	int output_count = 0;
	int output_capacity = 0;

	if (watch == NULL || event == NULL) {
		thread_safe_log(LOG_LEVEL_ERR, "Invalid arguments to command_execute_sync_internal");
		return false;
	}

	/* Handle special config reload command */
	if (strcmp(watch->command, "__config_reload__") == 0) {
		/* This is handled by the monitor, not executed as a shell command */
		return true;
	}

	/* Record start time */
	time(&start_time);

	/* Substitute placeholders in the command */
	command = command_substitute_placeholders(watch, watch->command, event);
	if (command == NULL) {
		return false;
	}

	thread_safe_log(LOG_LEVEL_INFO, "Executing command: %s", command);

	/* Create pipes for stdout and stderr if configured to capture output */
	if (capture_output) {
		if (pipe(stdout_pipe) < 0 || pipe(stderr_pipe) < 0) {
			thread_safe_log(LOG_LEVEL_ERR, "Failed to create pipes: %s", strerror(errno));
			free(command);
			return false;
		}
	}

	/* Fork a child process */
	pid = fork();
	if (pid == -1) {
		thread_safe_log(LOG_LEVEL_ERR, "Failed to fork: %s", strerror(errno));
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

		/* Execute the command */
		execl("/bin/sh", "sh", "-c", command, NULL);

		/* If we get here, execl failed */
		thread_safe_log(LOG_LEVEL_ERR, "Failed to execute command: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Parent process - create command intent */
	command_intent_create(pid, command, event->path);

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
					thread_safe_log(LOG_LEVEL_WARNING, "select() failed: %s", strerror(errno));
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
									if (!add_to_output_buffer(&output_buffer, &output_count, &output_capacity,
									                          line_buffer)) {
										thread_safe_log(LOG_LEVEL_WARNING,
										                "[%s]: Failed to buffer output, switching to real-time",
										                watch->name);
										buffer_output = false;
										thread_safe_log(LOG_LEVEL_NOTICE, "[%s]: %s", watch->name, line_buffer);
									}
								} else {
									/* Real-time logging */
									thread_safe_log(LOG_LEVEL_NOTICE, "[%s]: %s", watch->name, line_buffer);
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
					thread_safe_log(LOG_LEVEL_WARNING, "[%s]: %s", watch->name, buffer);
				}
			}
		}

		/* Log any remaining partial line */
		if (line_pos > 0) {
			line_buffer[line_pos] = '\0';
			if (buffer_output) {
				if (!add_to_output_buffer(&output_buffer, &output_count, &output_capacity, line_buffer)) {
					thread_safe_log(LOG_LEVEL_NOTICE, "[%s]: %s", watch->name, line_buffer);
				}
			} else {
				thread_safe_log(LOG_LEVEL_NOTICE, "[%s]: %s", watch->name, line_buffer);
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
	command_intent_mark_complete(pid);

	/* Restore previous signal mask */
	sigprocmask(SIG_SETMASK, &oldmask, NULL);

	/* Record end time */
	time(&end_time);

	/* Flush buffered output if buffering was enabled */
	if (capture_output && buffer_output && output_buffer) {
		flush_output_buffer(watch, output_buffer, output_count);

		/* Clean up buffer */
		for (int i = 0; i < output_count; i++) {
			free(output_buffer[i]);
		}
		free(output_buffer);
	}

	/* Log command completion */
	thread_safe_log(LOG_LEVEL_INFO, "[%s] Finished execution (pid %d, duration: %lds, exit: %d)",
	                watch->name, pid, end_time - start_time, WEXITSTATUS(status));

	/* Mark the entity state with the command execution */
	entity_state_t *state = get_entity_state(event->path, ENTITY_UNKNOWN, (watch_entry_t *) watch);
	if (state) {
		state->last_command_time = time(NULL);
	}

	free(command);
	return true;
}

/* Command execution using thread pool */
bool command_execute(const watch_entry_t *watch, const file_event_t *event) {
	return thread_pool_submit(watch, event);
}

/* Clean up command subsystem */
void command_cleanup(void) {
	/* Wait for all pending commands to complete */
	thread_pool_wait_all();

	/* Destroy thread pool */
	thread_pool_destroy();

	/* Clean up command intents */
	command_intent_cleanup();
}
