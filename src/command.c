#include "command.h"

#include <errno.h>
#include <libgen.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "events.h"
#include "logger.h"
#include "resource.h"
#include "scanner.h"
#include "stability.h"
#include "threads.h"

/* Module-scoped threads reference */
static threads_t *command_threads = NULL;

/* Maximum length of command */
#define MAX_CMD_LEN 4096

/* Debounce time in milliseconds */
static int debounce_ms = DEFAULT_DEBOUNCE_TIME_MS;

/* Initialize command subsystem */
bool command_init(threads_t *threads) {
	if (!threads) {
		log_message(ERROR, "Invalid threads parameter");
		return false;
	}

	/* Store threads reference */
	command_threads = threads;

	/* Ignore SIGCHLD to prevent zombie processes, child processes are waited for explicitly */
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		log_message(ERROR, "Failed to set SIGCHLD to SIG_IGN: %s", strerror(errno));
		return false;
	}

	return true;
}

/* Set debounce time */
void command_debounce_time(int milliseconds) {
	if (milliseconds >= 0) {
		debounce_ms = milliseconds;
		log_message(INFO, "Command debounce time set to %d ms", debounce_ms);
	}
}

/* Get debounce time */
int command_get_debounce_time(void) { return debounce_ms; }

/* Shell-escape a single path by wrapping in single quotes */
static char *command_escape(const char *path) {
	if (!path) return NULL;

	/* Calculate required buffer size */
	size_t len = strlen(path);
	size_t quotes = len + 8;
	for (const char *p = path; *p; p++) {
		/* Escape internal quotes 'x' becomes '\''x'\'' */
		if (*p == '\'') quotes += 4;
	}

	char *escaped = malloc(quotes);
	if (!escaped) return NULL;

	char *out = escaped;
	*out++ = '\''; /* Opening quote */

	for (const char *in = path; *in; in++) {
		if (*in == '\'') {
			/* Replace ' with '\'' */
			*out++ = '\'';
			*out++ = '\\';
			*out++ = '\'';
			*out++ = '\'';
		} else {
			*out++ = *in;
		}
	}

	*out++ = '\''; /* Closing quote */
	*out = '\0';

	return escaped;
}

/* Shell-escape a newline-separated list of paths */
static char *command_escape_list(const char *paths) {
	if (!paths || !*paths) return strdup("");

	/* Start with dynamic buffer */
	size_t result_capacity = 4096;
	char *result = malloc(result_capacity);
	if (!result) return NULL;

	result[0] = '\0';
	size_t result_len = 0;

	char *paths_copy = strdup(paths);
	if (!paths_copy) {
		free(result);
		return NULL;
	}

	char *line = strtok(paths_copy, "\n");
	bool first = true;

	while (line != NULL) {
		char *escaped = command_escape(line);
		if (escaped) {
			size_t escaped_len = strlen(escaped);
			/* +1 for newline if not first, +1 for null */
			size_t needed = result_len + (first ? 0 : 1) + escaped_len + 1;

			/* Grow buffer if needed */
			if (needed > result_capacity) {
				size_t new_capacity = needed * 2; /* Double to avoid frequent reallocations */
				char *new_result = realloc(result, new_capacity);
				if (!new_result) {
					free(escaped);
					free(result);
					free(paths_copy);
					return NULL;
				}
				result = new_result;
				result_capacity = new_capacity;
			}

			/* Add newline separator if not first */
			if (!first) {
				result[result_len++] = '\n';
			}

			/* Copy escaped path */
			strcpy(result + result_len, escaped);
			result_len += escaped_len;

			free(escaped);
			first = false;
		}
		line = strtok(NULL, "\n");
	}

	free(paths_copy);
	return result;
}

/* Helper function to substitute a placeholder in a string with dynamic allocation */
static char *command_substitute(const char *input, const char *placeholder, const char *value) {
	if (!input || !placeholder || !value) return input ? strdup(input) : NULL;

	const char *current_pos = strstr(input, placeholder);
	if (!current_pos) {
		return strdup(input); /* No substitution needed */
	}

	size_t placeholder_len = strlen(placeholder);
	size_t value_len = strlen(value);
	size_t input_len = strlen(input);

	/* Calculate new length after all substitutions */
	size_t new_len = input_len;
	const char *search_pos = input;
	while ((search_pos = strstr(search_pos, placeholder)) != NULL) {
		new_len = new_len - placeholder_len + value_len;
		search_pos += placeholder_len;
	}

	/* Allocate result buffer */
	char *result = malloc(new_len + 1);
	if (!result) return NULL;

	/* Perform substitutions */
	const char *src = input;
	char *dst = result;

	while ((current_pos = strstr(src, placeholder)) != NULL) {
		/* Copy text before placeholder */
		size_t prefix_len = current_pos - src;
		memcpy(dst, src, prefix_len);
		dst += prefix_len;

		/* Copy replacement value */
		memcpy(dst, value, value_len);
		dst += value_len;

		/* Move past placeholder */
		src = current_pos + placeholder_len;
	}

	/* Copy remaining text */
	strcpy(dst, src);

	return result;
}

/* Helper function to update command string with substitution */
static bool command_update(char **result, const char *placeholder, const char *value) {
	char *new_result = command_substitute(*result, placeholder, value);
	if (!new_result) return false;

	free(*result);
	*result = new_result;
	return true;
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
char *command_placeholders(monitor_t *monitor, const char *command, watchref_t watchref, const event_t *event) {
	char *result;
	char time_str[64];
	char user_str[64];
	char size_str[32];
	char *event_str;
	struct passwd *pwd;
	struct tm tm;
	struct stat info;

	const watch_t *watch = registry_get(monitor->registry, watchref);
	if (command == NULL || event == NULL || watch == NULL) {
		return NULL;
	}

	/* Start with a copy of the original command */
	result = strdup(command);
	if (result == NULL) {
		log_message(ERROR, "Failed to allocate memory for command");
		return NULL;
	}

	/* Substitute %p with the path */
	char *escaped_path = command_escape(event->path);
	if (escaped_path) {
		if (!command_update(&result, "%p", escaped_path)) {
			free(escaped_path);
			return NULL;
		}
		free(escaped_path);
	}

	/* Substitute %n with the filename/dirname */
	if (strstr(result, "%n")) {
		char *path_copy = strdup(event->path);
		if (path_copy) {
			char *escaped_basename = command_escape(basename(path_copy));
			if (escaped_basename) {
				if (!command_update(&result, "%n", escaped_basename)) {
					free(escaped_basename);
					free(path_copy);
					return NULL;
				}
				free(escaped_basename);
			}
			free(path_copy);
		}
	}

	/* Substitute %d with the directory */
	if (strstr(result, "%d")) {
		char *path_copy = strdup(event->path);
		if (path_copy) {
			char *escaped_dirname = command_escape(dirname(path_copy));
			if (escaped_dirname) {
				if (!command_update(&result, "%d", escaped_dirname)) {
					free(escaped_dirname);
					free(path_copy);
					return NULL;
				}
				free(escaped_dirname);
			}
			free(path_copy);
		}
	}

	/* Substitute %b with the base watch path */
	char *escaped_base_path = command_escape(watch->path);
	if (escaped_base_path) {
		if (!command_update(&result, "%b", escaped_base_path)) {
			free(escaped_base_path);
			return NULL;
		}
		free(escaped_base_path);
	}

	/* Substitute %w with the watch name */
	if (!command_update(&result, "%w", watch->name)) return NULL;

	/* Substitute %r with the relative path */
	if (strstr(result, "%r")) {
		const char *relative_path = event->path + strlen(watch->path);
		if (*relative_path == '/') {
			relative_path++;
		}
		char *escaped_relative = command_escape(relative_path);
		if (escaped_relative) {
			if (!command_update(&result, "%r", escaped_relative)) {
				free(escaped_relative);
				return NULL;
			}
			free(escaped_relative);
		}
	}

	/* Get subscription for size and trigger file placeholders */
	subscription_t *subscription = NULL;
	if (watchref_valid(watchref)) {
		subscription = resources_subscription(monitor->resources, monitor->registry, event->path, watchref, ENTITY_UNKNOWN);
	}

	/* Substitute %f and %F with trigger file path and name */
	if (strstr(result, "%f") || strstr(result, "%F")) {
		const char *trigger = event->path; /* Default to event path */
		if (subscription) {
			subscription_t *root = stability_root(monitor, subscription);
			if (root && root->trigger) {
				trigger = root->trigger;
			}
		}

		char *escaped_trigger = command_escape(trigger);
		if (escaped_trigger) {
			if (!command_update(&result, "%f", escaped_trigger)) {
				free(escaped_trigger);
				return NULL;
			}
			free(escaped_trigger);
		}

		if (strstr(result, "%F")) {
			char *path_copy = strdup(trigger);
			if (path_copy) {
				char *escaped_trigger_basename = command_escape(basename(path_copy));
				if (escaped_trigger_basename) {
					if (!command_update(&result, "%F", escaped_trigger_basename)) {
						free(escaped_trigger_basename);
						free(path_copy);
						return NULL;
					}
					free(escaped_trigger_basename);
				}
				free(path_copy);
			}
		}
	}

	/* Substitute %l with list of filenames (without paths) modified since processing began */
	if (strstr(result, "%l")) {
		if (watch->target == WATCH_DIRECTORY) {
			/* Use current event time with 1-second buffer to catch files modified around this event */
			time_t since_time = event->wall_time.tv_sec - 1;
			char *modified_files = scanner_modified(watch->path, since_time, watch->recursive, true);
			if (modified_files) {
				char *escaped_files = command_escape_list(modified_files);
				if (escaped_files) {
					if (!command_update(&result, "%l", escaped_files)) {
						free(escaped_files);
						free(modified_files);
						return NULL;
					}
					free(escaped_files);
				} else {
					if (!command_update(&result, "%l", "")) {
						free(modified_files);
						return NULL;
					}
				}
				free(modified_files);
			} else {
				if (!command_update(&result, "%l", "")) return NULL;
			}
		} else {
			/* For file watches, just use the file basename */
			char *basename_str = strrchr(event->path, '/');
			basename_str = basename_str ? basename_str + 1 : event->path;
			if (!command_update(&result, "%l", basename_str)) return NULL;
		}
	}

	/* Substitute %L with list of files modified since processing began */
	if (strstr(result, "%L")) {
		if (watch->target == WATCH_DIRECTORY) {
			/* Use current event time with 1-second buffer to catch files modified around this event */
			time_t since_time = event->wall_time.tv_sec - 1;
			char *modified_files = scanner_modified(watch->path, since_time, watch->recursive, false);
			if (modified_files) {
				char *escaped_files = command_escape_list(modified_files);
				if (escaped_files) {
					if (!command_update(&result, "%L", escaped_files)) {
						free(escaped_files);
						free(modified_files);
						return NULL;
					}
					free(escaped_files);
				} else {
					if (!command_update(&result, "%L", "")) {
						free(modified_files);
						return NULL;
					}
				}
				free(modified_files);
			} else {
				if (!command_update(&result, "%L", "")) return NULL;
			}
		} else {
			/* For file watches, use the full file path */
			char *escaped_path = command_escape(event->path);
			if (escaped_path) {
				if (!command_update(&result, "%L", escaped_path)) {
					free(escaped_path);
					return NULL;
				}
				free(escaped_path);
			} else {
				if (!command_update(&result, "%L", "")) return NULL;
			}
		}
	}

	/* Handle size placeholders %s and %S */
	if (strstr(result, "%s") || strstr(result, "%S")) {
		size_t size = 0;
		if (subscription && subscription->resource->kind == ENTITY_DIRECTORY) {
			subscription_t *size_subscription = stability_root(monitor, subscription);
			pthread_mutex_lock(&subscription->resource->mutex);
			size = size_subscription ? size_subscription->profile->stability->stats.tree_size : subscription->profile->stability->stats.tree_size;
			pthread_mutex_unlock(&subscription->resource->mutex);
		} else if (stat(event->path, &info) == 0) {
			size = info.st_size;
		}

		snprintf(size_str, sizeof(size_str), "%zu", size);
		if (!command_update(&result, "%s", size_str)) return NULL;
		if (!command_update(&result, "%S", format_size((ssize_t) size, false))) return NULL;
	}

	/* Substitute %t with the time */
	localtime_r(&event->wall_time.tv_sec, &tm);
	strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm);
	if (!command_update(&result, "%t", time_str)) return NULL;

	/* Substitute %u with the user */
	pwd = getpwuid(event->user_id);
	if (pwd != NULL) {
		snprintf(user_str, sizeof(user_str), "%s", pwd->pw_name);
	} else {
		snprintf(user_str, sizeof(user_str), "%d", event->user_id);
	}
	if (!command_update(&result, "%u", user_str)) return NULL;

	/* Substitute %e with the event type */
	event_str = (char *) filter_to_string(event->type);
	if (!command_update(&result, "%e", event_str)) return NULL;

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
bool command_execute(monitor_t *monitor, watchref_t watchref, const event_t *event, bool async) {
	const watch_t *watch = registry_get(monitor->registry, watchref);
	if (watch == NULL || event == NULL) {
		log_message(ERROR, "Invalid arguments to command_execute");
		return false;
	}

	/* For asynchronous execution, delegate to thread pool */
	if (async) {
		return threads_submit(command_threads, monitor, watchref, event);
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
	command = command_placeholders(monitor, watch->command, watchref, event);
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
			command_environment(monitor, watchref, event);
		}

		/* Execute the command */
		execl("/bin/sh", "sh", "-c", command, NULL);

		/* If we get here, exec failed */
		log_message(ERROR, "Failed to execute command: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Parent process - get a reference to the subscription for post-execution cleanup */
	subscription_t *subscription = NULL;
	if (watchref_valid(watchref)) {
		subscription = resources_subscription(monitor->resources, monitor->registry, event->path, watchref, ENTITY_UNKNOWN);
	}

	/* Read and log output if configured */
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
			if (stdout_open) FD_SET(stdout_pipe[0], &read_fds);
			if (stderr_open) FD_SET(stderr_pipe[0], &read_fds);

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
										log_message(WARNING, "[%s]: Failed to buffer output, switching to real-time", watch->name);
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

	/* Wait for child process to complete */
	int status;
	waitpid(pid, &status, 0);

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

	/* Clear command executing flag and reset baseline */
	if (subscription) {
		subscription_t *root = stability_root(monitor, subscription);
		resource_t *executing_resource = root ? root->resource : subscription->resource;
		struct timespec current_time;
		clock_gettime(CLOCK_MONOTONIC, &current_time);

		/* Update command time on the original subscription that triggered the event */
		subscription->command_time = current_time.tv_sec;

		if (executing_resource) {
			/* Clear executing flag on the root to allow new events for the entire watch */
			executing_resource->executing = false;
			/* Reset directory baseline to accept command result as new authoritative state */
			stability_reset(monitor, root ? root : subscription);

			/* Process next deferred event, if any */
			resource_lock(executing_resource);
			bool has_deferred = executing_resource->deferred_count > 0;
			resource_unlock(executing_resource);
			if (has_deferred) {
				events_deferred(monitor, executing_resource);
			}
		}
	}

	free(command);
	return true;
}

/* Set environment variables for command execution */
void command_environment(monitor_t *monitor, watchref_t watchref, const event_t *event) {
	const watch_t *watch = registry_get(monitor->registry, watchref);
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
	const char *trigger_file = event->path; /* Default to event path */
	subscription_t *subscription = NULL;
	if (watchref_valid(watchref)) {
		subscription = resources_subscription(monitor->resources, monitor->registry, event->path, watchref, ENTITY_UNKNOWN);
	}
	if (subscription) {
		subscription_t *root = stability_root(monitor, subscription);
		if (root && root->trigger) {
			trigger_file = root->trigger;
		}
	}
	setenv("KQ_TRIGGER_FILE_PATH", trigger_file, 1);

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
	if (watch->target == WATCH_DIRECTORY) {
		time_t since_time = event->wall_time.tv_sec - 1;
		char *modified_files = scanner_modified(watch->path, since_time, watch->recursive, true);
		if (modified_files) {
			setenv("KQ_MODIFIED_FILES", modified_files, 1);
			free(modified_files);
		}
	}
}

/* Clean up command subsystem */
void command_cleanup(threads_t *threads) {
	/* Wait for all pending commands to complete */
	threads_t *exec_threads = threads ? threads : command_threads;
	if (exec_threads) {
		/* Check if there are pending commands to wait for */
		pthread_mutex_lock(&exec_threads->queue_mutex);
		int pending_commands = exec_threads->queue_size + exec_threads->active_tasks;
		pthread_mutex_unlock(&exec_threads->queue_mutex);

		if (pending_commands > 0) {
			log_message(INFO, "Waiting for %d pending command%s to finish...",
						pending_commands, pending_commands == 1 ? "" : "s");
		}

		threads_wait(exec_threads);

		if (pending_commands > 0) {
			log_message(INFO, "All pending commands finished");
		}
	}

	/* If a specific thread pool is being cleaned up, clear the reference */
	if (threads != NULL) {
		command_threads = NULL;
	}
}
