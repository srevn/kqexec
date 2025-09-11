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

#include "binder.h"
#include "events.h"
#include "logger.h"
#include "resource.h"
#include "stability.h"
#include "threads.h"

/* Module-scoped threads reference */
static threads_t *command_threads = NULL;

/* Maximum length of command */
#define MAX_CMD_LEN 4096

/* Cooldown time in milliseconds */
static int cooldown_ms = DEFAULT_COOLDOWN_TIME_MS;

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

/* Set cooldown time */
void command_cooldown_time(int milliseconds) {
	if (milliseconds >= 0) {
		cooldown_ms = milliseconds;
		log_message(INFO, "Command cooldown time set to %d ms", cooldown_ms);
	}
}

/* Get cooldown time */
int command_get_cooldown_time(void) { return cooldown_ms; }

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

	/* Substitute placeholders in the command using binder module */
	binder_t *binder_ctx = binder_create(monitor, watchref, event);
	if (!binder_ctx) {
		log_message(ERROR, "Failed to create binder context");
		return false;
	}

	command = binder_placeholders(binder_ctx, watch->command);
	if (command == NULL) {
		binder_destroy(binder_ctx);
		return false;
	}

	log_message(INFO, "Executing command: %s", command);

	/* Create pipes for stdout and stderr if configured to capture output */
	if (capture_output) {
		if (pipe(stdout_pipe) < 0 || pipe(stderr_pipe) < 0) {
			log_message(ERROR, "Failed to create pipes: %s", strerror(errno));
			free(command);
			binder_destroy(binder_ctx);
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
		binder_destroy(binder_ctx);
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
			binder_environment(binder_ctx);
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
		ssize_t data_read;
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
				data_read = read(stdout_pipe[0], buffer, sizeof(buffer) - 1);

				if (data_read <= 0) {
					stdout_open = false;
				} else {
					buffer[data_read] = '\0';

					/* Process line by line */
					for (size_t i = 0; i < (size_t) data_read; i++) {
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
				data_read = read(stderr_pipe[0], buffer, sizeof(buffer) - 1);

				if (data_read <= 0) {
					stderr_open = false;
				} else {
					buffer[data_read] = '\0';
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
	log_message(INFO, "[%s] Finished execution (pid: %d, duration: %lds, exit: %d)",
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
			stability_reset(monitor, root ? root : subscription, event->baseline_snapshot);

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
	binder_destroy(binder_ctx);
	return true;
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
