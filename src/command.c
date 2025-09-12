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
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "binder.h"
#include "events.h"
#include "logger.h"
#include "resource.h"
#include "stability.h"
#include "threads.h"

static threads_t *command_threads = NULL;		   /* Module-scoped threads reference */
static int cooldown_ms = DEFAULT_COOLDOWN_TIME_MS; /* Cooldown time in milliseconds */

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
void cooldown_set(int milliseconds) {
	if (milliseconds >= 0) {
		cooldown_ms = milliseconds;
		log_message(INFO, "Command cooldown time set to %d ms", cooldown_ms);
	}
}

/* Get cooldown time */
int cooldown_get(void) { return cooldown_ms; }

/* Append raw data to single output buffer */
static bool buffer_append(output_t *buf, const char *data, size_t len) {
	size_t needed = buf->used + len;

	/* Check memory limit */
	if (needed > MAX_BUFFER_SIZE) {
		buf->failed = true;
		return false;
	}

	/* Grow buffer if needed */
	if (needed > buf->capacity) {
		size_t new_capacity = buf->capacity ? buf->capacity * 2 : INITIAL_BUFFER_SIZE;
		while (new_capacity < needed) {
			new_capacity *= 2;
		}

		if (new_capacity > MAX_BUFFER_SIZE) {
			new_capacity = MAX_BUFFER_SIZE;
		}

		char *new_data = realloc(buf->data, new_capacity);
		if (!new_data) {
			buf->failed = true;
			return false;
		}

		buf->data = new_data;
		buf->capacity = new_capacity;
	}

	/* Append data */
	memcpy(buf->data + buf->used, data, len);
	buf->used = needed;

	return true;
}

/* Flush single buffer output line-by-line */
static void buffer_flush(const watch_t *watch, output_t *buf) {
	if (buf->used == 0) return;

	/* Ensure null termination for string functions */
	if (buf->used >= buf->capacity) {
		char *new_data = realloc(buf->data, buf->used + 1);
		if (!new_data) {
			log_message(ERROR, "Failed to reallocate buffer for logging");
			return;
		}
		buf->data = new_data;
		buf->capacity = buf->used + 1;
	}
	buf->data[buf->used] = '\0';

	char *start = buf->data;
	char *end;
	char *last_char = buf->data + buf->used;

	/* Process the buffer line by line */
	while (start < last_char && (end = strchr(start, '\n')) != NULL) {
		*end = '\0';
		log_message(NOTICE, "[%s]: %s", watch->name, start);
		start = end + 1;
	}

	/* Log any remaining part of the buffer that doesn't end with a newline */
	if (start < last_char) {
		log_message(NOTICE, "[%s]: %s", watch->name, start);
	}
}

/* Read command output using select() */
static void command_read(const watch_t *watch, int stdout_pipe[2], int stderr_pipe[2], output_t *buf) {
	/* Close write ends in parent */
	close(stdout_pipe[1]);
	close(stderr_pipe[1]);

	int max_fd = (stdout_pipe[0] > stderr_pipe[0]) ? stdout_pipe[0] : stderr_pipe[0];
	bool stdout_open = true, stderr_open = true;

	while (stdout_open || stderr_open) {
		fd_set read_fds;
		FD_ZERO(&read_fds);

		if (stdout_open) FD_SET(stdout_pipe[0], &read_fds);
		if (stderr_open) FD_SET(stderr_pipe[0], &read_fds);

		int select_result = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
		if (select_result <= 0) {
			if (select_result < 0 && errno != EINTR) {
				log_message(WARNING, "select() failed: %s", strerror(errno));
			}
			continue;
		}

		/* Handle stdout - read raw chunks and append to buffer */
		if (stdout_open && FD_ISSET(stdout_pipe[0], &read_fds)) {
			char buffer[8192];
			ssize_t bytes_read = read(stdout_pipe[0], buffer, sizeof(buffer));
			if (bytes_read <= 0) {
				stdout_open = false;
			} else {
				if (!buffer_append(buf, buffer, bytes_read)) {
					log_message(WARNING, "[%s] stdout buffer limit reached, output truncated", watch->name);
					/* Keep reading to drain the pipe, but discard */
					char discard_buffer[1024];
					while (read(stdout_pipe[0], discard_buffer, sizeof(discard_buffer)) > 0);
					stdout_open = false;
				}
			}
		}

		/* Handle stderr - log immediately */
		if (stderr_open && FD_ISSET(stderr_pipe[0], &read_fds)) {
			char buffer[8192];
			ssize_t bytes_read = read(stderr_pipe[0], buffer, sizeof(buffer) - 1);
			if (bytes_read <= 0) {
				stderr_open = false;
			} else {
				buffer[bytes_read] = '\0';
				log_message(WARNING, "[%s] stderr: %s", watch->name, buffer);
			}
		}
	}

	/* Close read ends */
	close(stdout_pipe[0]);
	close(stderr_pipe[0]);
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
	time_t start, end_time;

	/* Output buffering variables */
	output_t output_buf = {0};

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
		subscription = resources_subscription(monitor->resources,
											  monitor->registry, event->path, watchref, ENTITY_UNKNOWN);
	}

	/* Read and log output if configured */
	if (capture_output) {
		command_read(watch, stdout_pipe, stderr_pipe, &output_buf);
	}

	/* Wait for child process to complete */
	int status;
	waitpid(pid, &status, 0);

	/* Record end time */
	time(&end_time);

	/* Flush buffered output */
	if (capture_output) {
		buffer_flush(watch, &output_buf);

		/* Clean up buffer */
		free(output_buf.data);
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
