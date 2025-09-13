#include "command.h"

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
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

/* Read only stderr for error logging with timeout and size limits */
static bool command_stderr(const watch_t *watch, int stderr_pipe[2]) {
	/* Close write end in parent */
	close(stderr_pipe[1]);

	fd_set read_fds;
	struct timeval timeout;
	char buffer[1024]; /* Smaller buffer for error messages */
	ssize_t bytes_read;
	size_t total_read = 0;
	const size_t MAX_STDERR_SIZE = 16384; /* 16KB limit for stderr */
	bool timed_out = false;

	while (total_read < MAX_STDERR_SIZE) {
		FD_ZERO(&read_fds);
		FD_SET(stderr_pipe[0], &read_fds);

		/* 5 second timeout to prevent hanging */
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;

		int select_result = select(stderr_pipe[0] + 1, &read_fds, NULL, NULL, &timeout);

		if (select_result < 0) {
			if (errno != EINTR) {
				log_message(WARNING, "[%s] select() on stderr failed: %s",
							watch->name, strerror(errno));
			}
			break;
		}

		if (select_result == 0) {
			/* Timeout - child may be hanging */
			log_message(WARNING, "[%s] stderr read timeout", watch->name);
			timed_out = true;
			break;
		}

		if (FD_ISSET(stderr_pipe[0], &read_fds)) {
			bytes_read = read(stderr_pipe[0], buffer, sizeof(buffer) - 1);
			if (bytes_read <= 0) {
				break; /* EOF or error */
			}

			total_read += bytes_read;
			buffer[bytes_read] = '\0';

			/* Split by lines and log each non-empty line */
			char *line_start = buffer;
			char *newline;

			while ((newline = strchr(line_start, '\n')) != NULL) {
				*newline = '\0';
				if (strlen(line_start) > 0) {
					log_message(WARNING, "[%s] stderr: %s", watch->name, line_start);
				}
				line_start = newline + 1;
			}

			/* Log remaining partial line if any */
			if (strlen(line_start) > 0) {
				log_message(WARNING, "[%s] stderr: %s", watch->name, line_start);
			}
		}
	}

	if (total_read >= MAX_STDERR_SIZE) {
		log_message(WARNING, "[%s] stderr output truncated (exceeded %zu bytes)",
					watch->name, MAX_STDERR_SIZE);
	}

	/* Close read end */
	close(stderr_pipe[0]);
	return !timed_out;
}

/* Read command output using select() */
static bool command_read(const watch_t *watch, int stdout_pipe[2], int stderr_pipe[2], output_t *buf) {
	/* Close write ends in parent */
	close(stdout_pipe[1]);
	close(stderr_pipe[1]);

	int max_fd = (stdout_pipe[0] > stderr_pipe[0]) ? stdout_pipe[0] : stderr_pipe[0];
	bool stdout_open = true, stderr_open = true;

	/* Variables for stderr limiting */
	size_t total_stderr_read = 0;
	const size_t MAX_STDERR_SIZE = 16384; /* 16KB limit for stderr */
	bool stderr_truncated = false;
	bool timed_out = false;

	while (stdout_open || stderr_open) {
		fd_set read_fds;
		FD_ZERO(&read_fds);

		if (stdout_open) FD_SET(stdout_pipe[0], &read_fds);
		if (stderr_open) FD_SET(stderr_pipe[0], &read_fds);

		struct timeval timeout;
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;

		int select_result = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
		if (select_result < 0) {
			if (errno != EINTR) {
				log_message(WARNING, "[%s] select() on output pipes failed: %s", watch->name,
							strerror(errno));
				break;
			}
			continue;
		}

		if (select_result == 0) {
			log_message(WARNING, "[%s] command read timeout", watch->name);
			timed_out = true;
			break;
		}

		/* Handle stdout - read raw chunks and append to buffer */
		if (stdout_open && FD_ISSET(stdout_pipe[0], &read_fds)) {
			char buffer[8192];
			ssize_t bytes_read = read(stdout_pipe[0], buffer, sizeof(buffer));
			if (bytes_read <= 0) {
				stdout_open = false;
			} else {
				if (!buffer_append(buf, buffer, bytes_read)) {
					log_message(WARNING, "[%s] stdout buffer limit reached, output truncated",
								watch->name);

					/* Set pipe to non-blocking to drain it without blocking */
					int flags = fcntl(stdout_pipe[0], F_GETFL, 0);
					if (flags != -1) {
						fcntl(stdout_pipe[0], F_SETFL, flags | O_NONBLOCK);
					}

					/* Keep reading to drain the pipe, but discard */
					char discard_buffer[1024];
					while (read(stdout_pipe[0], discard_buffer, sizeof(discard_buffer)) > 0);
					stdout_open = false;
				}
			}
		}

		/* Handle stderr - log immediately with size limit */
		if (stderr_open && FD_ISSET(stderr_pipe[0], &read_fds)) {
			char buffer[8192];
			ssize_t bytes_read = read(stderr_pipe[0], buffer, sizeof(buffer) - 1);
			if (bytes_read <= 0) {
				stderr_open = false;
			} else {
				total_stderr_read += bytes_read;
				if (total_stderr_read >= MAX_STDERR_SIZE && !stderr_truncated) {
					log_message(WARNING, "[%s] stderr output truncated (exceeded %zu bytes)",
								watch->name, MAX_STDERR_SIZE);
					stderr_truncated = true;
				}

				if (!stderr_truncated) {
					buffer[bytes_read] = '\0';
					char *line_start = buffer;
					char *newline;
					while ((newline = strchr(line_start, '\n')) != NULL) {
						*newline = '\0';
						if (strlen(line_start) > 0) {
							log_message(WARNING, "[%s] stderr: %s", watch->name, line_start);
						}
						line_start = newline + 1;
					}
					if (strlen(line_start) > 0) {
						log_message(WARNING, "[%s] stderr: %s", watch->name, line_start);
					}
				}
			}
		}
	}

	/* Close read ends */
	close(stdout_pipe[0]);
	close(stderr_pipe[0]);
	return !timed_out;
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

	/* Always create stderr pipe for error logging */
	if (pipe(stderr_pipe) < 0) {
		log_message(ERROR, "Failed to create stderr pipe: %s", strerror(errno));
		free(command);
		binder_destroy(binder_ctx);
		return false;
	}

	/* Create stdout pipe only if configured to capture output */
	if (capture_output) {
		if (pipe(stdout_pipe) < 0) {
			log_message(ERROR, "Failed to create stdout pipe: %s", strerror(errno));
			close(stderr_pipe[0]);
			close(stderr_pipe[1]);
			free(command);
			binder_destroy(binder_ctx);
			return false;
		}
	}

	/* Fork a child process */
	pid = fork();
	if (pid == -1) {
		log_message(ERROR, "Failed to fork: %s", strerror(errno));
		/* Always close stderr pipe */
		close(stderr_pipe[0]);
		close(stderr_pipe[1]);
		/* Close stdout pipe if it was created */
		if (capture_output) {
			close(stdout_pipe[0]);
			close(stdout_pipe[1]);
		}
		free(command);
		binder_destroy(binder_ctx);
		return false;
	}

	/* Child process */
	if (pid == 0) {
		/* Create a new process group to terminate the command and its children */
		if (setpgid(0, 0) < 0) {
			log_message(ERROR, "Failed to set new process group: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}

		/* Always redirect stderr to pipe for error logging */
		close(stderr_pipe[0]);
		dup2(stderr_pipe[1], STDERR_FILENO);
		close(stderr_pipe[1]);

		/* Handle stdout based on log_output setting */
		if (capture_output) {
			/* Redirect stdout to pipe for output logging */
			close(stdout_pipe[0]);
			dup2(stdout_pipe[1], STDOUT_FILENO);
			close(stdout_pipe[1]);
		} else {
			/* Suppress stdout by redirecting to /dev/null */
			int dev_null = open("/dev/null", O_WRONLY);
			if (dev_null >= 0) {
				dup2(dev_null, STDOUT_FILENO);
				close(dev_null);
			}
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

	/* Always read stderr for error logging, read stdout only if configured */
	bool read_ok;
	if (capture_output) {
		read_ok = command_read(watch, stdout_pipe, stderr_pipe, &output_buf);
	} else {
		/* Only read stderr for error logging when stdout capture is disabled */
		read_ok = command_stderr(watch, stderr_pipe);
	}

	/* If read timed out, the child process is unresponsive and must be killed */
	if (!read_ok) {
		log_message(ERROR, "[%s] Terminating unresponsive command (pid: %d)", watch->name, pid);
		kill(-pid, SIGKILL); /* Kill the entire process group */
	}

	/* Wait for child process to complete with proper signal handling */
	int status;
	pid_t wait_result;
	do {
		wait_result = waitpid(pid, &status, 0);
	} while (wait_result == -1 && errno == EINTR);

	if (wait_result == -1) {
		log_message(ERROR, "[%s] waitpid() failed: %s", watch->name, strerror(errno));
		status = -1; /* Mark as failed */
	}

	/* Record end time */
	time(&end_time);

	/* Flush buffered output */
	if (capture_output) {
		buffer_flush(watch, &output_buf);

		/* Clean up buffer */
		free(output_buf.data);
	}

	/* Log command completion with proper status interpretation */
	if (wait_result == -1) {
		log_message(INFO, "[%s] Finished execution (pid: %d, duration: %lds, wait failed)",
					watch->name, pid, end_time - start);
	} else if (WIFEXITED(status)) {
		log_message(INFO, "[%s] Finished execution (pid: %d, duration: %lds, exit: %d)",
					watch->name, pid, end_time - start, WEXITSTATUS(status));
	} else if (WIFSIGNALED(status)) {
		log_message(WARNING, "[%s] Killed by signal (pid: %d, duration: %lds, signal: %d)",
					watch->name, pid, end_time - start, WTERMSIG(status));
	} else {
		log_message(WARNING, "[%s] Abnormal termination (pid: %d, duration: %lds, status: %d)",
					watch->name, pid, end_time - start, status);
	}

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

	/* Return success only if command completed normally with exit code 0 */
	if (wait_result != -1 && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		return true;
	}
	return false;
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
