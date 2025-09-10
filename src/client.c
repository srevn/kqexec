#include "client.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "control.h"

/* Connect to the control server */
int client_connect(const char *socket_path) {
	if (!socket_path) {
		socket_path = DEFAULT_SOCKET;
	}

	int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock_fd == -1) {
		fprintf(stderr, "Error: Failed to create socket: %s\n", strerror(errno));
		return -1;
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

	if (connect(sock_fd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		int err = errno;
		close(sock_fd);

		/* Provide helpful error messages */
		switch (err) {
			case ENOENT:
				fprintf(stderr, "Error: kqexec daemon not running\n");
				break;
			case EACCES:
				fprintf(stderr, "Error: Permission denied accessing socket %s\n", socket_path);
				break;
			case ECONNREFUSED:
				fprintf(stderr, "Error: Daemon not accepting connections\n");
				break;
			default:
				fprintf(stderr, "Error: Cannot connect to daemon: %s\n", strerror(err));
		}
		return -1;
	}

	return sock_fd;
}

/* Send command to server */
bool client_send(int sock_fd, const char *command_text) {
	if (sock_fd < 0 || !command_text) return false;

	size_t command_length = strlen(command_text);
	size_t total_sent = 0;
	ssize_t data_sent;

	/* Handle partial writes and signal interruptions */
	while (total_sent < command_length) {
		data_sent = write(sock_fd, command_text + total_sent, command_length - total_sent);

		if (data_sent == -1) {
			if (errno == EINTR) {
				/* Interrupted by signal, retry */
				continue;
			} else {
				fprintf(stderr, "Error: Failed to send command: %s\n", strerror(errno));
				return false;
			}
		}

		total_sent += data_sent;
	}

	return true;
}

/* Receive response from server */
char *client_receive(int sock_fd) {
	if (sock_fd < 0) return NULL;

	size_t buffer_size = 4096;
	char *buffer = malloc(buffer_size);
	if (!buffer) {
		fprintf(stderr, "Error: Failed to allocate memory for response\n");
		return NULL;
	}

	size_t total_received = 0;
	ssize_t data_received;

	/* Read until we get double newline or connection closes */
	while (true) {
		/* Check if we need to grow the buffer */
		if (total_received >= buffer_size - 1) {
			size_t new_size = buffer_size * 2;
			char *new_buffer = realloc(buffer, new_size);
			if (!new_buffer) {
				fprintf(stderr, "Error: Failed to expand response buffer\n");
				free(buffer);
				return NULL;
			}
			buffer = new_buffer;
			buffer_size = new_size;
		}

		data_received = read(sock_fd, buffer + total_received, buffer_size - total_received - 1);

		if (data_received <= 0) {
			if (data_received == 0) {
				break; /* Connection closed */
			} else if (errno == EINTR) {
				/* Interrupted by signal, retry */
				continue;
			} else {
				fprintf(stderr, "Error: Failed to receive response: %s\n", strerror(errno));
				free(buffer);
				return NULL;
			}
		}

		total_received += data_received;
		buffer[total_received] = '\0';

		/* Check for end of response */
		if (strstr(buffer, "\n\n") != NULL) {
			break;
		}

		/* Safety check to prevent infinite growth */
		if (buffer_size > 1024 * 1024) { /* 1MB limit */
			fprintf(stderr, "Error: Response too large (>1MB)\n");
			free(buffer);
			return NULL;
		}
	}

	if (total_received == 0) {
		fprintf(stderr, "Error: No response received from daemon\n");
		free(buffer);
		return NULL;
	}

	return buffer;
}

/* Parse key-value data from response */
static char *client_value(const char *response, const char *key) {
	if (!response || !key) return NULL;

	size_t key_len = strlen(key);
	char search_key[256]; /* Stack allocated buffer for "key=" */
	snprintf(search_key, sizeof(search_key), "%s=", key);
	char *key_start = strstr(response, search_key);

	if (!key_start) return NULL;

	char *value_start = key_start + key_len + 1; /* Skip "key=" */
	char *value_end = strchr(value_start, '\n');
	if (!value_end) {
		value_end = value_start + strlen(value_start);
	}

	size_t value_len = value_end - value_start;
	char *value = malloc(value_len + 1);
	if (value) {
		memcpy(value, value_start, value_len);
		value[value_len] = '\0';
	}

	return value;
}

/* Display formatted list output */
static void client_list(const char *response) {
	char *watch_count_str = client_value(response, "watch_count");
	if (!watch_count_str) {
		printf("No watch count data found\n");
		return;
	}

	int watch_count = atoi(watch_count_str);
	free(watch_count_str);

	if (watch_count == 0) {
		printf("No watches configured\n");
		return;
	}

	/* Print header */
	printf("%-20s %-44s %-24s %s\n", "NAME", "PATH", "EVENTS", "STATUS");

	/* Print each watch */
	for (int i = 0; i < watch_count; i++) {
		char key_name[64], key_path[64], key_events[64], key_status[64];
		snprintf(key_name, sizeof(key_name), "watch_%d_name", i);
		snprintf(key_path, sizeof(key_path), "watch_%d_path", i);
		snprintf(key_events, sizeof(key_events), "watch_%d_events", i);
		snprintf(key_status, sizeof(key_status), "watch_%d_status", i);

		char *name = client_value(response, key_name);
		char *path = client_value(response, key_path);
		char *events = client_value(response, key_events);
		char *status = client_value(response, key_status);

		if (name && path && events && status) {
			/* Truncate long paths for display */
			char display_path[45] = {0};
			if (strlen(path) > 44) {
				const char *filename = strrchr(path, '/');
				if (filename && (strlen(path) - strlen(filename) < 40)) {
					snprintf(display_path, sizeof(display_path), "...%s", filename);
				} else {
					snprintf(display_path, sizeof(display_path), "%.41s...", path);
				}
			} else {
				strncpy(display_path, path, sizeof(display_path) - 1);
			}

			printf("%-20s %-44s %-24s %s\n", name, display_path, events, status);
		}

		free(name);
		free(path);
		free(events);
		free(status);
	}
}

/* Display formatted disable output */
static void client_disable(const char *response) {
	char *disabled_counter = client_value(response, "disabled_count");
	char *error_counter = client_value(response, "error_count");

	if (!disabled_counter || !error_counter) {
		printf("Incomplete disable data received\n");
		goto cleanup;
	}

	int disabled_count = atoi(disabled_counter);
	int error_count = atoi(error_counter);

	if (disabled_count > 0) {
		char *disabled_names = client_value(response, "disabled_names");
		if (disabled_names) {
			printf("Disabled %d watch%s: %s\n", disabled_count,
				   disabled_count == 1 ? "" : "es", disabled_names);
			free(disabled_names);
		} else {
			printf("Disabled %d watch%s\n", disabled_count,
				   disabled_count == 1 ? "" : "es");
		}
	}

	if (error_count > 0) {
		printf("Errors (%d):\n", error_count);
		for (int i = 0; i < error_count; i++) {
			char error_watch_key[64], error_msg_key[64];
			snprintf(error_watch_key, sizeof(error_watch_key), "error_%d_watch", i);
			snprintf(error_msg_key, sizeof(error_msg_key), "error_%d_message", i);

			char *watch_name = client_value(response, error_watch_key);
			char *error_msg = client_value(response, error_msg_key);

			if (watch_name && error_msg) {
				printf("  %s: %s\n", watch_name, error_msg);
			}

			free(watch_name);
			free(error_msg);
		}
	}

	if (disabled_count == 0 && error_count == 0) {
		printf("No watches were disabled\n");
	}

cleanup:
	free(disabled_counter);
	free(error_counter);
}

/* Display formatted enable output */
static void client_enable(const char *response) {
	char *enabled_counter = client_value(response, "enabled_count");
	char *error_counter = client_value(response, "error_count");

	if (!enabled_counter || !error_counter) {
		printf("Incomplete enable data received\n");
		goto cleanup;
	}

	int enabled_count = atoi(enabled_counter);
	int error_count = atoi(error_counter);

	if (enabled_count > 0) {
		char *enabled_names = client_value(response, "enabled_names");
		if (enabled_names) {
			printf("Enabled %d watch%s: %s\n", enabled_count,
				   enabled_count == 1 ? "" : "es", enabled_names);
			free(enabled_names);
		} else {
			printf("Enabled %d watch%s\n", enabled_count,
				   enabled_count == 1 ? "" : "es");
		}
	}

	if (error_count > 0) {
		printf("Errors (%d):\n", error_count);
		for (int i = 0; i < error_count; i++) {
			char error_watch_key[64], error_msg_key[64];
			snprintf(error_watch_key, sizeof(error_watch_key), "error_%d_watch", i);
			snprintf(error_msg_key, sizeof(error_msg_key), "error_%d_message", i);

			char *watch_name = client_value(response, error_watch_key);
			char *error_msg = client_value(response, error_msg_key);

			if (watch_name && error_msg) {
				printf("  %s: %s\n", watch_name, error_msg);
			}

			free(watch_name);
			free(error_msg);
		}
	}

	if (enabled_count == 0 && error_count == 0) {
		printf("No watches were enabled\n");
	}

cleanup:
	free(enabled_counter);
	free(error_counter);
}

/* Display formatted reload output */
static void client_reload(const char *response) {
	char *reload_requested = client_value(response, "reload_requested");

	if (reload_requested && strcmp(reload_requested, "true") == 0) {
		printf("Configuration reload requested\n");
	} else {
		printf("Reload operation completed\n");
	}

	free(reload_requested);
}

/* Display formatted suppress output */
static void client_suppress(const char *response) {
	char *watch_name = client_value(response, "watch_name");
	char *duration_ms = client_value(response, "duration_ms");

	if (watch_name && duration_ms) {
		printf("Watch '%s' suppressed for %s ms\n", watch_name, duration_ms);
	} else {
		printf("Suppress command sent\n");
	}

	free(watch_name);
	free(duration_ms);
}

/* Display formatted status output */
static void client_status(const char *response) {
	char *active_counter = client_value(response, "active_count");
	char *disabled_counter = client_value(response, "disabled_count");
	char *pending_counter = client_value(response, "pending_count");
	char *suppressed_counter = client_value(response, "suppressed_count");

	if (!active_counter || !disabled_counter || !pending_counter || !suppressed_counter) {
		printf("Incomplete status data received\n");
		goto cleanup;
	}

	int active_count = atoi(active_counter);
	int disabled_count = atoi(disabled_counter);
	int pending_count = atoi(pending_counter);
	int suppressed_count = atoi(suppressed_counter);

	printf("Watches: %d active, %d disabled, %d suppressed, %d pending",
		   active_count, disabled_count, suppressed_count, pending_count);

	if (active_count > 0) {
		char *active_names = client_value(response, "active_names");
		if (active_names) {
			printf("\nActive: %s", active_names);
			free(active_names);
		}
	}

	if (disabled_count > 0) {
		char *disabled_names = client_value(response, "disabled_names");
		if (disabled_names) {
			printf("\nDisabled: %s", disabled_names);
			free(disabled_names);
		}
	}

	if (suppressed_count > 0) {
		char *suppressed_names = client_value(response, "suppressed_names");
		if (suppressed_names) {
			printf("\nSuppressed: %s", suppressed_names);
			free(suppressed_names);
		}
	}

	if (pending_count > 0) {
		char *pending_paths = client_value(response, "pending_paths");
		if (pending_paths) {
			printf("\nPending: %s", pending_paths);
			free(pending_paths);
		}
	}

	printf("\n");

cleanup:
	free(active_counter);
	free(disabled_counter);
	free(pending_counter);
	free(suppressed_counter);
}

/* Display response to user */
void client_display(const char *response) {
	if (!response) {
		printf("No response received\n");
		return;
	}

	/* Use explicit response_type for robust protocol handling */
	char *response_type = client_value(response, "response_type");
	if (!response_type) {
		fprintf(stderr, "Error: Malformed response from daemon\n");
		/* For debugging, print the raw response */
		fprintf(stderr, "Raw response: %s\n", response);
		return;
	}

	if (strcmp(response_type, "list") == 0) {
		client_list(response);
	} else if (strcmp(response_type, "status") == 0) {
		client_status(response);
	} else if (strcmp(response_type, "disable") == 0) {
		client_disable(response);
	} else if (strcmp(response_type, "enable") == 0) {
		client_enable(response);
	} else if (strcmp(response_type, "reload") == 0) {
		client_reload(response);
	} else if (strcmp(response_type, "suppress") == 0) {
		client_suppress(response);
	} else if (strcmp(response_type, "error") == 0) {
		char *message = client_value(response, "message");
		if (message) {
			fprintf(stderr, "Error: %s\n", message);
			free(message);
		} else {
			fprintf(stderr, "Error: Received unspecified error from daemon\n");
		}
	} else {
		fprintf(stderr, "Error: Unknown response type from daemon: %s\n", response_type);
	}

	free(response_type);
}

/* Build command string from options */
char *client_build(options_t *options) {
	if (!options) return NULL;

	size_t buffer_size = 0;
	const char *command_str = NULL;
	char *suppressed_name = NULL;
	char *suppressed_duration = NULL;
	char *arg_copy = NULL;

	/* Pre-parse arguments for commands with special formats */
	if (options->command == CMD_SUPPRESS) {
		if (options->suppress) {
			arg_copy = strdup(options->suppress);
			if (!arg_copy) {
				fprintf(stderr, "Error: Failed to allocate memory for command arguments\n");
				return NULL;
			}
			char *colon = strrchr(arg_copy, ':');
			if (colon && colon != arg_copy && *(colon + 1) != '\0') {
				*colon = '\0';
				suppressed_name = arg_copy;
				suppressed_duration = colon + 1;
			} else {
				fprintf(stderr, "Error: Invalid format, use WATCH_NAME:DURATION\n");
				free(arg_copy);
				return NULL;
			}
		} else {
			fprintf(stderr, "Error: --suppress command requires an argument\n");
			return NULL;
		}
	}

	/* Determine base command string */
	switch (options->command) {
		case CMD_DISABLE:
			command_str = "command=disable\n";
			break;
		case CMD_ENABLE:
			command_str = "command=enable\n";
			break;
		case CMD_STATUS:
			command_str = "command=status\n";
			break;
		case CMD_LIST:
			command_str = "command=list\n";
			break;
		case CMD_RELOAD:
			command_str = "command=reload\n";
			break;
		case CMD_SUPPRESS:
			command_str = "command=suppress\n";
			break;
		default:
			if (arg_copy) free(arg_copy);
			return NULL;
	}
	buffer_size += strlen(command_str);

	/* Calculate size for watch names (for disable/enable) */
	if (options->watch_names && options->num_watches > 0) {
		buffer_size += strlen("watches=");
		for (int i = 0; i < options->num_watches; i++) {
			if (options->watch_names[i]) {
				buffer_size += strlen(options->watch_names[i]);
				if (i < options->num_watches - 1) {
					buffer_size += 1; /* For comma */
				}
			}
		}
		buffer_size += 1; /* For newline */
	}

	/* Calculate size for suppress argument */
	if (suppressed_name && suppressed_duration) {
		buffer_size += strlen("watch=") + strlen(suppressed_name) + 1;
		buffer_size += strlen("duration=") + strlen(suppressed_duration) + 1;
	}

	buffer_size += 2; /* For final \n\n terminator */

	/* Allocate exact buffer size + null terminator */
	char *command = malloc(buffer_size + 1);
	if (!command) {
		fprintf(stderr, "Error: Failed to allocate memory for command\n");
		if (arg_copy) free(arg_copy);
		return NULL;
	}

	/* Build the command string */
	int written = snprintf(command, buffer_size + 1, "%s", command_str);

	if (options->watch_names && options->num_watches > 0) {
		written += snprintf(command + written, buffer_size + 1 - written, "watches=");
		for (int i = 0; i < options->num_watches; i++) {
			if (options->watch_names[i]) {
				written += snprintf(command + written, buffer_size + 1 - written, "%s", options->watch_names[i]);
				if (i < options->num_watches - 1) {
					written += snprintf(command + written, buffer_size + 1 - written, ",");
				}
			}
		}
		snprintf(command + written, buffer_size + 1 - written, "\n");
	}

	if (suppressed_name && suppressed_duration) {
		written += snprintf(command + written, buffer_size + 1 - written, "watch=%s\n", suppressed_name);
		snprintf(command + written, buffer_size + 1 - written, "duration=%s\n", suppressed_duration);
	}

	if (arg_copy) free(arg_copy);

	strcat(command, "\n");

	return command;
}

/* Parse comma-separated watch list */
char **client_parse(const char *watch_list) {
	if (!watch_list) return NULL;

	/* Count number of watches */
	int count = 1;
	for (const char *p = watch_list; *p; p++) {
		if (*p == ',') count++;
	}

	char **watches = calloc(count + 1, sizeof(char *)); /* +1 for NULL terminator */
	if (!watches) return NULL;

	char *list_copy = strdup(watch_list);
	if (!list_copy) {
		free(watches);
		return NULL;
	}

	int i = 0;
	char *token;
	char *rest = list_copy;
	while ((token = strtok_r(rest, ",", &rest)) && i < count) {
		/* Trim whitespace */
		while (*token == ' ' || *token == '\t') token++;
		char *end = token + strlen(token) - 1;
		while (end > token && (*end == ' ' || *end == '\t')) *end-- = '\0';

		watches[i++] = strdup(token);
	}

	free(list_copy);
	return watches;
}

/* Clean up client options */
void client_cleanup(options_t *options) {
	if (!options) return;

	if (options->watch_names) {
		for (int i = 0; i < options->num_watches; i++) {
			free(options->watch_names[i]);
		}
		free(options->watch_names);
	}

	free(options->suppress);
	free(options->socket_path);
	memset(options, 0, sizeof(options_t));
}

/* Client mode entry point */
int client_main(options_t *options) {
	if (!options) {
		fprintf(stderr, "Error: Invalid client options\n");
		return EXIT_FAILURE;
	}

	/* Connect to daemon */
	int sock_fd = client_connect(options->socket_path);
	if (sock_fd < 0) {
		return EXIT_FAILURE;
	}

	/* Build and send command */
	char *command = client_build(options);
	if (!command) {
		fprintf(stderr, "Error: Failed to build command\n");
		close(sock_fd);
		return EXIT_FAILURE;
	}

	if (!client_send(sock_fd, command)) {
		free(command);
		close(sock_fd);
		return EXIT_FAILURE;
	}

	free(command);

	/* Receive and display response */
	char *response = client_receive(sock_fd);
	int exit_code = EXIT_SUCCESS;

	if (response) {
		client_display(response);

		/* Check response status for exit code */
		if (strstr(response, "status=error") != NULL) {
			exit_code = EXIT_FAILURE;
		}

		free(response);
	} else {
		exit_code = EXIT_FAILURE;
	}

	close(sock_fd);
	return exit_code;
}
