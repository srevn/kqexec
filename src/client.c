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

	size_t command_len = strlen(command_text);

	/* Add double newline terminator if not present */
	char *full_command;
	if (strstr(command_text, "\n\n") == NULL) {
		full_command = malloc(command_len + 3);
		if (!full_command) {
			fprintf(stderr, "Error: Failed to allocate memory for command\n");
			return false;
		}
		strcpy(full_command, command_text);
		strcat(full_command, "\n\n");
	} else {
		full_command = strdup(command_text);
		if (!full_command) {
			fprintf(stderr, "Error: Failed to allocate memory for command\n");
			return false;
		}
	}

	size_t command_length = strlen(full_command);
	size_t total_sent = 0;
	ssize_t data_sent;

	/* Handle partial writes and signal interruptions */
	while (total_sent < command_length) {
		data_sent = write(sock_fd, full_command + total_sent, command_length - total_sent);

		if (data_sent == -1) {
			if (errno == EINTR) {
				/* Interrupted by signal, retry */
				continue;
			} else {
				fprintf(stderr, "Error: Failed to send command: %s\n", strerror(errno));
				free(full_command);
				return false;
			}
		}

		total_sent += data_sent;
	}

	free(full_command);
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

/* Display response to user */
void client_display(const char *response) {
	if (!response) {
		printf("No response received\n");
		return;
	}

	char *response_copy = strdup(response);
	if (!response_copy) return;

	char *line = strtok(response_copy, "\n");
	bool is_success = false;

	/* Parse first line to check status */
	if (line && strncmp(line, "status=", 7) == 0) {
		is_success = strcmp(line + 7, "success") == 0;
	}

	/* Display all lines */
	line = strtok(NULL, "\n");
	while (line) {
		if (strncmp(line, "message=", 8) == 0) {
			if (is_success) {
				printf("%s\n", line + 8);
			} else {
				fprintf(stderr, "%s\n", line + 8);
			}
		} else if (strchr(line, '=') != NULL) {
			/* Display other key=value pairs */
			printf("%s\n", line);
		}
		line = strtok(NULL, "\n");
	}

	free(response_copy);
}

/* Build command string from options */
char *client_build(options_t *options) {
	if (!options) return NULL;

	/* Calculate required buffer size */
	size_t buffer_size = 50; /* Base size for "command=disable\n" etc. */

	if (options->watch_names && options->num_watches > 0) {
		buffer_size += 10; /* "watches=" */
		for (int i = 0; i < options->num_watches; i++) {
			if (options->watch_names[i]) {
				buffer_size += strlen(options->watch_names[i]);
				if (i > 0) buffer_size += 1; /* comma */
			}
		}
		buffer_size += 1; /* newline */
	}

	buffer_size += 10; /* Safety margin */

	char *command = malloc(buffer_size);
	if (!command) return NULL;

	int written = 0;

	/* Add command type */
	switch (options->command) {
		case CMD_DISABLE:
			written = snprintf(command, buffer_size, "command=disable\n");
			break;
		case CMD_ENABLE:
			written = snprintf(command, buffer_size, "command=enable\n");
			break;
		case CMD_STATUS:
			written = snprintf(command, buffer_size, "command=status\n");
			break;
		case CMD_LIST:
			written = snprintf(command, buffer_size, "command=list\n");
			break;
		case CMD_RELOAD:
			written = snprintf(command, buffer_size, "command=reload\n");
			break;
		default:
			free(command);
			return NULL;
	}

	/* Add watch names if specified */
	if (options->watch_names && options->num_watches > 0) {
		written += snprintf(command + written, buffer_size - written, "watches=");

		for (int i = 0; i < options->num_watches; i++) {
			if (i > 0) {
				written += snprintf(command + written, buffer_size - written, ",");
			}
			written += snprintf(command + written, buffer_size - written, "%s", options->watch_names[i]);

			/* Check for buffer overflow */
			if (written >= (int) buffer_size - 10) {
				fprintf(stderr, "Error: Command too long for buffer\n");
				free(command);
				return NULL;
			}
		}
		written += snprintf(command + written, buffer_size - written, "\n");
	}

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
	char *token = strtok(list_copy, ",");
	while (token && i < count) {
		/* Trim whitespace */
		while (*token == ' ' || *token == '\t') token++;
		char *end = token + strlen(token) - 1;
		while (end > token && (*end == ' ' || *end == '\t')) *end-- = '\0';

		watches[i++] = strdup(token);
		token = strtok(NULL, ",");
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
	if (response) {
		client_display(response);
		free(response);
	}

	close(sock_fd);
	return EXIT_SUCCESS;
}
