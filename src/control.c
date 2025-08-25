#include "control.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "logger.h"
#include "monitor.h"

/* Create a new control server */
server_t *server_create(const char *socket_path) {
	if (!socket_path) {
		socket_path = DEFAULT_SOCKET;
	}

	server_t *server = calloc(1, sizeof(server_t));
	if (!server) {
		log_message(ERROR, "Failed to allocate memory for control server");
		return NULL;
	}

	/* Create Unix domain socket */
	server->socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (server->socket_fd == -1) {
		log_message(ERROR, "Failed to create Unix socket: %s", strerror(errno));
		free(server);
		return NULL;
	}

	/* Set socket to non-blocking mode */
	int flags = fcntl(server->socket_fd, F_GETFL, 0);
	if (flags == -1 || fcntl(server->socket_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		log_message(ERROR, "Failed to set socket non-blocking: %s", strerror(errno));
		close(server->socket_fd);
		free(server);
		return NULL;
	}

	/* Setup socket address */
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

	/* Remove existing socket file if it exists */
	unlink(socket_path);

	/* Bind socket */
	if (bind(server->socket_fd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		log_message(ERROR, "Failed to bind Unix socket to %s: %s", socket_path, strerror(errno));
		close(server->socket_fd);
		free(server);
		return NULL;
	}

	/* Listen for connections */
	if (listen(server->socket_fd, SOMAXCONN) == -1) {
		log_message(ERROR, "Failed to listen on Unix socket: %s", strerror(errno));
		close(server->socket_fd);
		unlink(socket_path);
		free(server);
		return NULL;
	}

	/* Set socket file permissions (readable/writable by owner and group) */
	if (chmod(socket_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) == -1) {
		log_message(WARNING, "Failed to set socket permissions: %s", strerror(errno));
	}

	server->socket_path = strdup(socket_path);
	server->max_clients = MAX_CLIENTS;
	server->num_clients = 0;
	server->running = false;

	/* Allocate client array */
	server->clients = calloc(server->max_clients, sizeof(client_t *));
	if (!server->clients) {
		log_message(ERROR, "Failed to allocate memory for client array");
		close(server->socket_fd);
		unlink(socket_path);
		free(server->socket_path);
		free(server);
		return NULL;
	}

	log_message(INFO, "Control server created on socket: %s", socket_path);
	return server;
}

/* Destroy control server and cleanup resources */
void server_destroy(server_t *server) {
	if (!server) return;

	server->running = false;

	/* Close all client connections */
	for (int i = 0; i < server->num_clients; i++) {
		if (server->clients[i]) {
			close(server->clients[i]->fd);
			free(server->clients[i]->write_buffer);
			free(server->clients[i]);
		}
	}

	/* Close server socket */
	if (server->socket_fd >= 0) {
		close(server->socket_fd);
	}

	/* Remove socket file */
	if (server->socket_path) {
		unlink(server->socket_path);
		free(server->socket_path);
	}

	free(server->clients);
	free(server);
	log_message(INFO, "Control server destroyed");
}

/* Start the control server and register with kqueue */
bool server_start(server_t *server, int kqueue_fd) {
	if (!server || kqueue_fd < 0) return false;

	/* Register server socket with kqueue for read events */
	struct kevent change;
	EV_SET(&change, server->socket_fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, server);

	if (kevent(kqueue_fd, &change, 1, NULL, 0, NULL) == -1) {
		log_message(ERROR, "Failed to register control server socket with kqueue: %s", strerror(errno));
		return false;
	}

	server->running = true;
	log_message(INFO, "Control server started and registered with kqueue");
	return true;
}

/* Stop the control server */
void server_stop(server_t *server) {
	if (!server) return;
	server->running = false;
	log_message(INFO, "Control server stopped");
}

/* Accept a new client connection */
void control_accept(server_t *server, int kqueue_fd) {
	if (!server || !server->running || kqueue_fd < 0) return;

	struct sockaddr_un client_addr;
	socklen_t client_len = sizeof(client_addr);

	int client_fd = accept(server->socket_fd, (struct sockaddr *) &client_addr, &client_len);
	if (client_fd == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			log_message(WARNING, "Failed to accept client connection: %s", strerror(errno));
		}
		return;
	}

	/* Check client limit */
	if (server->num_clients >= server->max_clients) {
		log_message(WARNING, "Too many clients connected (%d), rejecting connection", server->num_clients);
		close(client_fd);
		return;
	}

	/* Set client socket to non-blocking */
	int flags = fcntl(client_fd, F_GETFL, 0);
	if (flags == -1 || fcntl(client_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		log_message(WARNING, "Failed to set client socket non-blocking: %s", strerror(errno));
		close(client_fd);
		return;
	}

	/* Create client structure */
	client_t *client = calloc(1, sizeof(client_t));
	if (!client) {
		log_message(ERROR, "Failed to allocate memory for client");
		close(client_fd);
		return;
	}

	client->fd = client_fd;
	client->buffer_pos = 0;
	client->addr = client_addr;
	client->write_buffer = NULL;
	client->write_size = 0;
	client->write_pos = 0;

	/* Add client to array */
	server->clients[server->num_clients++] = client;

	/* Register client socket with kqueue for read events */
	struct kevent change;
	EV_SET(&change, client_fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, client);

	if (kevent(kqueue_fd, &change, 1, NULL, 0, NULL) == -1) {
		log_message(WARNING, "Failed to register client socket with kqueue: %s", strerror(errno));
		/* Remove the client we just added */
		server->num_clients--;
		close(client_fd);
		free(client);
		return;
	}

	log_message(DEBUG, "Accepted control client connection (fd %d), total clients: %d",
				client_fd, server->num_clients);
}

/* Remove a client from the server */
void control_remove(server_t *server, int client_fd, int kqueue_fd) {
	if (!server) return;

	for (int i = 0; i < server->num_clients; i++) {
		if (server->clients[i] && server->clients[i]->fd == client_fd) {
			/* Unregister from kqueue */
			if (kqueue_fd >= 0) {
				struct kevent change;
				EV_SET(&change, client_fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
				if (kevent(kqueue_fd, &change, 1, NULL, 0, NULL) == -1) {
					log_message(DEBUG, "Failed to unregister client socket: %s", strerror(errno));
				}
			}

			close(server->clients[i]->fd);
			free(server->clients[i]->write_buffer);
			free(server->clients[i]);

			/* Shift remaining clients down */
			for (int j = i; j < server->num_clients - 1; j++) {
				server->clients[j] = server->clients[j + 1];
			}

			server->num_clients--;
			server->clients[server->num_clients] = NULL;

			log_message(DEBUG, "Removed client (fd %d), remaining clients: %d", client_fd,
						server->num_clients);
			break;
		}
	}
}

/* Check if a kevent is from a control client */
bool control_event(server_t *server, struct kevent *event) {
	if (!server || !event) return false;

	for (int i = 0; i < server->num_clients; i++) {
		if (server->clients[i] && server->clients[i]->fd == (int) event->ident) {
			return true;
		}
	}
	return false;
}

/* Handle client event (data ready to read) */
void control_handle(monitor_t *monitor, struct kevent *event) {
	if (!monitor || !event) return;

	server_t *server = monitor->server;
	if (!server) return;

	int client_fd = (int) event->ident;
	client_t *client = NULL;

	/* Find the client */
	for (int i = 0; i < server->num_clients; i++) {
		if (server->clients[i] && server->clients[i]->fd == client_fd) {
			client = server->clients[i];
			break;
		}
	}

	if (!client) {
		log_message(WARNING, "Received event for unknown client fd %d", client_fd);
		return;
	}

	/* Handle client disconnection */
	if (event->flags & EV_EOF || event->data == 0) {
		log_message(DEBUG, "Client (fd %d) disconnected", client_fd);
		control_remove(server, client_fd, monitor->kq);
		return;
	}

	/* Read data from client */
	ssize_t data_read = read(client_fd, client->buffer + client->buffer_pos,
							 BUFFER_SIZE - client->buffer_pos - 1);

	if (data_read <= 0) {
		if (data_read == 0 || (data_read == -1 && errno != EAGAIN && errno != EWOULDBLOCK)) {
			log_message(DEBUG, "Client (fd %d) closed connection or error occurred: %s",
						client_fd, strerror(errno));
			control_remove(server, client_fd, monitor->kq);
		}
		return;
	}

	client->buffer_pos += data_read;
	client->buffer[client->buffer_pos] = '\0';

	/* Look for complete command (ends with double newline) */
	char *end_marker = strstr(client->buffer, "\n\n");
	if (end_marker) {
		*end_marker = '\0'; /* Terminate command string */

		/* Process the command */
		result_t result = control_process(monitor, client->buffer);
		char *response = control_format(&result);

		if (response) {
			/* Send response to client using buffered approach */
			if (!control_send(monitor, client, response)) {
				log_message(WARNING, "Failed to send response to client (fd %d)", client_fd);
				control_remove(server, client_fd, monitor->kq);
				free(response);
				control_cleanup(&result);
				return;
			}
			free(response);
		}

		control_cleanup(&result);

		/* Reset buffer for next command */
		client->buffer_pos = 0;
		client->buffer[0] = '\0';
	} else if (client->buffer_pos >= BUFFER_SIZE - 1) {
		/* Buffer overflow, disconnect client */
		log_message(WARNING, "Client (fd %d) buffer overflow: %zu data attempted, max %d data allowed",
					client_fd, client->buffer_pos, BUFFER_SIZE - 1);
		control_remove(server, client_fd, monitor->kq);
	}
}

/* Send response to client with write buffering */
bool control_send(monitor_t *monitor, client_t *client, const char *response) {
	if (!monitor || !client || !response) return false;

	size_t response_len = strlen(response);

	/* If no pending data, try direct write first */
	if (!client->write_buffer) {
		ssize_t data_sent = write(client->fd, response, response_len);

		if (data_sent == (ssize_t) response_len) {
			/* Complete write successful */
			return true;
		}

		if (data_sent < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				data_sent = 0; /* Treat as partial write of 0 bytes */
			} else {
				/* Real error occurred */
				return false;
			}
		}

		/* Partial write occurred, buffer the remaining data */
		size_t remaining = response_len - data_sent;
		client->write_buffer = malloc(remaining);
		if (!client->write_buffer) return false;

		memcpy(client->write_buffer, response + data_sent, remaining);
		client->write_size = remaining;
		client->write_pos = 0;

		/* Register for write events */
		struct kevent change;
		EV_SET(&change, client->fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, client);
		if (kevent(monitor->kq, &change, 1, NULL, 0, NULL) == -1) {
			log_message(WARNING, "Failed to register for write events: %s", strerror(errno));
			free(client->write_buffer);
			client->write_buffer = NULL;
			return false;
		}

		return true;
	} else {
		/* Already have pending data, append to buffer */
		size_t new_size = client->write_size + response_len;
		char *new_buffer = realloc(client->write_buffer, new_size);
		if (!new_buffer) return false;

		memcpy(new_buffer + client->write_size, response, response_len);
		client->write_buffer = new_buffer;
		client->write_size = new_size;

		return true;
	}
}

/* Handle pending writes for a client */
bool control_pending(monitor_t *monitor, client_t *client) {
	if (!monitor || !client || !client->write_buffer) return false;

	size_t remaining = client->write_size - client->write_pos;
	ssize_t data_sent = write(client->fd, client->write_buffer + client->write_pos, remaining);

	if (data_sent <= 0) {
		if (data_sent == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
			/* Connection closed or error */
			return false;
		}
		/* Would block, try again later */
		return true;
	}

	client->write_pos += data_sent;

	/* Check if all data has been sent */
	if (client->write_pos >= client->write_size) {
		/* All data sent, cleanup and unregister write events */
		free(client->write_buffer);
		client->write_buffer = NULL;
		client->write_size = 0;
		client->write_pos = 0;

		struct kevent change;
		EV_SET(&change, client->fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
		if (kevent(monitor->kq, &change, 1, NULL, 0, NULL) == -1) {
			log_message(DEBUG, "Failed to unregister write events: %s", strerror(errno));
		}
	}

	return true;
}

/* Handle write events for clients */
void control_write(monitor_t *monitor, struct kevent *event) {
	if (!monitor || !event) return;

	server_t *server = monitor->server;
	if (!server) return;

	int client_fd = (int) event->ident;
	client_t *client = NULL;

	/* Find the client */
	for (int i = 0; i < server->num_clients; i++) {
		if (server->clients[i] && server->clients[i]->fd == client_fd) {
			client = server->clients[i];
			break;
		}
	}

	if (!client) {
		log_message(WARNING, "Received write event for unknown client fd %d", client_fd);
		return;
	}

	/* Handle the pending write */
	if (!control_pending(monitor, client)) {
		log_message(DEBUG, "Client (fd %d) write failed, disconnecting", client_fd);
		control_remove(server, client_fd, monitor->kq);
	}
}

/* Initialize command result structure */
static void control_result(result_t *result) {
	memset(result, 0, sizeof(result_t));
}

/* Clean up command result structure */
void control_cleanup(result_t *result) {
	if (!result) return;

	free(result->message);

	for (int i = 0; i < result->data_count; i++) {
		free(result->data_keys[i]);
		free(result->data_values[i]);
	}
	free(result->data_keys);
	free(result->data_values);

	memset(result, 0, sizeof(result_t));
}

/* Parse a key=value line */
bool kv_parse(const char *line, char **key, char **value) {
	if (!line || !key || !value) return false;

	*key = NULL;
	*value = NULL;

	char *equals = strchr(line, '=');
	if (!equals) return false;

	size_t key_len = equals - line;
	*key = malloc(key_len + 1);
	if (!*key) return false;

	strncpy(*key, line, key_len);
	(*key)[key_len] = '\0';

	*value = strdup(equals + 1);
	if (!*value) {
		free(*key);
		*key = NULL;
		return false;
	}

	return true;
}

/* Get value for a specific key from KV text */
char *kv_value(const char *text, const char *key) {
	if (!text || !key) return NULL;

	char *text_copy = strdup(text);
	if (!text_copy) return NULL;

	char *line = strtok(text_copy, "\n");
	while (line) {
		char *line_key, *line_value;
		if (kv_parse(line, &line_key, &line_value)) {
			if (strcmp(line_key, key) == 0) {
				free(line_key);
				free(text_copy);
				return line_value;
			}
			free(line_key);
			free(line_value);
		}
		line = strtok(NULL, "\n");
	}

	free(text_copy);
	return NULL;
}

/* Split comma-separated values */
char **kv_split(const char *value, const char *delimiter, int *count) {
	if (!value || !delimiter || !count) return NULL;

	*count = 0;

	/* Count occurrences */
	int delim_count = 1;
	const char *p = value;
	while ((p = strstr(p, delimiter)) != NULL) {
		delim_count++;
		p += strlen(delimiter);
	}

	char **result = malloc(delim_count * sizeof(char *));
	if (!result) return NULL;

	char *value_copy = strdup(value);
	if (!value_copy) {
		free(result);
		return NULL;
	}

	char *token = strtok(value_copy, delimiter);
	while (token && *count < delim_count) {
		/* Trim whitespace */
		while (*token == ' ' || *token == '\t') token++;
		char *end = token + strlen(token) - 1;
		while (end > token && (*end == ' ' || *end == '\t')) *end-- = '\0';

		result[(*count)++] = strdup(token);
		token = strtok(NULL, delimiter);
	}

	free(value_copy);
	return result;
}

/* Process disable command */
static result_t process_disable(monitor_t *monitor, const char *command_text) {
	result_t result;
	control_result(&result);

	char *watches_value = kv_value(command_text, "watches");

	if (watches_value) {
		/* Disable specific watches */
		int count = 0;
		char **watch_names = kv_split(watches_value, ",", &count);

		int disabled_count = 0;
		for (int i = 0; i < count; i++) {
			/* Find the watch by name in the registry */
			uint32_t num_watches = 0;
			watchref_t *watchrefs = registry_active(monitor->registry, &num_watches);

			bool found = false;
			for (uint32_t j = 0; j < num_watches; j++) {
				watch_t *watch = registry_get(monitor->registry, watchrefs[j]);
				if (watch && watch->name && strcmp(watch->name, watch_names[i]) == 0) {
					if (monitor_deactivate(monitor, watchrefs[j])) {
						disabled_count++;
					}
					found = true;
					break;
				}
			}

			if (!found) {
				log_message(WARNING, "Watch '%s' not found for disable command", watch_names[i]);
			}

			free(watchrefs);
			free(watch_names[i]);
		}
		free(watch_names);

		result.success = true;
		result.message = malloc(128);
		if (result.message) {
			snprintf(result.message, 128, "Disabled %d watches", disabled_count);
		}
	} else {
		result.success = false;
		result.message = strdup("Missing 'watches' parameter for disable command");
	}

	free(watches_value);
	return result;
}

/* Process enable command */
static result_t process_enable(monitor_t *monitor, const char *command_text) {
	result_t result;
	control_result(&result);

	char *watches_value = kv_value(command_text, "watches");

	if (watches_value) {
		/* Enable specific watches */
		int count = 0;
		char **watch_names = kv_split(watches_value, ",", &count);

		int enabled_count = 0;
		for (int i = 0; i < count; i++) {
			/* Find the watch by name regardless of state */
			watchref_t watchref = registry_find(monitor->registry, watch_names[i]);

			if (monitor_activate(monitor, watchref)) {
				enabled_count++;
			} else {
				log_message(WARNING, "Watch '%s' not found or failed to enable", watch_names[i]);
			}

			free(watch_names[i]);
		}
		free(watch_names);

		result.success = true;
		result.message = malloc(128);
		if (result.message) {
			snprintf(result.message, 128, "Enabled %d watches", enabled_count);
		}
	} else {
		result.success = false;
		result.message = strdup("Missing 'watches' parameter for enable command");
	}

	free(watches_value);
	return result;
}

/* Process status command */
static result_t process_status(monitor_t *monitor, const char *command_text) {
	result_t result;
	control_result(&result);

	(void) command_text; /* Unused parameter */

	result.success = true;

	/* Count disabled watches by iterating through the registry */
	uint32_t num_watches = 0;
	watchref_t *watchrefs = registry_active(monitor->registry, &num_watches);

	int disabled_count = 0;
	for (uint32_t i = 0; i < num_watches; i++) {
		watch_t *watch = registry_get(monitor->registry, watchrefs[i]);
		if (watch && !watch->enabled) {
			disabled_count++;
		}
	}

	/* Build status message */
	char *message = malloc(512);
	if (message) {
		if (disabled_count > 0) {
			snprintf(message, 512, "%d watches disabled", disabled_count);
		} else {
			snprintf(message, 512, "All watches enabled");
		}
	}
	result.message = message;

	/* Add data about disabled watches */
	if (disabled_count > 0) {
		result.data_keys = malloc(disabled_count * sizeof(char *));
		result.data_values = malloc(disabled_count * sizeof(char *));

		if (result.data_keys && result.data_values) {
			int data_index = 0;
			for (uint32_t i = 0; i < num_watches && data_index < disabled_count; i++) {
				watch_t *watch = registry_get(monitor->registry, watchrefs[i]);
				if (watch && !watch->enabled && watch->name) {
					result.data_keys[data_index] = strdup("disabled_watch");
					result.data_values[data_index] = strdup(watch->name);
					data_index++;
				}
			}
			result.data_count = data_index;
		}
	}

	free(watchrefs);
	return result;
}

/* Process list command */
static result_t process_list(monitor_t *monitor, const char *command_text) {
	result_t result;
	control_result(&result);

	(void) command_text; /* Unused parameter */

	/* Get active watches from registry */
	uint32_t num_watches = 0;
	watchref_t *watchrefs = registry_active(monitor->registry, &num_watches);

	result.success = true;
	result.message = malloc(128);
	if (result.message) {
		snprintf(result.message, 128, "Found %u total watches", num_watches);
	}

	if (watchrefs && num_watches > 0) {
		result.data_keys = malloc(num_watches * sizeof(char *));
		result.data_values = malloc(num_watches * sizeof(char *));

		if (result.data_keys && result.data_values) {
			int valid_count = 0;
			for (uint32_t i = 0; i < num_watches; i++) {
				watch_t *watch = registry_get(monitor->registry, watchrefs[i]);
				if (watch && watch->name) {
					result.data_keys[valid_count] = strdup("watch");
					result.data_values[valid_count] = strdup(watch->name);
					valid_count++;
				}
			}
			result.data_count = valid_count;
		}
		free(watchrefs);
	}

	return result;
}

/* Process reload command */
static result_t process_reload(monitor_t *monitor, const char *command_text) {
	result_t result;
	control_result(&result);

	(void) command_text; /* Unused parameter */

	/* Trigger reload by setting flag */
	monitor->reload = true;

	result.success = true;
	result.message = strdup("Configuration reload requested");

	return result;
}

/* Main command processing function */
result_t control_process(monitor_t *monitor, const char *command_text) {
	result_t result;
	control_result(&result);

	if (!monitor || !command_text) {
		result.success = false;
		result.message = strdup("Invalid monitor or command");
		return result;
	}

	char *command = kv_value(command_text, "command");
	if (!command) {
		result.success = false;
		result.message = strdup("Missing 'command' parameter");
		return result;
	}

	if (strcmp(command, "disable") == 0) {
		result = process_disable(monitor, command_text);
	} else if (strcmp(command, "enable") == 0) {
		result = process_enable(monitor, command_text);
	} else if (strcmp(command, "status") == 0) {
		result = process_status(monitor, command_text);
	} else if (strcmp(command, "list") == 0) {
		result = process_list(monitor, command_text);
	} else if (strcmp(command, "reload") == 0) {
		result = process_reload(monitor, command_text);
	} else {
		result.success = false;
		result.message = malloc(128);
		if (result.message) {
			snprintf(result.message, 128, "Unknown command: %s", command);
		}
	}

	free(command);
	return result;
}

/* Format command result as KV response */
char *control_format(const result_t *result) {
	if (!result) return NULL;

	size_t buffer_size = 1024;
	char *response = malloc(buffer_size);
	if (!response) return NULL;

	int written = snprintf(response, buffer_size, "status=%s\n",
						   result->success ? "success" : "error");

	if (result->message) {
		written += snprintf(response + written, buffer_size - written,
							"message=%s\n", result->message);
	}

	/* Add data key-value pairs if present */
	for (int i = 0; i < result->data_count && written < (int) buffer_size - 10; i++) {
		written += snprintf(response + written, buffer_size - written, "%s=%s\n",
							result->data_keys[i], result->data_values[i]);
	}

	/* Add terminating newline */
	if (written < (int) buffer_size - 2) {
		strcat(response, "\n");
	}

	return response;
}
