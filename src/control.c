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
#include "protocol.h"

/* Ensure client write buffer has enough capacity for additional data */
static bool client_buffer(client_t *client, size_t additional_needed) {
	if (!client) return false;

	/* Check if we have enough space */
	if (client->write_size + additional_needed <= client->write_capacity) {
		return true;
	}

	/* Calculate new capacity using doubling strategy */
	size_t new_capacity = client->write_capacity;
	while (client->write_size + additional_needed > new_capacity) {
		new_capacity = (new_capacity == 0) ? 128 : new_capacity * 2;
	}

	/* Reallocate buffer */
	char *new_buffer = realloc(client->write_buffer, new_capacity);
	if (!new_buffer) {
		log_message(ERROR, "Failed to reallocate client write buffer");
		return false;
	}

	client->write_buffer = new_buffer;
	client->write_capacity = new_capacity;
	return true;
}

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
			free(server->clients[i]->buffer);
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
	client->addr = client_addr;

	/* Allocate and initialize read buffer */
	client->buffer = malloc(BUFFER_SIZE);
	if (!client->buffer) {
		log_message(ERROR, "Failed to allocate memory for client read buffer");
		close(client_fd);
		free(client);
		return;
	}
	client->buffer_capacity = BUFFER_SIZE;
	client->buffer_pos = 0;

	/* Initialize write buffer fields */
	client->write_buffer = NULL;
	client->write_size = 0;
	client->write_pos = 0;
	client->write_capacity = 0;

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

	log_message(DEBUG, "Accepted control client connection (fd=%d), total clients: %d",
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
			free(server->clients[i]->buffer);
			free(server->clients[i]->write_buffer);
			free(server->clients[i]);

			/* Shift remaining clients down */
			for (int j = i; j < server->num_clients - 1; j++) {
				server->clients[j] = server->clients[j + 1];
			}

			server->num_clients--;
			server->clients[server->num_clients] = NULL;

			log_message(DEBUG, "Removed client (fd=%d), remaining clients: %d", client_fd,
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
		log_message(DEBUG, "Client (fd=%d) disconnected", client_fd);
		control_remove(server, client_fd, monitor->kq);
		return;
	}

	/* Ensure buffer has space */
	if (client->buffer_pos >= client->buffer_capacity - 1) {
		/* Use doubling strategy for buffer growth */
		size_t new_capacity = client->buffer_capacity * 2;

		/* Impose a sane limit to prevent excessive memory allocation */
		if (new_capacity > 1024 * 1024) { /* 1MB limit */
			log_message(WARNING, "Client (fd=%d) command buffer > 1MB. Disconnecting.", client_fd);
			control_remove(server, client_fd, monitor->kq);
			return;
		}

		char *new_buffer = realloc(client->buffer, new_capacity);
		if (!new_buffer) {
			log_message(ERROR, "Failed to expand client read buffer. Disconnecting client (fd=%d).", client_fd);
			control_remove(server, client_fd, monitor->kq);
			return;
		}
		client->buffer = new_buffer;
		client->buffer_capacity = new_capacity;
	}

	/* Read data from client */
	ssize_t data_read = read(client_fd, client->buffer + client->buffer_pos,
							 client->buffer_capacity - client->buffer_pos - 1);

	if (data_read <= 0) {
		if (data_read == 0 || (data_read == -1 && errno != EAGAIN && errno != EWOULDBLOCK)) {
			log_message(DEBUG, "Client (fd=%d) closed connection or error occurred: %s",
						client_fd, strerror(errno));
			control_remove(server, client_fd, monitor->kq);
		}
		return;
	}

	client->buffer_pos += data_read;
	client->buffer[client->buffer_pos] = '\0';

	/* Loop to process all complete commands in the buffer */
	char *current_pos = client->buffer;
	while (true) {
		char *end_marker = strstr(current_pos, "\n\n");
		if (!end_marker) {
			/* No complete command found, break and wait for more data */
			break;
		}

		*end_marker = '\0'; /* Terminate command string */

		/* Process the command */
		char *command_str = current_pos;
		char *command = kv_value(command_str, "command");
		if (command) {
			log_message(DEBUG, "Processing '%s' command from session (fd=%d)", command, client_fd);
			free(command);
		}
		protocol_t result = protocol_process(monitor, command_str);
		char *response = protocol_format(&result);

		if (response) {
			/* Send response to client using buffered approach */
			if (!control_send(monitor, client, response)) {
				log_message(WARNING, "Failed to send response to client (fd=%d)", client_fd);
				control_remove(server, client_fd, monitor->kq);
				free(response);
				protocol_cleanup(&result);
				return; /* Stop processing on send error */
			}
			free(response);
		}

		protocol_cleanup(&result);

		/* Move to the start of the next potential command */
		current_pos = end_marker + 2; /* Skip past '\n\n' */
	}

	/* Shift any remaining partial command to the beginning of the buffer */
	size_t remaining_len = strlen(current_pos);
	if (remaining_len > 0) {
		memmove(client->buffer, current_pos, remaining_len);
	}
	client->buffer_pos = remaining_len;
	client->buffer[client->buffer_pos] = '\0';
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
		if (!client_buffer(client, remaining)) return false;

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
		if (!client_buffer(client, response_len)) return false;

		memcpy(client->write_buffer + client->write_size, response, response_len);
		client->write_size += response_len;

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
		client->write_capacity = 0;

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
		log_message(DEBUG, "Client (fd=%d) write failed, disconnecting", client_fd);
		control_remove(server, client_fd, monitor->kq);
	}
}
