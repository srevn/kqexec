#ifndef CONTROL_H
#define CONTROL_H

#include <pthread.h>
#include <stdbool.h>
#include <sys/event.h>
#include <sys/un.h>

/* Forward declarations */
typedef struct monitor monitor_t;

/* Control server configuration */
#define DEFAULT_SOCKET "/tmp/kqexec.sock"  /* Default socket path for control interface */
#define MAX_CLIENTS 32                     /* Maximum concurrent client connections */
#define BUFFER_SIZE 4096                   /* Size of client input/output buffers */

/* Connected client state */
typedef struct client {
	/* Connection details */
	int fd;                                /* Client socket file descriptor */
	struct sockaddr_un addr;               /* Client socket address */
	
	/* Input processing */
	char *buffer;                          /* Dynamically allocated input buffer */
	size_t buffer_pos;                     /* Current position in input buffer */
	size_t buffer_capacity;                /* Allocated capacity of input buffer */
	
	/* Output buffering */
	char *write_buffer;                    /* Dynamically allocated write buffer */
	size_t write_pos;                      /* Current position in write buffer */
	size_t write_size;                     /* Current used size of write buffer */
	size_t write_capacity;                 /* Total allocated capacity of write buffer */
} client_t;

/* Control server state */
typedef struct server {
	/* Socket configuration */
	bool running;                          /* Server running state */
	int socket_fd;                         /* Server socket file descriptor */
	char *socket_path;                     /* Socket file path */
	
	/* Client connection management */
	int num_clients;                       /* Current number of active clients */
	int max_clients;                       /* Maximum allowed concurrent clients */
	client_t **clients;                    /* Array of connected client pointers */
} server_t;

/* Server lifecycle */
server_t *server_create(const char *socket_path);
void server_destroy(server_t *server);
bool server_start(server_t *server, int kqueue_fd);
void server_stop(server_t *server);

/* Client connection management */
void control_accept(server_t *server, int kqueue_fd);
void control_handle(monitor_t *monitor, struct kevent *event);
void control_write(monitor_t *monitor, struct kevent *event);
bool control_event(server_t *server, struct kevent *event);
void control_remove(server_t *server, int client_fd, int kqueue_fd);

/* Write buffering */
bool control_send(monitor_t *monitor, client_t *client, const char *response);
bool control_pending(monitor_t *monitor, client_t *client);

#endif /* CONTROL_H */
