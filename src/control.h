#ifndef CONTROL_H
#define CONTROL_H

#include <pthread.h>
#include <stdbool.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/un.h>

/* Forward declarations */
typedef struct monitor monitor_t;

/* Control server configuration */
#define DEFAULT_SOCKET "/tmp/kqexec.sock"    /* Default socket path for control interface */
#define MAX_CLIENTS 32                       /* Maximum concurrent client connections */
#define BUFFER_SIZE 4096                     /* Size of client input/output buffers */

/* Connected client state */
typedef struct client {
	/* Connection details */
	int fd;                                /* Client socket file descriptor */
	struct sockaddr_un addr;               /* Client socket address */
	
	/* Input processing */
	char buffer[BUFFER_SIZE];              /* Input buffer for incoming commands */
	size_t buffer_pos;                     /* Current position in input buffer */
	
	/* Output buffering */
	char *write_buffer;                    /* Dynamically allocated write buffer */
	size_t write_pos;                      /* Current position in write buffer */
	size_t write_size;                     /* Total allocated size of write buffer */
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

/* Command result for key-value protocol responses */
typedef struct result {
	/* Status information */
	bool success;                          /* Command success status */
	char *message;                         /* Result message */
	
	/* Data payload */
	int data_count;                        /* Number of key-value pairs in response */
	char **data_keys;                      /* Array of response data keys */
	char **data_values;                    /* Array of corresponding data values */
} result_t;

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

/* Command processing */
result_t control_process(monitor_t *monitor, const char *command_text);
char *control_format(const result_t *result);
void control_cleanup(result_t *result);

/* KV protocol utilities */
char *kv_value(const char *text, const char *key);
char **kv_split(const char *value, const char *delimiter, int *count);

#endif /* CONTROL_H */
