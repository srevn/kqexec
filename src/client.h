#ifndef CLIENT_H
#define CLIENT_H

#include <stdbool.h>

/* Client command types */
typedef enum command {
	CMD_DISABLE,                           /* Temporarily disable specified watches */
	CMD_ENABLE,                            /* Re-enable previously disabled watches */  
	CMD_STATUS,                            /* Get current daemon and watch status */
	CMD_LIST,                              /* List all configured watches */
	CMD_RELOAD                             /* Reload configuration from file */
} command_t;

/* Client command-line options */
typedef struct options {
	/* Command configuration */
	command_t command;                     /* Which command to execute */
	char *socket_path;                     /* Path to daemon's control socket */
	
	/* Watch selection */
	int num_watches;                       /* Number of watches in array */
	char **watch_names;                    /* Array of specific watch names to target */
} options_t;

/* Client mode entry point */
int client_main(options_t *options);

/* Client connection functions */
int client_connect(const char *socket_path);
bool client_send(int sock_fd, const char *command_text);
char *client_receive(int sock_fd);
void client_display(const char *response);

/* Command building functions */
char *client_build(options_t *options);
char **client_parse(const char *watch_list);

/* Cleanup functions */
void client_cleanup(options_t *options);

#endif /* CLIENT_H */
