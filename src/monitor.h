#ifndef MONITOR_H
#define MONITOR_H

#include <stdbool.h>
#include <sys/types.h>
#include <time.h>

#include "states.h"
#include "config.h"

/* Maximum number of watches */
#define MAX_WATCHES 128

/* Watched file/directory information */
typedef struct {
	int wd;                       /* Watch descriptor (file descriptor) */
	char *path;                   /* Full path */
	watch_entry_t *watch;         /* Associated watch entry */
	bool is_shared_fd;            /* Whether this FD is shared with other watches */
} watch_info_t;

/* Deferred directory check queue entry */
typedef struct {
	char *path;                    /* Path to the watched directory (unique key) */
	struct timespec next_check;    /* When this directory needs checking */
	watch_entry_t **watches;       /* Array of watches for this path */
	int watch_count;               /* Number of watches for this path */
	int watch_capacity;            /* Allocated capacity for watches array */
} deferred_check_t;

/* Structure to hold monitoring context */
typedef struct monitor {
	int kq;                     	/* Kqueue descriptor */
	config_t *config;           	/* Configuration */
	watch_info_t **watches;     	/* Array of watch information */
	int watch_count;            	/* Number of watches */
	bool running;               	/* Monitor running flag */
	
	bool reload_requested;      	/* Flag to indicate reload requested */
	char *config_file;          	/* Copy of config file path for reloading */
	
	/* Priority queue for deferred directory checks */
	deferred_check_t *check_queue;  /* Min-heap of deferred checks */
	int check_queue_size;           /* Current number of entries */
	int check_queue_capacity;       /* Allocated capacity */
} monitor_t;

/* Structure for file/directory event */
typedef struct file_event {
	char *path;                     /* Path where event occurred */
	event_type_t type;          	/* Type of event */
	struct timespec time;       	/* Time of event (MONOTONIC for internal use) */
	struct timespec wall_time;  	/* Wall clock time (REALTIME for display) */
	uid_t user_id;              	/* User ID associated with event */
} file_event_t;

/* Function prototypes */
monitor_t *monitor_create(config_t *config);
void monitor_destroy(monitor_t *monitor);
bool monitor_setup(monitor_t *monitor);
bool monitor_start(monitor_t *monitor);
void monitor_stop(monitor_t *monitor);
bool monitor_reload(monitor_t *monitor);
void monitor_request_reload(monitor_t *monitor);
bool monitor_add_watch(monitor_t *monitor, watch_entry_t *watch);
bool monitor_process_events(monitor_t *monitor);
void schedule_deferred_check(monitor_t *monitor, entity_state_t *state);

#endif /* MONITOR_H */
