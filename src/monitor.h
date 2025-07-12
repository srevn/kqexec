#ifndef MONITOR_H
#define MONITOR_H

#include <stdbool.h>

#include "queue.h"
#include "config.h"
#include "events.h"

/* Maximum number of watches */
#define MAX_WATCHES 128

/* Watched file/directory information */
typedef struct {
	int wd;                                /* Watch descriptor (file descriptor) */
	char *path;                            /* Full path */
	ino_t inode;                           /* Inode number for validation */
	dev_t device;                          /* Device ID for validation */
	watch_entry_t *watch;                  /* Associated watch entry */
	bool shared_fd;                        /* Whether this FD is shared with other watches */
	time_t last_validation;                /* Last time this path was validated */
} watch_info_t;

/* Structure to hold monitoring context */
typedef struct monitor {
	int kq;                                /* Kqueue descriptor */
	config_t *config;                      /* Configuration */
	watch_info_t **watches;                /* Array of watch information */
	int watch_count;                       /* Number of watches */
	bool running;                          /* Monitor running flag */

	bool reload_requested;                 /* Flag to indicate reload requested */
	char *config_file;                     /* Copy of config file path for reloading */

	/* Priority queue for deferred directory checks */
	defer_queue_t *check_queue;            /* Deferred checks queue */

	/* Queue for delayed events */
	struct delayed_event *delayed_events;  /* Array of delayed events */
	int delayed_event_count;               /* Current number of delayed events */
	int delayed_event_capacity;            /* Allocated capacity */
} monitor_t;

/* Function prototypes */
monitor_t *monitor_create(config_t *config);
void monitor_destroy(monitor_t *monitor);
bool monitor_setup(monitor_t *monitor);
bool monitor_start(monitor_t *monitor);
void monitor_stop(monitor_t *monitor);
bool monitor_reload(monitor_t *monitor);
bool monitor_add(monitor_t *monitor, watch_entry_t *watch);
bool monitor_tree(monitor_t *monitor, const char *dir_path, watch_entry_t *watch);
bool monitor_poll(monitor_t *monitor);
bool monitor_sync(monitor_t *monitor, const char *path);
bool monitor_prune(monitor_t *monitor, const char *parent_path);

#endif /* MONITOR_H */
