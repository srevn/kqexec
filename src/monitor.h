#ifndef MONITOR_H
#define MONITOR_H

#include <stdbool.h>

#include "queue.h"
#include "config.h"
#include "events.h"
#include "states.h"

/* Monitor configuration */
#define MAX_WATCHES 128
#define MAX_PATH_LEN 1024
#define MAX_FAILED_CHECKS 3
#define MAX_EVENTS 64

/* Watched file/directory information */
typedef struct watcher {
	int wd;                                /* Watch descriptor */
	char *path;                            /* Full path */
	ino_t inode;                           /* Inode number for validation */
	dev_t device;                          /* Device ID for validation */
	watch_t *watch;                        /* Associated watch entry */
	bool shared_fd;                        /* Whether this FD is shared with other watches */
	time_t validated;                      /* Last time this path was validated */
} watcher_t;

/* Structure to hold monitoring context */
typedef struct monitor {
	/* Core components */
	int kq;                                /* Kqueue descriptor */
	config_t *config;                      /* Configuration */
	state_t *states;                       /* State table for this monitor */
	
	/* Watch tracking */
	watcher_t **watches;                   /* Array of watch information */
	int num_watches;                       /* Number of watches */

	/* Queue for delayed events */
	queue_t *check_queue;                  /* Deferred checks queue */
	struct delayed *delayed_events;        /* Array of delayed events */
	int delayed_count;                     /* Current number of delayed events */
	int delayed_capacity;                  /* Allocated capacity */
	
	/* Control flags & config */
	bool running;                          /* Monitor running flag */
	bool reload;                           /* Flag to indicate reload requested */
	char *config_path;                     /* Copy of config file path for reloading */
} monitor_t;

/* Monitor lifecycle management */
monitor_t *monitor_create(config_t *config);
void monitor_destroy(monitor_t *monitor);
bool monitor_setup(monitor_t *monitor);

/* Monitor control operations */
bool monitor_start(monitor_t *monitor);
void monitor_stop(monitor_t *monitor);
bool monitor_reload(monitor_t *monitor);
bool monitor_poll(monitor_t *monitor);

/* Watch management */
bool monitor_add(monitor_t *monitor, watch_t *watch);
bool monitor_tree(monitor_t *monitor, const char *dir_path, watch_t *watch);

/* Path synchronization */
bool monitor_sync(monitor_t *monitor, const char *path);
bool monitor_prune(monitor_t *monitor, const char *parent);

#endif /* MONITOR_H */
