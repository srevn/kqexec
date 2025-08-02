#ifndef MONITOR_H
#define MONITOR_H

#include <stdbool.h>

#include "queue.h"
#include "config.h"
#include "events.h"
#include "states.h"
#include "pending.h"
#include "registry.h"

/* Monitor configuration */
#define MAX_WATCHES 128
#define MAX_PATH_LEN 1024
#define MAX_CHECKS_FAILED 3
#define MAX_EVENTS 64
#define GRAVEYARD_SECONDS 5

/* Watched file/directory information */
typedef struct watcher {
	watchref_t watchref;                   /* Associated watch reference */
	int wd;                                /* Watch descriptor */
	char *path;                            /* Full path */
	ino_t inode;                           /* Inode number for validation */
	dev_t device;                          /* Device ID for validation */
	bool shared_fd;                        /* Whether this FD is shared with other watches */
	time_t validated;                      /* Last time this path was validated */
} watcher_t;

/* Graveyard for stale watchers and old configurations */
typedef struct graveyard {
	watcher_t **stale_watches;             /* Array of watchers pending cleanup */
	int num_stale;                         /* Count of stale watchers in array */
	config_t *old_config;                  /* Previous configuration awaiting cleanup */
	time_t retirement_time;                /* Timestamp when cleanup becomes safe */
} graveyard_t;

/* Structure to hold monitoring context */
typedef struct monitor {
	int kq;                                /* Kqueue descriptor */
	config_t *config;                      /* Configuration */
	states_t *states;                      /* State table for this monitor */
	registry_t *registry;                  /* Watch registry */
	graveyard_t graveyard;                 /* Graveyard for stale items */
	
	/* Watch tracking */
	watcher_t **watches;                   /* Array of watch information */
	int num_watches;                       /* Number of watches */
	
	/* Pending watches for non-existent paths */
	watchref_t glob_watchref;              /* Special watch for intermediate glob directories */
	pending_t **pending;                   /* Array of pending watch information */
	int num_pending;                       /* Number of pending watches */

	/* Queue for delayed events */
	queue_t *check_queue;                  /* Deferred checks queue */
	struct delayed *delayed_events;        /* Array of delayed events */
	int delayed_count;                     /* Current number of delayed events */
	int delayed_capacity;                  /* Allocated capacity */
	
	/* Control flags & config */
	bool running;                          /* Monitor running flag */
	bool reload;                           /* Flag to indicate reload requested */
	char *config_path;                     /* Copy of config file path for reloading */
	
	/* Observers for watcher cleanups */
	observer_t monitor_observer;           /* Observer registration for direct watcher cleanup */
	observer_t pending_observer;           /* Observer registration for pending cleanup */	
} monitor_t;

/* Monitor lifecycle management */
monitor_t *monitor_create(config_t *config, registry_t *registry);
void monitor_destroy(monitor_t *monitor);
bool monitor_setup(monitor_t *monitor);

/* Monitor control operations */
bool monitor_start(monitor_t *monitor);
void monitor_stop(monitor_t *monitor);
bool monitor_reload(monitor_t *monitor);
bool monitor_poll(monitor_t *monitor);

/* Watch management */
bool monitor_add(monitor_t *monitor, watchref_t watchref, bool skip_pending);
bool monitor_tree(monitor_t *monitor, const char *dir_path, watchref_t watchref);
bool monitor_path(monitor_t *monitor, const char *path, watchref_t watchref);
void monitor_graveyard(monitor_t *monitor);

/* Path synchronization */
bool monitor_sync(monitor_t *monitor, const char *path);
bool monitor_prune(monitor_t *monitor, const char *parent);

#endif /* MONITOR_H */
