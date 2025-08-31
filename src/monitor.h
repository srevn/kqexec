#ifndef MONITOR_H
#define MONITOR_H

#include <pthread.h>
#include <stdbool.h>

#include "config.h"
#include "events.h"
#include "mapper.h"
#include "pending.h"
#include "queue.h"
#include "registry.h"
#include "resource.h"

/* Forward declaration */
typedef struct server server_t;

/* Monitor configuration */
#define MAX_WATCHES 128                    /* Maximum number of simultaneous watches */
#define MAX_PATH_LEN 1024                  /* Maximum length for filesystem paths */
#define MAX_CHECKS_FAILED 3                /* Maximum consecutive validation failures */
#define MAX_EVENTS 64                      /* Maximum number of incoming events to process */
#define GRAVEYARD_SECONDS 5                /* Time to wait before cleaning up stale watchers */

/* Watched file/directory information */
typedef struct watcher {
	watchref_t watchref;                   /* Associated watch reference */
	int wd;                                /* Watch descriptor */
	char *path;                            /* Full path */
	ino_t inode;                           /* Inode number for validation */
	dev_t device;                          /* Device ID for validation */
	bool shared_fd;                        /* Whether this FD is shared with other watches */
	time_t validated;                      /* Last time this path was validated */
	
	/* Hash table linkage */
	struct watcher *next;                  /* Next watcher in hash bucket */
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
	mapper_t *mapper;                      /* FD -> Watcher mapping */
	registry_t *registry;                  /* Watch registry */
	resources_t *resources;                /* Resource table for this monitor */
	graveyard_t graveyard;                 /* Graveyard for stale items */
	
	/* Watch tracking */
	int num_watches;                       /* Number of watches */
	int watches_capacity;                  /* Allocated capacity for watches array */
	watcher_t **watches;                   /* Array of watch information */
	
	/* Path lookup hash table for lookups */
	watcher_t **buckets;                   /* Hash table buckets for path -> watcher lookup */
	size_t bucket_count;                   /* Number of hash table buckets */
	
	/* Pending watches for non-existent paths */
	int num_pending;                       /* Number of pending watches */
	int pending_capacity;                  /* Allocated capacity for pending array */
	pending_t **pending;                   /* Array of pending watch information */
	
	/* Queue for delayed events */
	queue_t *check_queue;                  /* Queued checks queue */
	struct delayed *delayed_events;        /* Array of delayed events */
	int delayed_count;                     /* Current number of delayed events */
	int delayed_capacity;                  /* Allocated capacity */
	
	/* Control flags & config */
	bool running;                          /* Monitor running flag */
	bool reload;                           /* Flag to indicate reload requested */
	bool reloading;                        /* Flag to indicate reload in progress */
	pthread_mutex_t reload_mutex;          /* Mutex to serialize reload operations */
	char *config_path;                     /* Copy of config file path for reloading */
	
	/* Unix socket control server */
	server_t *server;                      /* Control socket server */
	
	/* Observers for watcher cleanups */
	observer_t monitor_observer;           /* Observer registration for watcher cleanup */
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

/* Dynamic watch control */
bool monitor_activate(monitor_t *monitor, watchref_t watchref);
bool monitor_disable(monitor_t *monitor, watchref_t watchref);

/* Path synchronization */
bool monitor_sync(monitor_t *monitor, const char *path);
bool monitor_prune(monitor_t *monitor, const char *parent);

/* Utility functions */
unsigned int watcher_hash(const char *path, size_t bucket_count);

#endif /* MONITOR_H */
