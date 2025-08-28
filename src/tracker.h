#ifndef TRACKER_H
#define TRACKER_H

#include <stdbool.h>
#include <sys/event.h>

#include "config.h"
#include "registry.h"

/* Forward declarations */
typedef struct monitor monitor_t;
typedef struct watcher watcher_t;
typedef struct profile profile_t;
typedef struct resource resource_t;

/* Magic number for file tracking validation */
#define TRACKER_MAGIC 0x5452434B           /* "TRCK" */

/* File tracking configuration */
#define TRACKER_CLEANUP_INTERVAL 30        /* Seconds between cleanup cycles */
#define TRACKER_IDLE_TIMEOUT 300           /* Seconds before removing idle file trackers */
#define MAX_TRACKER_PER_DIR 1024           /* Maximum file trackers per directory */

/* File tracking states */
typedef enum tracker_state {
	TRACKER_ACTIVE,                        /* Currently monitoring */
	TRACKER_ONESHOT_FIRED,                 /* One-shot event fired, needs re-registration */
	TRACKER_PENDING_CLEANUP                /* Marked for cleanup */
} tracker_state_t;

/* File tracking structure for tracking individual files within directory watches */
typedef struct tracker {
	/* Validation and identity */
	char *path;                            /* Full path to the file */
	ino_t inode;                           /* File inode for validation */
	dev_t device;                          /* Device ID for validation */
	uint32_t magic;                        /* Magic number for validation */
	
	/* System resources */
	int fd;                                /* File descriptor */
	resource_t *parent;                    /* Direct pointer to parent directory resource */
	
	/* Watch associations */
	watchref_t *watchrefs;                 /* Parent directory watch references */
	int num_watchrefs;                     /* Number of parent watch references */
	int watchrefs_capacity;                /* Capacity of the watchrefs array */
	
	/* Timing and state */
	time_t created;                        /* When this file tracker was created */
	time_t last_event;                     /* Last time this file had an event */
	tracker_state_t tracker_state;         /* Current state */
	
	/* Linked list management */
	struct tracker *next;                  /* Next in hash bucket or list */
} tracker_t;

/* File tracking registry for efficient lookup and management */
typedef struct trackers {
	tracker_t **buckets;                   /* Hash table buckets */
	size_t bucket_count;                   /* Number of hash buckets */
	int total_count;                       /* Total number of file trackers */
	time_t last_cleanup;                   /* Last time cleanup was performed */
} trackers_t;

/* File tracking management functions */
trackers_t *trackers_create(size_t bucket_count);
void trackers_destroy(trackers_t *registry);

/* File tracking lifecycle */
bool tracker_add(monitor_t *monitor, resource_t *resource, const char *file_path, watchref_t watchref);
tracker_t *tracker_find(trackers_t *registry, const char *file_path);

/* File tracking registration with kqueue */
bool tracker_register(monitor_t *monitor, tracker_t *tracker);
bool tracker_reregister(monitor_t *monitor, tracker_t *tracker);

/* File tracking event processing */
bool tracker_handle(monitor_t *monitor, tracker_t *tracker, struct kevent *event, struct timespec *time);

/* Directory scanning for file tracking */
bool tracker_scan(monitor_t *monitor, resource_t *resource, watchref_t watchref, const watch_t *watch);

/* Cleanup and maintenance */
void tracker_cleanup(monitor_t *monitor, trackers_t *registry);
void tracker_purge(monitor_t *monitor, trackers_t *registry, watchref_t watchref);
void directory_cleanup(monitor_t *monitor, trackers_t *registry, const char *dir_path);

/* Stability integration */
void directory_reregister(monitor_t *monitor, resource_t *resource);

/* Utility functions */
unsigned int tracker_hash(const char *path, size_t bucket_count);
bool tracker_monitor(const watch_t *watch, const char *file_path);
bool tracker_valid(const tracker_t *tracker);

/* Statistics */
int tracker_counter(monitor_t *monitor);

#endif /* TRACKER_H */
