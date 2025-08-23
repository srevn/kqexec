#ifndef FILES_H
#define FILES_H

#include <stdbool.h>
#include <sys/event.h>
#include <time.h>

#include "config.h"
#include "registry.h"

/* Forward declarations */
typedef struct monitor monitor_t;
typedef struct watcher watcher_t;
typedef struct profile profile_t;
typedef struct resource resource_t;

/* Magic number for file watcher validation */
#define FWATCHER_MAGIC 0x46574348          /* "FWCH" */

/* File watcher configuration */
#define FILES_CLEANUP_INTERVAL 30          /* Seconds between cleanup cycles */
#define FILES_IDLE_TIMEOUT 300             /* Seconds before removing idle file watches */
#define MAX_FILES_PER_DIR 1024             /* Maximum file watches per directory */

/* File watcher states */
typedef enum fstate {
	FILES_ACTIVE,                          /* Currently monitoring */
	FILES_ONESHOT_FIRED,                   /* One-shot event fired, needs re-registration */
	FILES_PENDING_CLEANUP                  /* Marked for cleanup */
} fstate_t;

/* File watcher structure for tracking individual files within directory watches */
typedef struct fwatcher {
	uint32_t magic;                        /* Magic number for validation */
	char *path;                            /* Full path to the file */
	int fd;                                /* File descriptor */
	watchref_t *watchrefs;                 /* Parent directory watch references */
	int num_watchrefs;                     /* Number of parent watch references */
	int cap_watchrefs;                     /* Capacity of the watchrefs array */
	fstate_t state;                        /* Current state */
	time_t last_event;                     /* Last time this file had an event */
	time_t created;                        /* When this file watch was created */
	ino_t inode;                           /* File inode for validation */
	dev_t device;                          /* Device ID for validation */
	struct fwatcher *next;                 /* Next in hash bucket or list */
} fwatcher_t;

/* File watch registry for efficient lookup and management */
typedef struct fregistry {
	fwatcher_t **buckets;                  /* Hash table buckets */
	size_t bucket_count;                   /* Number of hash buckets */
	int total_count;                       /* Total number of file watches */
	time_t last_cleanup;                   /* Last time cleanup was performed */
} fregistry_t;

/* File monitor management functions */
fregistry_t *fregistry_create(size_t bucket_count);
void fregistry_destroy(fregistry_t *registry);

/* File watcher lifecycle */
bool files_add(monitor_t *monitor, resource_t *resource, const char *file_path, watchref_t watchref);
fwatcher_t *files_find(fregistry_t *registry, const char *file_path);

/* File watch registration with kqueue */
bool files_register(monitor_t *monitor, fwatcher_t *fwatcher);
bool files_reregister(monitor_t *monitor, fwatcher_t *fwatcher);

/* File watch event processing */
bool files_handle(monitor_t *monitor, fwatcher_t *watcher, struct kevent *event, struct timespec *time);

/* Directory scanning for file watches */
bool files_scan(monitor_t *monitor, resource_t *resource, watchref_t watchref, const watch_t *watch);

/* Cleanup and maintenance */
void files_cleanup(monitor_t *monitor, fregistry_t *registry);
void directory_cleanup(monitor_t *monitor, fregistry_t *registry, const char *dir_path);

/* Stability integration */
void directory_reregister(monitor_t *monitor, fregistry_t *registry, const char *dir_path);

/* Utility functions */
unsigned int files_hash(const char *path, size_t bucket_count);
bool files_monitor(const watch_t *watch, const char *file_path);
bool fwatcher_valid(const fwatcher_t *watcher);

#endif /* FILES_H */
