#ifndef MONITOR_H
#define MONITOR_H

#include <stdbool.h>
#include <sys/types.h>

#include "config.h"

/* Maximum number of watches */
#define MAX_WATCHES 128

/* Structure to hold monitoring context */
typedef struct monitor monitor_t;

/* Structure for file/directory event */
typedef struct {
	char *path;             	/* Path where event occurred */
	event_type_t type;      	/* Type of event */
	struct timespec time;   	/* Time of event (MONOTONIC for internal use) */
	struct timespec wall_time; 	/* Wall clock time (REALTIME for display) */
	uid_t user_id;          	/* User ID associated with event */
} file_event_t;

/* Function prototypes */
monitor_t *monitor_create(config_t *config);
void monitor_destroy(monitor_t *monitor);
bool monitor_setup(monitor_t *monitor);
bool monitor_start(monitor_t *monitor);
void monitor_stop(monitor_t *monitor);
bool monitor_add_watch(monitor_t *monitor, watch_entry_t *watch);
bool monitor_process_events(monitor_t *monitor);

#endif /* MONITOR_H */
