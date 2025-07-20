#ifndef EVENTS_H
#define EVENTS_H

#include <stdbool.h>
#include <time.h>
#include <sys/event.h>

#include "config.h"

/* Forward declarations */
typedef struct monitor monitor_t;
typedef struct entity entity_t;

/* Logical operation types */
typedef enum optype {
	OP_NONE = 0,                           /* No operation */

	/* File operations */
	OP_FILE_CONTENT_CHANGED,               /* File content was modified */
	OP_FILE_CREATED,                       /* File was created */
	OP_FILE_DELETED,                       /* File was deleted */
	OP_FILE_RENAMED,                       /* File was renamed/moved */
	OP_FILE_METADATA_CHANGED,              /* File attributes changed */

	/* Directory operations */
	OP_DIR_CONTENT_CHANGED,                /* Directory content changed */
	OP_DIR_CREATED,                        /* Directory was created */
	OP_DIR_DELETED,                        /* Directory was deleted */
	OP_DIR_METADATA_CHANGED                /* Directory attributes changed */
} optype_t;

/* Structure for file/directory event */
typedef struct event {
	char *path;                            /* Path where event occurred */
	filter_t type;                         /* Type of event */
	struct timespec time;                  /* Time of event (MONOTONIC for internal use) */
	struct timespec wall_time;             /* Wall clock time (REALTIME for display) */
	uid_t user_id;                         /* User ID associated with event */
} event_t;

/* Delayed event queue entry */
typedef struct delayed {
	event_t event;                         /* The event to process */
	watch_t *watch;                        /* The watch configuration */
	kind_t kind;                           /* Type of entity */
	struct timespec process_time;          /* When to process this event */
} delayed_t;

/* Sync request structure for collecting paths that need validation */
typedef struct syncreq {
	char **paths;                          /* Array of paths needing sync */
	int count;                             /* Current number of paths */
	int capacity;                          /* Allocated capacity */
} syncreq_t;

/* Event lifecycle management */
void events_schedule(monitor_t *monitor, watch_t *watch, event_t *event, kind_t kind);
void events_delayed(monitor_t *monitor);
int events_timeout(monitor_t *monitor, struct timespec *current_time);

/* Event processing */
bool events_handle(monitor_t *monitor, struct kevent *events, int event_count, struct timespec *time, syncreq_t *syncreq);
bool events_process(monitor_t *monitor, watch_t *watch, event_t *event, kind_t kind);
struct timespec *timeout_calculate(monitor_t *monitor, struct timespec *timeout, struct timespec *current_time);

/* Sync request management */
void syncreq_init(syncreq_t *syncreq);
bool syncreq_add(syncreq_t *syncreq, const char *path);
void syncreq_cleanup(syncreq_t *syncreq);

/* Event to operation translation */
optype_t determine_operation(entity_t *state, filter_t filter);
filter_t operation_to_event_type(optype_t op);

#endif /* EVENTS_H */
