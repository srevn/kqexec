#ifndef EVENTS_H
#define EVENTS_H

#include <stdbool.h>
#include <time.h>
#include <sys/event.h>

#include "config.h"

/* Forward declarations to avoid circular dependency with states.h */
typedef struct monitor monitor_t;
typedef struct entity_state entity_state_t;

/* Activity window size for detecting quiet periods (in milliseconds) */
#define MAX_SAMPLES 5             /* Number of recent events to track for activity analysis */

/* Logical operation types */
typedef enum {
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
} operation_type_t;

/* Activity sample for analyzing bursts of events */
typedef struct {
	struct timespec timestamp;             /* When the event occurred */
	operation_type_t operation;            /* Type of operation */
} activity_sample_t;

/* Structure for file/directory event */
typedef struct file_event {
	char *path;                            /* Path where event occurred */
	event_type_t type;                     /* Type of event */
	struct timespec time;                  /* Time of event (MONOTONIC for internal use) */
	struct timespec wall_time;             /* Wall clock time (REALTIME for display) */
	uid_t user_id;                         /* User ID associated with event */
} file_event_t;

/* Delayed event queue entry */
typedef struct delayed_event {
	file_event_t event;                    /* The event to process */
	watch_entry_t *watch;                  /* The watch configuration */
	entity_type_t entity_type;             /* Type of entity */
	struct timespec process_time;          /* When to process this event */
} delayed_event_t;

/* Event queue structure */
typedef struct {
	delayed_event_t *items;                /* Array of delayed events */
	int count;                             /* Current number of delayed events */
	int capacity;                          /* Allocated capacity */
} event_queue_t;

/* Sync request structure for collecting paths that need validation */
typedef struct {
	char **paths;                          /* Array of paths needing sync */
	int count;                             /* Current number of paths */
	int capacity;                          /* Allocated capacity */
} sync_request_t;

/* Event lifecycle management */
void events_schedule(monitor_t *monitor, watch_entry_t *watch, file_event_t *event, entity_type_t entity_type);
void events_delayed(monitor_t *monitor);
int events_timeout(monitor_t *monitor, struct timespec *now);

/* Event processing */
bool events_handle(monitor_t *monitor, struct kevent *events, int count, struct timespec *time, sync_request_t *sync_request);
bool events_process(monitor_t *monitor, watch_entry_t *watch, file_event_t *event, entity_type_t entity_type);
struct timespec *timeout_calculate(monitor_t *monitor, struct timespec *timeout, struct timespec *now);

/* Event queue management */
event_queue_t *event_queue_create(void);
void event_queue_destroy(event_queue_t *queue);

/* Sync request management */
void sync_request_init(sync_request_t *sync_request);
bool sync_request_add(sync_request_t *sync_request, const char *path);
void sync_request_cleanup(sync_request_t *sync_request);

/* Event to operation translation */
operation_type_t determine_operation(entity_state_t *state, event_type_t new_event_type);
event_type_t operation_to_event_type(operation_type_t op);

#endif /* EVENTS_H */
