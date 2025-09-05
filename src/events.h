#ifndef EVENTS_H
#define EVENTS_H

#include <stdbool.h>
#include <sys/event.h>

#include "config.h"
#include "registry.h"

/* Forward declarations */
typedef struct diff diff_t;
typedef struct monitor monitor_t;
typedef struct snapshot snapshot_t;
typedef struct resource resource_t;
typedef struct subscription subscription_t;

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
	OP_DIR_METADATA_CHANGED,               /* Directory attributes changed */
	
	/* Multiple operation types */
	OP_DIR_COMPOSITE_CHANGE                /* Structure and content changed */
} optype_t;

/* Structure for file/directory event */
typedef struct event {
	char *path;                            /* Path where event occurred */
	filter_t type;                         /* Type of event */
	struct timespec time;                  /* Time of event (MONOTONIC for internal use) */
	struct timespec wall_time;             /* Wall clock time (REALTIME for display) */
	uid_t user_id;                         /* User ID associated with event */
	diff_t *diff;                          /* Directory snapshot differences */
	snapshot_t *baseline_snapshot;         /* Snapshot for baseline reset */
} event_t;

/* Delayed event queue entry */
typedef struct delayed {
	kind_t kind;                           /* Type of entity */
	event_t event;                         /* The event to process */
	watchref_t watchref;                   /* The watch reference */
	struct timespec process_time;          /* When to process this event */
} delayed_t;

/* Deferred event queue entry */
typedef struct deferred {
	kind_t kind;                           /* Type of entity */
	event_t event;                         /* The event to process */
	watchref_t watchref;                   /* The watch reference */
	struct deferred *next;                 /* Next deferred event in the queue */
} deferred_t;

/* Structure for collecting paths that need validation */
typedef struct validate {
	char **paths;                          /* Array of paths needing validation */
	int paths_count;                       /* Current number of paths */
	int paths_capacity;                    /* Allocated capacity */
} validate_t;

/* Event processing core */
bool events_handle(monitor_t *monitor, struct kevent *events, int event_count, struct timespec *time, validate_t *validate);
bool events_process(monitor_t *monitor, watchref_t watchref, event_t *event, kind_t kind, bool is_deferred);

/* Delayed event management */
void events_delay(monitor_t *monitor, watchref_t watchref, event_t *event, kind_t kind);
void events_delayed(monitor_t *monitor);

/* Batch event management */
void events_batch(monitor_t *monitor);
void events_deferred(monitor_t *monitor, resource_t *resource);

/* Timeout calculation */
int events_timeout(monitor_t *monitor, struct timespec *current_time);
struct timespec *timeout_calculate(monitor_t *monitor, struct timespec *timeout, struct timespec *current_time);

/* Validate request management */
void validate_init(validate_t *validate);
bool validate_add(validate_t *validate, const char *path);
void validate_cleanup(validate_t *validate);

/* Event to operation translation */
optype_t events_operation(monitor_t *monitor, subscription_t *subscription, filter_t filter);
filter_t operation_to_filter(optype_t optype);

#endif /* EVENTS_H */
