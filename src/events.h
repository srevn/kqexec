#ifndef EVENTS_H
#define EVENTS_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/event.h>

#include "config.h"
#include "states.h"

/* Forward declaration for monitor */
typedef struct monitor monitor_t;

/* Structure for file/directory event */
typedef struct file_event {
	char *path;                      /* Path where event occurred */
	event_type_t type;               /* Type of event */
	struct timespec time;            /* Time of event (MONOTONIC for internal use) */
	struct timespec wall_time;       /* Wall clock time (REALTIME for display) */
	uid_t user_id;                   /* User ID associated with event */
} file_event_t;

/* Delayed event queue entry */
typedef struct delayed_event {
	file_event_t event;              /* The event to process */
	watch_entry_t *watch;            /* The watch configuration */
	entity_type_t entity_type;       /* Type of entity */
	struct timespec process_time;    /* When to process this event */
} delayed_event_t;

/* Event queue structure */
typedef struct {
	delayed_event_t *items;          /* Array of delayed events */
	int count;                       /* Current number of delayed events */
	int capacity;                    /* Allocated capacity */
} event_queue_t;

/* Function prototypes */

/* Event lifecycle management */
void events_schedule(monitor_t *monitor, watch_entry_t *watch, file_event_t *event, entity_type_t entity_type);
void events_process(monitor_t *monitor);
int events_timeout(monitor_t *monitor, struct timespec *now);

/* Event processing */
bool events_handle(monitor_t *monitor, struct kevent *events, int count, struct timespec *time);
struct timespec* timeout_calculate(monitor_t *monitor, struct timespec *timeout, struct timespec *now);

/* Event queue management */
event_queue_t* event_queue_create(void);
void event_queue_destroy(event_queue_t *queue);

#endif /* EVENTS_H */
