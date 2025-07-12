#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/event.h>

#include "events.h"
#include "monitor.h"
#include "logger.h"
#include "command.h"

/* Create a new event queue */
event_queue_t* event_queue_create(void) {
	event_queue_t *queue = calloc(1, sizeof(event_queue_t));
	if (queue == NULL) {
		log_message(ERROR, "Failed to allocate memory for event queue");
		return NULL;
	}
	
	queue->items = NULL;
	queue->count = 0;
	queue->capacity = 0;
	
	return queue;
}

/* Destroy an event queue and free all resources */
void event_queue_destroy(event_queue_t *queue) {
	if (queue == NULL) {
		return;
	}
	
	/* Free all event paths */
	if (queue->items) {
		for (int i = 0; i < queue->count; i++) {
			free(queue->items[i].event.path);
		}
		free(queue->items);
	}
	
	free(queue);
}

/* Schedule an event for delayed processing */
void events_schedule(monitor_t *monitor, watch_entry_t *watch, file_event_t *event, entity_type_t entity_type) {
	if (!monitor || !watch || !event || watch->processing_delay <= 0) {
		return;
	}

	/* Expand delayed events array if needed */
	if (monitor->delayed_event_count >= monitor->delayed_event_capacity) {
		int new_capacity = monitor->delayed_event_capacity == 0 ? 16 : monitor->delayed_event_capacity * 2;
		delayed_event_t *new_events = realloc(monitor->delayed_events, new_capacity * sizeof(delayed_event_t));
		if (!new_events) {
			log_message(ERROR, "Failed to allocate memory for delayed events");
			return;
		}
		monitor->delayed_events = new_events;
		monitor->delayed_event_capacity = new_capacity;
	}

	/* Calculate process time */
	struct timespec process_time;
	clock_gettime(CLOCK_MONOTONIC, &process_time);
	process_time.tv_sec += watch->processing_delay / 1000;
	process_time.tv_nsec += (watch->processing_delay % 1000) * 1000000;

	/* Normalize nsec */
	if (process_time.tv_nsec >= 1000000000) {
		process_time.tv_sec++;
		process_time.tv_nsec -= 1000000000;
	}

	/* Store the delayed event */
	delayed_event_t *delayed = &monitor->delayed_events[monitor->delayed_event_count++];
	delayed->event.path = strdup(event->path);
	delayed->event.type = event->type;
	delayed->event.time = event->time;
	delayed->event.wall_time = event->wall_time;
	delayed->event.user_id = event->user_id;
	delayed->watch = watch;
	delayed->entity_type = entity_type;
	delayed->process_time = process_time;

	log_message(DEBUG, "Scheduled delayed event for %s (watch: %s) in %d ms",
	            event->path, watch->name, watch->processing_delay);
}

/* Process delayed events that are ready */
void events_process(monitor_t *monitor) {
	if (!monitor || !monitor->delayed_events || monitor->delayed_event_count == 0) {
		return;
	}

	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	int processed = 0;
	for (int i = 0; i < monitor->delayed_event_count; i++) {
		delayed_event_t *delayed = &monitor->delayed_events[i];

		/* Check if this event is ready to process */
		if (now.tv_sec > delayed->process_time.tv_sec ||
		    (now.tv_sec == delayed->process_time.tv_sec && now.tv_nsec >= delayed->process_time.tv_nsec)) {
			log_message(DEBUG, "Processing delayed event for %s (watch: %s)",
			            delayed->event.path, delayed->watch->name);

			/* Process the event */
			process_event(monitor, delayed->watch, &delayed->event, delayed->entity_type);

			/* Free the path string */
			free(delayed->event.path);

			/* Mark as processed */
			processed++;

			/* Move the last event to this position to avoid gaps */
			if (i < monitor->delayed_event_count - 1) {
				monitor->delayed_events[i] = monitor->delayed_events[monitor->delayed_event_count - 1];
				i--; /* Reprocess this position */
			}
			monitor->delayed_event_count--;
		}
	}

	if (processed > 0) {
		log_message(DEBUG, "Processed %d delayed events", processed);
	}
}

/* Calculate timeout for the next delayed event */
int events_timeout(monitor_t *monitor, struct timespec *now) {
	if (!monitor || !monitor->delayed_events || monitor->delayed_event_count == 0) {
		return -1; /* No timeout needed */
	}

	struct timespec earliest = monitor->delayed_events[0].process_time;
	for (int i = 1; i < monitor->delayed_event_count; i++) {
		if (monitor->delayed_events[i].process_time.tv_sec < earliest.tv_sec ||
		    (monitor->delayed_events[i].process_time.tv_sec == earliest.tv_sec &&
		     monitor->delayed_events[i].process_time.tv_nsec < earliest.tv_nsec)) {
			earliest = monitor->delayed_events[i].process_time;
		}
	}

	/* Calculate timeout in milliseconds */
	long timeout_ms;
	if (now->tv_sec > earliest.tv_sec || (now->tv_sec == earliest.tv_sec && now->tv_nsec > earliest.tv_nsec)) {
		timeout_ms = 0; /* Already overdue */
	} else {
		struct timespec diff;
		diff.tv_sec = earliest.tv_sec - now->tv_sec;
		if (earliest.tv_nsec >= now->tv_nsec) {
			diff.tv_nsec = earliest.tv_nsec - now->tv_nsec;
		} else {
			diff.tv_sec--;
			diff.tv_nsec = 1000000000 + earliest.tv_nsec - now->tv_nsec;
		}
		timeout_ms = diff.tv_sec * 1000 + diff.tv_nsec / 1000000;
	}

	return timeout_ms > 0 ? (int) timeout_ms : 0;
}

/* Convert kqueue flags to event type bitmask */
static event_type_t flags_to_event_type(uint32_t flags) {
	event_type_t event = EVENT_NONE;

	/* Content changes */
	if (flags & (NOTE_WRITE | NOTE_EXTEND)) {
		event |= EVENT_STRUCTURE;
	}

	/* Metadata changes */
	if (flags & (NOTE_ATTRIB | NOTE_LINK)) {
		event |= EVENT_METADATA;
	}

	/* Modification events */
	if (flags & (NOTE_DELETE | NOTE_RENAME | NOTE_REVOKE)) {
		event |= EVENT_CONTENT;
	}

	return event;
}

/* Handle kqueue events */
bool events_handle(monitor_t *monitor, struct kevent *events, int count, struct timespec *time) {
	if (!monitor || !events || count <= 0) {
		return false;
	}

	/* Process new events */
	for (int i = 0; i < count; i++) {
	event_loop_start:; /* Label to restart the loop if watches array is modified */

		/* Find all watches that use this file descriptor */
		for (int j = 0; j < monitor->watch_count; j++) {
			watch_info_t *info = monitor->watches[j];

			if ((uintptr_t) info->wd == events[i].ident) {
				file_event_t event;
				memset(&event, 0, sizeof(event));
				event.path = info->path;
				event.type = flags_to_event_type(events[i].fflags);
				event.time = *time;
				clock_gettime(CLOCK_REALTIME, &event.wall_time);
				event.user_id = getuid();

				entity_type_t entity_type = (info->watch->type == WATCH_FILE) ? ENTITY_FILE : ENTITY_DIRECTORY;

				log_message(DEBUG, "Event: path=%s, flags=0x%x -> type=%s (watch: %s)",
				            info->path, events[i].fflags, event_type_to_string(event.type), info->watch->name);

				/* Proactive validation for directory events on NOTE_WRITE */
				if (info->watch->type == WATCH_DIRECTORY && (events[i].fflags & NOTE_WRITE)) {
					log_message(DEBUG, "Write event on dir %s, validating and re-scanning.", info->path);
					if (monitor_validate_and_refresh_path(monitor, info->path)) {
						/* The watches array was modified, restart the event processing to use the new array */
						goto event_loop_start;
					}
				}

				/* Check if this watch has a processing delay configured */
				if (info->watch->processing_delay > 0) {
					/* Schedule the event for delayed processing */
					events_schedule(monitor, info->watch, &event, entity_type);
				} else {
					/* Process the event immediately */
					process_event(monitor, info->watch, &event, entity_type);
				}
			}
		}
	}

	return true;
}

/* Calculate timeouts for monitor based on deferred checks and delayed events */
struct timespec* timeout_calculate(monitor_t *monitor, struct timespec *timeout, struct timespec *now) {
	if (!monitor || !timeout || !now) {
		return NULL;
	}

	/* Initialize timeout buffer */
	memset(timeout, 0, sizeof(*timeout));
	
	/* Get timeout for delayed events */
	int delayed_timeout_ms = events_timeout(monitor, now);

	/* Check if we have any pending deferred checks */
	if (monitor->check_queue && monitor->check_queue->size > 0) {
		/* Debug output for the queue status */
		if (monitor->check_queue->items[0].path) {
			log_message(DEBUG, "Deferred queue status: %d entries, next check for path %s",
			            monitor->check_queue->size, monitor->check_queue->items[0].path);
		}

		/* Get the earliest check time (top of min-heap) */
		struct timespec next_check = monitor->check_queue->items[0].next_check;

		/* Calculate relative timeout */
		if (now->tv_sec < next_check.tv_sec ||
		    (now->tv_sec == next_check.tv_sec &&
		     now->tv_nsec < next_check.tv_nsec)) {
			/* Time until next check */
			timeout->tv_sec = next_check.tv_sec - now->tv_sec;
			if (next_check.tv_nsec >= now->tv_nsec) {
				timeout->tv_nsec = next_check.tv_nsec - now->tv_nsec;
			} else {
				timeout->tv_sec--;
				timeout->tv_nsec = 1000000000 + next_check.tv_nsec - now->tv_nsec;
			}

			/* Ensure sane values */
			if (timeout->tv_sec < 0) {
				timeout->tv_sec = 0;
				timeout->tv_nsec = 50000000; /* 50ms minimum */
			} else if (timeout->tv_sec == 0 && timeout->tv_nsec < 10000000) {
				timeout->tv_nsec = 50000000; /* 50ms minimum */
			}

			/* If we have both deferred checks and delayed events, use the shorter timeout */
			if (delayed_timeout_ms >= 0) {
				long current_timeout_ms = timeout->tv_sec * 1000 + timeout->tv_nsec / 1000000;
				if (delayed_timeout_ms < current_timeout_ms) {
					timeout->tv_sec = delayed_timeout_ms / 1000;
					timeout->tv_nsec = (delayed_timeout_ms % 1000) * 1000000;
					log_message(DEBUG, "Using shorter delayed event timeout: %d ms", delayed_timeout_ms);
				}
			}

			return timeout;
		} else {
			/* Check time already passed, use minimal timeout */
			timeout->tv_sec = 0;
			timeout->tv_nsec = 10000000; /* 10ms */
			log_message(DEBUG, "Deferred check overdue, using minimal timeout");
			return timeout;
		}
	} else if (delayed_timeout_ms >= 0) {
		/* No deferred checks, but we have delayed events */
		timeout->tv_sec = delayed_timeout_ms / 1000;
		timeout->tv_nsec = (delayed_timeout_ms % 1000) * 1000000;
		log_message(DEBUG, "No deferred checks, timeout for delayed events: %d ms", delayed_timeout_ms);
		return timeout;
	} else {
		log_message(DEBUG, "No pending directory activity or delayed events, waiting indefinitely");
		return NULL;
	}
}
