#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/event.h>
#include <sys/stat.h>

#include "events.h"
#include "monitor.h"
#include "logger.h"
#include "command.h"
#include "states.h"
#include "stability.h"
#include "scanner.h"

/* Initialize a sync request structure */
void syncreq_init(syncreq_t *syncreq) {
	if (!syncreq) return;
	syncreq->paths = NULL;
	syncreq->count = 0;
	syncreq->capacity = 0;
}

/* Add a path to the sync request */
bool syncreq_add(syncreq_t *syncreq, const char *path) {
	if (!syncreq || !path) return false;
	
	/* Check if path already exists to avoid duplicates */
	for (int i = 0; i < syncreq->count; i++) {
		if (strcmp(syncreq->paths[i], path) == 0) {
			return true; /* Already exists, no need to add */
		}
	}
	
	/* Expand array if needed */
	if (syncreq->count >= syncreq->capacity) {
		int new_capacity = syncreq->capacity == 0 ? 4 : syncreq->capacity * 2;
		char **new_paths = realloc(syncreq->paths, new_capacity * sizeof(char *));
		if (!new_paths) {
			log_message(ERROR, "Failed to allocate memory for sync request paths");
			return false;
		}
		syncreq->paths = new_paths;
		syncreq->capacity = new_capacity;
	}
	
	/* Add the path */
	syncreq->paths[syncreq->count] = strdup(path);
	if (!syncreq->paths[syncreq->count]) {
		log_message(ERROR, "Failed to duplicate path for sync request: %s", path);
		return false;
	}
	syncreq->count++;
	
	log_message(DEBUG, "Added path to sync request: %s", path);
	return true;
}

/* Clean up a sync request structure */
void syncreq_cleanup(syncreq_t *syncreq) {
	if (!syncreq) return;
	
	if (syncreq->paths) {
		for (int i = 0; i < syncreq->count; i++) {
			free(syncreq->paths[i]);
		}
		free(syncreq->paths);
	}
	
	syncreq->paths = NULL;
	syncreq->count = 0;
	syncreq->capacity = 0;
}

/* Schedule an event for delayed processing */
void events_schedule(monitor_t *monitor, watch_t *watch, event_t *event, kind_t kind) {
	if (!monitor || !watch || !event || watch->processing_delay <= 0) {
		return;
	}

	/* Expand delayed events array if needed */
	if (monitor->delayed_count >= monitor->delayed_capacity) {
		int new_capacity = monitor->delayed_capacity == 0 ? 16 : monitor->delayed_capacity * 2;
		delayed_t *new_events = realloc(monitor->delayed_events, new_capacity * sizeof(delayed_t));
		if (!new_events) {
			log_message(ERROR, "Failed to allocate memory for delayed events");
			return;
		}
		monitor->delayed_events = new_events;
		monitor->delayed_capacity = new_capacity;
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
	delayed_t *delayed = &monitor->delayed_events[monitor->delayed_count++];
	delayed->event.path = strdup(event->path);
	delayed->event.type = event->type;
	delayed->event.time = event->time;
	delayed->event.wall_time = event->wall_time;
	delayed->event.user_id = event->user_id;
	delayed->watch = watch;
	delayed->kind = kind;
	delayed->process_time = process_time;

	log_message(DEBUG, "Scheduled delayed event for %s (watch: %s) in %d ms",
	            		event->path, watch->name, watch->processing_delay);
}

/* Process delayed events that are ready */
void events_delayed(monitor_t *monitor) {
	if (!monitor || !monitor->delayed_events || monitor->delayed_count == 0) {
		return;
	}

	struct timespec current_time;
	clock_gettime(CLOCK_MONOTONIC, &current_time);

	int processed = 0;
	for (int i = 0; i < monitor->delayed_count; i++) {
		delayed_t *delayed = &monitor->delayed_events[i];

		/* Check if this event is ready to process */
		if (current_time.tv_sec > delayed->process_time.tv_sec ||
		    (current_time.tv_sec == delayed->process_time.tv_sec && current_time.tv_nsec >= delayed->process_time.tv_nsec)) {
			log_message(DEBUG, "Processing delayed event for %s (watch: %s)",
			        			delayed->event.path, delayed->watch->name);

			/* Process the event */
			events_process(monitor, delayed->watch, &delayed->event, delayed->kind);

			/* Free the path string */
			free(delayed->event.path);

			/* Mark as processed */
			processed++;

			/* Move the last event to this position to avoid gaps */
			if (i < monitor->delayed_count - 1) {
				monitor->delayed_events[i] = monitor->delayed_events[monitor->delayed_count - 1];
				i--; /* Reprocess this position */
			}
			monitor->delayed_count--;
		}
	}

	if (processed > 0) {
		log_message(DEBUG, "Processed %d delayed events", processed);
	}
}

/* Calculate timeout for the next delayed event */
int events_timeout(monitor_t *monitor, struct timespec *current_time) {
	if (!monitor || !monitor->delayed_events || monitor->delayed_count == 0) {
		return -1; /* No timeout needed */
	}

	struct timespec earliest = monitor->delayed_events[0].process_time;
	for (int i = 1; i < monitor->delayed_count; i++) {
		if (monitor->delayed_events[i].process_time.tv_sec < earliest.tv_sec ||
		    (monitor->delayed_events[i].process_time.tv_sec == earliest.tv_sec &&
		     monitor->delayed_events[i].process_time.tv_nsec < earliest.tv_nsec)) {
			earliest = monitor->delayed_events[i].process_time;
		}
	}

	/* Calculate timeout in milliseconds */
	long timeout_ms;
	if (current_time->tv_sec > earliest.tv_sec ||
		(current_time->tv_sec == earliest.tv_sec && current_time->tv_nsec > earliest.tv_nsec)) {
		timeout_ms = 0; /* Already overdue */
	} else {
		struct timespec time_diff;
		time_diff.tv_sec = earliest.tv_sec - current_time->tv_sec;
		if (earliest.tv_nsec >= current_time->tv_nsec) {
			time_diff.tv_nsec = earliest.tv_nsec - current_time->tv_nsec;
		} else {
			time_diff.tv_sec--;
			time_diff.tv_nsec = 1000000000 + earliest.tv_nsec - current_time->tv_nsec;
		}
		timeout_ms = time_diff.tv_sec * 1000 + time_diff.tv_nsec / 1000000;
	}

	return timeout_ms > 0 ? (int) timeout_ms : 0;
}

/* Convert kqueue flags to event type bitmask */
static filter_t flags_to_event_type(uint32_t flags) {
	filter_t event = EVENT_NONE;

	/* Content changes */
	if (flags & (NOTE_WRITE | NOTE_EXTEND)) {
		event |= EVENT_STRUCTURE;
	}

	/* Metadata changes */
	if (flags & (NOTE_ATTRIB | NOTE_LINK)) {
		event |= EVENT_METADATA;
	}

	/* Modification events */
	if (flags & (NOTE_DELETE | NOTE_RENAME | NOTE_REVOKE | NOTE_WRITE)) {
		event |= EVENT_CONTENT;
	}

	return event;
}

/* Handle kqueue events */
bool events_handle(monitor_t *monitor, struct kevent *events, int event_count, struct timespec *time, syncreq_t *syncreq) {
	if (!monitor || !events || event_count <= 0) {
		return false;
	}

	/* Process new events */
	for (int i = 0; i < event_count; i++) {
		/* Get the watcher directly from udata for O(1) access */
		watcher_t *primary_watcher = (watcher_t*)events[i].udata;
		if (!primary_watcher) {
			log_message(WARNING, "Received kevent with NULL udata, skipping");
			continue;
		}

		int fd = (int)events[i].ident;

		/* Find all watches that share this file descriptor */
		for (int j = 0; j < monitor->num_watches; j++) {
			watcher_t *watcher = monitor->watches[j];

			if (watcher->wd == fd) {
				event_t event;
				memset(&event, 0, sizeof(event));
				event.path = watcher->path;
				event.type = flags_to_event_type(events[i].fflags);
				event.time = *time;
				clock_gettime(CLOCK_REALTIME, &event.wall_time);
				event.user_id = getuid();

				kind_t kind = (watcher->watch->target == WATCH_FILE) ? ENTITY_FILE : ENTITY_DIRECTORY;

				log_message(DEBUG, "Event: path=%s, flags=0x%x -> type=%s (watch: %s)",
									watcher->path, events[i].fflags, filter_to_string(event.type), watcher->watch->name);

				/* Proactive validation for directory events on NOTE_WRITE */
				if (watcher->watch->target == WATCH_DIRECTORY && (events[i].fflags & NOTE_WRITE)) {
					log_message(DEBUG, "Write event on dir %s, requesting sync validation.", watcher->path);
					if (syncreq) {
						syncreq_add(syncreq, watcher->path);
					}
				}

				/* Check if this watch has a processing delay configured */
				if (watcher->watch->processing_delay > 0) {
					/* Schedule the event for delayed processing */
					events_schedule(monitor, watcher->watch, &event, kind);
				} else {
					/* Process the event immediately */
					events_process(monitor, watcher->watch, &event, kind);
				}
			}
		}
	}

	return true;
}

/* Calculate timeouts for monitor based on deferred checks and delayed events */
struct timespec* timeout_calculate(monitor_t *monitor, struct timespec *timeout, struct timespec *current_time) {
	if (!monitor || !timeout || !current_time) {
		return NULL;
	}

	/* Initialize timeout buffer */
	memset(timeout, 0, sizeof(*timeout));
	
	/* Get timeout for delayed events */
	int delayed_timeout_ms = events_timeout(monitor, current_time);

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
		if (current_time->tv_sec < next_check.tv_sec ||
		    (current_time->tv_sec == next_check.tv_sec &&
		     current_time->tv_nsec < next_check.tv_nsec)) {
			/* Time until next check */
			timeout->tv_sec = next_check.tv_sec - current_time->tv_sec;
			if (next_check.tv_nsec >= current_time->tv_nsec) {
				timeout->tv_nsec = next_check.tv_nsec - current_time->tv_nsec;
			} else {
				timeout->tv_sec--;
				timeout->tv_nsec = 1000000000 + next_check.tv_nsec - current_time->tv_nsec;
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

/* Convert operation type to corresponding event type */
filter_t operation_to_event_type(optype_t op) {
	switch (op) {
		case OP_FILE_CONTENT_CHANGED:
		case OP_DIR_CONTENT_CHANGED:  return EVENT_STRUCTURE;
		case OP_FILE_CREATED:
		case OP_FILE_DELETED:
		case OP_FILE_RENAMED:
		case OP_DIR_CREATED:
		case OP_DIR_DELETED:          return EVENT_CONTENT;
		case OP_FILE_METADATA_CHANGED:
		case OP_DIR_METADATA_CHANGED: return EVENT_METADATA;
		default:                      return EVENT_NONE;
	}
}

/* Determine operation type based on entity state and event type */
optype_t determine_operation(entity_t *state, filter_t filter) {
	if (!state) return OP_NONE;

	/* Update state change flags based on the new event type */
	if (filter & EVENT_STRUCTURE) state->structure_changed = true;
	if (filter & EVENT_METADATA) state->metadata_changed = true;
	if (filter & EVENT_CONTENT) state->content_changed = true;

	/* Check current existence vs tracked existence */
	struct stat info;
	bool exists_now = (stat(state->node->path, &info) == 0);

	optype_t determined_op = OP_NONE;

	if (state->exists && !exists_now) {
		/* Deletion */
		determined_op = (state->kind == ENTITY_FILE) ? OP_FILE_DELETED : OP_DIR_DELETED;
		log_message(DEBUG, "Entity %s detected as DELETED", state->node->path);
		state->exists = false;
	} else if (!state->exists && exists_now) {
		/* Creation */
		determined_op = (state->kind == ENTITY_FILE) ? OP_FILE_CREATED : OP_DIR_CREATED;
		log_message(DEBUG, "Entity %s detected as CREATED", state->node->path);
		state->exists = true;

		/* Update type if it was unknown */
		if (state->kind == ENTITY_UNKNOWN) {
			if (S_ISDIR(info.st_mode)) state->kind = ENTITY_DIRECTORY;
			else if (S_ISREG(info.st_mode)) state->kind = ENTITY_FILE;
		}

		/* For directory creation, gather initial stats */
		if (state->kind == ENTITY_DIRECTORY) {
			/* Create stability state for new directories */
			if (!state->stability) {
				state->stability = stability_create();
			}
			if (state->stability) {
				scanner_scan(state->node->path, &state->stability->stats);
				state->stability->prev_stats = state->stability->stats;
			}
		}
	} else if (exists_now) {
		/* Existed before and exists now - check for other changes */
		state->exists = true;

		/* Prioritize which operation to report if multiple flags are set */
		if (state->kind == ENTITY_DIRECTORY && (state->content_changed || state->structure_changed)) {
			determined_op = OP_DIR_CONTENT_CHANGED;
			log_message(DEBUG, "Directory %s structure changed", state->node->path);
		} else if (state->kind == ENTITY_FILE && state->content_changed) {
			determined_op = OP_FILE_RENAMED;
			log_message(DEBUG, "File %s content changed", state->node->path);
		} else if (state->kind == ENTITY_FILE && state->structure_changed) {
			determined_op = OP_FILE_CONTENT_CHANGED;
			log_message(DEBUG, "File %s content changed", state->node->path);
		} else if (state->metadata_changed) {
			determined_op = (state->kind == ENTITY_FILE) ? OP_FILE_METADATA_CHANGED : OP_DIR_METADATA_CHANGED;
			log_message(DEBUG, "Entity %s metadata changed", state->node->path);
		} else {
			log_message(DEBUG, "Entity %s exists but no relevant changes detected", state->node->path);
			determined_op = OP_NONE;
		}
	} else {
		log_message(DEBUG, "Entity %s still does not exist", state->node->path);
		determined_op = OP_NONE;
	}

	return determined_op;
}

/* Process a single file system event */
bool events_process(monitor_t *monitor, watch_t *watch, event_t *event, kind_t kind) {
	if (watch == NULL || event == NULL || event->path == NULL) {
		log_message(ERROR, "events_process: Received NULL watch, event, or event path");
		return false;
	}

	/* Additional safety checks for watch structure */
	if (!watch->name || !watch->command) {
		log_message(ERROR, "events_process: Watch has NULL name or command");
		return false;
	}

	log_message(DEBUG, "Processing event for %s (watch: %s, type: %s)",
	        			event->path, watch->name, filter_to_string(event->type));

	/* Handle config file events specially for hot reload */
	if (watch->name != NULL && strcmp(watch->name, "__config_file__") == 0) {
		static struct timespec reload_time = {0, 0};
		struct timespec current_time;
		clock_gettime(CLOCK_MONOTONIC, &current_time);

		/* Calculate time difference in milliseconds */
		long diff_ms = (current_time.tv_sec - reload_time.tv_sec) * 1000 +
		               (current_time.tv_nsec - reload_time.tv_nsec) / 1000000;

		if (diff_ms < 100) {
			log_message(DEBUG, "Skipping consecutive events generated by the configuration save operation");
			return true;
		}
		reload_time = current_time;

		log_message(NOTICE, "Configuraion changed: %s", event->path);
		if (monitor != NULL) {
			/* Add 100ms delay to allow atomic save operations to complete */
			usleep(100000);
			monitor->reload = true;
			log_message(DEBUG, "Configuration reload requested");
		} else {
			log_message(WARNING, "Config file changed but no monitor available for reload");
		}
		return true;
	}

	/* Check if this event was caused by one of our commands */
	if (command_affects(event->path)) {
		log_message(DEBUG, "Ignoring event for %s, it was caused by our command execution", event->path);
		return false;
	}

	/* Get state using the event path and watch config */
	entity_t *state = state_get(monitor->states, event->path, kind, watch);
	if (state == NULL) {
		return false; /* Error already logged by states_get */
	}

	/* Update timestamps before determining operation */
	state->last_time = event->time;
	state->wall_time = event->wall_time;

	/* Determine the logical operation */
	optype_t op = determine_operation(state, event->type);
	if (op == OP_NONE) {
		return false; /* No relevant change detected */
	}

	log_message(DEBUG, "Determined operation type %d for %s", op, state->node->path);

	/* Check if operation is included in watch mask */
	filter_t filter_for_mask = operation_to_event_type(op);
	if ((watch->filter & filter_for_mask) == 0) {
		log_message(DEBUG, "Operation maps to event type %s, which is not in watch mask for %s",
		        			filter_to_string(filter_for_mask), watch->name);
		return false;
	}

	/* Check debounce/deferral logic */
	if (stability_ready(monitor, state, op, command_get_debounce_time())) {
		/* Execute command immediately (only for non-directory-content changes) */
		event_t synthetic_event = {
			.path = state->node->path,
			.type = filter_for_mask,
			.time = state->last_time,
			.wall_time = state->wall_time,
			.user_id = event->user_id
		};

		log_message(INFO, "Executing command for %s (watch: %s, operation: %d)",
		    			   state->node->path, watch->name, op);

		if (command_execute(monitor, watch, &synthetic_event, false)) {
			log_message(INFO, "Command execution successful for %s", state->node->path);

			/* Update last command time and reset change flags */
			state->command_time = state->last_time.tv_sec;
			state->structure_changed = false;
			state->metadata_changed = false;
			state->content_changed = false;

			return true;
		} else {
			log_message(WARNING, "Command execution failed for %s", state->node->path);
			return false;
		}
	} else {
		log_message(DEBUG, "Command for %s (op %d) deferred or debounced", state->node->path, op);
		return false;
	}
}
