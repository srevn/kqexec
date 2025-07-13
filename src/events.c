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

/* Initialize a sync request structure */
void sync_request_init(sync_request_t *sync_request) {
	if (!sync_request) return;
	sync_request->paths = NULL;
	sync_request->count = 0;
	sync_request->capacity = 0;
}

/* Add a path to the sync request */
bool sync_request_add(sync_request_t *sync_request, const char *path) {
	if (!sync_request || !path) return false;
	
	/* Check if path already exists to avoid duplicates */
	for (int i = 0; i < sync_request->count; i++) {
		if (strcmp(sync_request->paths[i], path) == 0) {
			return true; /* Already exists, no need to add */
		}
	}
	
	/* Expand array if needed */
	if (sync_request->count >= sync_request->capacity) {
		int new_capacity = sync_request->capacity == 0 ? 4 : sync_request->capacity * 2;
		char **new_paths = realloc(sync_request->paths, new_capacity * sizeof(char *));
		if (!new_paths) {
			log_message(ERROR, "Failed to allocate memory for sync request paths");
			return false;
		}
		sync_request->paths = new_paths;
		sync_request->capacity = new_capacity;
	}
	
	/* Add the path */
	sync_request->paths[sync_request->count] = strdup(path);
	if (!sync_request->paths[sync_request->count]) {
		log_message(ERROR, "Failed to duplicate path for sync request: %s", path);
		return false;
	}
	sync_request->count++;
	
	log_message(DEBUG, "Added path to sync request: %s", path);
	return true;
}

/* Clean up a sync request structure */
void sync_request_cleanup(sync_request_t *sync_request) {
	if (!sync_request) return;
	
	if (sync_request->paths) {
		for (int i = 0; i < sync_request->count; i++) {
			free(sync_request->paths[i]);
		}
		free(sync_request->paths);
	}
	
	sync_request->paths = NULL;
	sync_request->count = 0;
	sync_request->capacity = 0;
}

/* Schedule an event for delayed processing */
void events_schedule(monitor_t *monitor, watch_entry_t *watch, file_event_t *event, entity_type_t entity_type) {
	if (!monitor || !watch || !event || watch->processing_delay <= 0) {
		return;
	}

	/* Expand delayed events array if needed */
	if (monitor->delayed_count >= monitor->delayed_capacity) {
		int new_capacity = monitor->delayed_capacity == 0 ? 16 : monitor->delayed_capacity * 2;
		delayed_event_t *new_events = realloc(monitor->delayed_events, new_capacity * sizeof(delayed_event_t));
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
	delayed_event_t *delayed = &monitor->delayed_events[monitor->delayed_count++];
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
void events_delayed(monitor_t *monitor) {
	if (!monitor || !monitor->delayed_events || monitor->delayed_count == 0) {
		return;
	}

	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	int processed = 0;
	for (int i = 0; i < monitor->delayed_count; i++) {
		delayed_event_t *delayed = &monitor->delayed_events[i];

		/* Check if this event is ready to process */
		if (now.tv_sec > delayed->process_time.tv_sec ||
		    (now.tv_sec == delayed->process_time.tv_sec && now.tv_nsec >= delayed->process_time.tv_nsec)) {
			log_message(DEBUG, "Processing delayed event for %s (watch: %s)",
			        			delayed->event.path, delayed->watch->name);

			/* Process the event */
			events_process(monitor, delayed->watch, &delayed->event, delayed->entity_type);

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
int events_timeout(monitor_t *monitor, struct timespec *now) {
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
	if (flags & (NOTE_DELETE | NOTE_RENAME | NOTE_REVOKE | NOTE_WRITE)) {
		event |= EVENT_CONTENT;
	}

	return event;
}

/* Handle kqueue events */
bool events_handle(monitor_t *monitor, struct kevent *events, int count, struct timespec *time, sync_request_t *sync_request) {
	if (!monitor || !events || count <= 0) {
		return false;
	}

	/* Process new events */
	for (int i = 0; i < count; i++) {
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
					log_message(DEBUG, "Write event on dir %s, requesting sync validation.", info->path);
					if (sync_request) {
						sync_request_add(sync_request, info->path);
					}
				}

				/* Check if this watch has a processing delay configured */
				if (info->watch->processing_delay > 0) {
					/* Schedule the event for delayed processing */
					events_schedule(monitor, info->watch, &event, entity_type);
				} else {
					/* Process the event immediately */
					events_process(monitor, info->watch, &event, entity_type);
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

/* Convert operation type to corresponding event type */
event_type_t operation_to_event_type(operation_type_t op) {
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
operation_type_t determine_operation(entity_state_t *state, event_type_t new_event_type) {
	if (!state) return OP_NONE;

	/* Update state change flags based on the new event type */
	if (new_event_type & EVENT_STRUCTURE) state->structure_changed = true;
	if (new_event_type & EVENT_METADATA) state->metadata_changed = true;
	if (new_event_type & EVENT_CONTENT) state->content_changed = true;

	/* Check current existence vs tracked existence */
	struct stat st;
	bool exists_now = (stat(state->path_state->path, &st) == 0);

	operation_type_t determined_op = OP_NONE;

	if (state->exists && !exists_now) {
		/* Deletion */
		determined_op = (state->type == ENTITY_FILE) ? OP_FILE_DELETED : OP_DIR_DELETED;
		log_message(DEBUG, "Entity %s detected as DELETED", state->path_state->path);
		state->exists = false;
	} else if (!state->exists && exists_now) {
		/* Creation */
		determined_op = (state->type == ENTITY_FILE) ? OP_FILE_CREATED : OP_DIR_CREATED;
		log_message(DEBUG, "Entity %s detected as CREATED", state->path_state->path);
		state->exists = true;

		/* Update type if it was unknown */
		if (state->type == ENTITY_UNKNOWN) {
			if (S_ISDIR(st.st_mode)) state->type = ENTITY_DIRECTORY;
			else if (S_ISREG(st.st_mode)) state->type = ENTITY_FILE;
		}

		/* For directory creation, gather initial stats */
		if (state->type == ENTITY_DIRECTORY) {
			scanner_scan(state->path_state->path, &state->dir_stats);
			state->prev_stats = state->dir_stats;
		}
	} else if (exists_now) {
		/* Existed before and exists now - check for other changes */
		state->exists = true;

		/* Prioritize which operation to report if multiple flags are set */
		if (state->type == ENTITY_DIRECTORY && (state->content_changed || state->structure_changed)) {
			determined_op = OP_DIR_CONTENT_CHANGED;
			log_message(DEBUG, "Directory %s structure changed", state->path_state->path);
		} else if (state->type == ENTITY_FILE && state->content_changed) {
			determined_op = OP_FILE_RENAMED;
			log_message(DEBUG, "File %s content changed", state->path_state->path);
		} else if (state->type == ENTITY_FILE && state->structure_changed) {
			determined_op = OP_FILE_CONTENT_CHANGED;
			log_message(DEBUG, "File %s content changed", state->path_state->path);
		} else if (state->metadata_changed) {
			determined_op = (state->type == ENTITY_FILE) ? OP_FILE_METADATA_CHANGED : OP_DIR_METADATA_CHANGED;
			log_message(DEBUG, "Entity %s metadata changed", state->path_state->path);
		} else {
			log_message(DEBUG, "Entity %s exists but no relevant changes detected", state->path_state->path);
			determined_op = OP_NONE;
		}
	} else {
		log_message(DEBUG, "Entity %s still does not exist", state->path_state->path);
		determined_op = OP_NONE;
	}

	return determined_op;
}

/* Process a single file system event */
bool events_process(monitor_t *monitor, watch_entry_t *watch, file_event_t *event, entity_type_t entity_type) {
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
	        			event->path, watch->name, event_type_to_string(event->type));

	/* Handle config file events specially for hot reload */
	if (watch->name != NULL && strcmp(watch->name, "__config_file__") == 0) {
		static struct timespec last_reload_time = {0, 0};
		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);

		/* Calculate time difference in milliseconds */
		long diff_ms = (now.tv_sec - last_reload_time.tv_sec) * 1000 +
		               (now.tv_nsec - last_reload_time.tv_nsec) / 1000000;

		if (diff_ms < 100) {
			log_message(DEBUG, "Skipping consecutive events generated by the configuration save operation");
			return true;
		}
		last_reload_time = now;

		log_message(NOTICE, "Configuraion changed: %s", event->path);
		if (monitor != NULL) {
			/* Add 100ms delay to allow atomic save operations to complete */
			usleep(100000);
			monitor->reload_requested = true;
			log_message(DEBUG, "Configuration reload requested");
		} else {
			log_message(WARNING, "Config file changed but no monitor available for reload");
		}
		return true;
	}

	/* Check if this event was caused by one of our commands */
	if (command_affects(event->path)) {
		log_message(DEBUG, "Ignoring event for %s - caused by our command execution", event->path);
		return false;
	}

	/* Get state using the event path and watch config */
	entity_state_t *state = states_get(event->path, entity_type, watch);
	if (state == NULL) {
		return false; /* Error already logged by states_get */
	}

	/* Update timestamps before determining operation */
	state->last_update = event->time;
	state->wall_time = event->wall_time;

	/* Determine the logical operation */
	operation_type_t op = determine_operation(state, event->type);
	if (op == OP_NONE) {
		return false; /* No relevant change detected */
	}

	log_message(DEBUG, "Determined operation type %d for %s", op, state->path_state->path);

	/* Check if operation is included in watch mask */
	event_type_t event_type_for_mask = operation_to_event_type(op);
	if ((watch->events & event_type_for_mask) == 0) {
		log_message(DEBUG, "Operation maps to event type %s, which is not in watch mask for %s",
		        			event_type_to_string(event_type_for_mask), watch->name);
		return false;
	}

	/* Check debounce/deferral logic */
	if (stability_ready(monitor, state, op, command_get_debounce_time())) {
		/* Execute command immediately (only for non-directory-content changes) */
		file_event_t synthetic_event = {
			.path = state->path_state->path,
			.type = event_type_for_mask,
			.time = state->last_update,
			.wall_time = state->wall_time,
			.user_id = event->user_id
		};

		log_message(INFO, "Executing command for %s (watch: %s, operation: %d)",
		    			   state->path_state->path, watch->name, op);

		if (command_execute(watch, &synthetic_event, false)) {
			log_message(INFO, "Command execution successful for %s", state->path_state->path);

			/* Update last command time and reset change flags */
			state->command_time = state->last_update.tv_sec;
			state->structure_changed = false;
			state->metadata_changed = false;
			state->content_changed = false;

			return true;
		} else {
			log_message(WARNING, "Command execution failed for %s", state->path_state->path);
			return false;
		}
	} else {
		log_message(DEBUG, "Command for %s (op %d) deferred or debounced", state->path_state->path, op);
		return false;
	}
}
