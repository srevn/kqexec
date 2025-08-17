#include "events.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include "command.h"
#include "logger.h"
#include "monitor.h"
#include "registry.h"
#include "resource.h"
#include "scanner.h"
#include "stability.h"
#include "utilities.h"

/* Defer an event on a resource that is currently executing a command */
static void events_defer(monitor_t *monitor, resource_t *resource, watchref_t watchref, const event_t *event, kind_t kind) {
	if (!resource || !event) return;

	/* Manage window state if batch_timeout feature is active */
	if (monitor && monitor->registry) {
		watch_t *watch = registry_get(monitor->registry, watchref);
		if (watch && watch->batch_timeout > 0) {
			struct timespec current_time;
			clock_gettime(CLOCK_MONOTONIC, &current_time);

			if (!resource->timeout_active) {
				/* Start new batch timeout */
				resource->timeout_start = current_time;
				resource->timeout_active = true;
				resource->current_timeout = watch->batch_timeout;
				log_message(DEBUG, "Started event batching (%dms timeout) for %s", watch->batch_timeout,
							resource->path);

				/* Proactively add watches to subdirectories to detect ongoing activity */
				if (resource->kind == ENTITY_DIRECTORY && watch->recursive) {
					log_message(DEBUG, "Proactively scanning %s to add watches for batch timeout",
								resource->path);
					monitor_tree(monitor, resource->path, watchref);
				}
			} else {
				/* Batch timeout already active, apply longest timeout */
				if (watch->batch_timeout > resource->current_timeout) {
					resource->current_timeout = watch->batch_timeout;
					log_message(DEBUG, "Extended batch timeout to %dms for %s (multiple watches)",
								watch->batch_timeout, resource->path);
				}
			}

			/* Update timers for both batch timeout and stability */
			resource->last_event = current_time;
			if (resource->profiles) {
				profile_t *profile = resource->profiles;
				while (profile) {
					if (profile->scanner) {
						profile->scanner->latest_time = current_time;
					}
					profile = profile->next;
				}
			}
		}
	}

	deferred_t *deferred = calloc(1, sizeof(deferred_t));
	if (!deferred) {
		log_message(ERROR, "Failed to allocate memory for deferred event on %s", resource->path);
		return;
	}

	/* Store event data */
	deferred->event.path = strdup(event->path);
	if (!deferred->event.path) {
		log_message(ERROR, "Failed to duplicate path for deferred event on %s", resource->path);
		free(deferred);
		return;
	}

	deferred->event.type = event->type;
	deferred->event.time = event->time;
	deferred->event.wall_time = event->wall_time;
	deferred->event.user_id = event->user_id;
	deferred->watchref = watchref;
	deferred->kind = kind;
	deferred->next = NULL;

	/* Enqueue the event */
	resource_lock(resource);
	if (resource->deferred_tail) {
		resource->deferred_tail->next = deferred;
		resource->deferred_tail = deferred;
	} else {
		resource->deferred_head = resource->deferred_tail = deferred;
	}

	resource->deferred_count++;
	log_message(DEBUG, "Queued deferred event for %s, total deferred: %d",
				resource->path, resource->deferred_count);
	resource_unlock(resource);
}

/* Process deferred events when batch timeout expires */
void events_deferred(monitor_t *monitor, resource_t *resource) {
	if (!monitor || !resource) return;

	resource_lock(resource);
	resource->timeout_active = false;

	/* Check if there are any events to process */
	if (!resource->deferred_head) {
		profile_t *profiles_head = resource->profiles;
		resource_unlock(resource);
		log_message(DEBUG, "Batch timeout expired for %s, no events queued", resource->path);
		for (profile_t *profile = profiles_head; profile; profile = profile->next) {
			if (profile->subscriptions) {
				stability_ready(monitor, profile->subscriptions, OP_DIR_CONTENT_CHANGED, 0);
			}
		}
		return;
	}

	log_message(DEBUG, "Coalescing %d deferred events for %s", resource->deferred_count,
				resource->path);

	/* Clear deferred queue to coalesce into single stability check */
	deferred_t *current = resource->deferred_head;
	while (current) {
		deferred_t *next = current->next;
		free(current->event.path);
		free(current);
		current = next;
	}
	resource->deferred_head = NULL;
	resource->deferred_tail = NULL;
	resource->deferred_count = 0;

	/* Get necessary resource properties before unlocking */
	profile_t *profiles_head = resource->profiles;
	kind_t kind = resource->kind;
	struct timespec last_time = resource->last_time;
	struct timespec wall_time = resource->wall_time;
	char *path = strdup(resource->path);

	resource_unlock(resource);

	if (!path) {
		log_message(ERROR, "Failed to copy resource path in events_deferred");
		return;
	}

	/* Handle files or directories after coalescing for each profile */
	for (profile_t *profile = profiles_head; profile; profile = profile->next) {
		subscription_t *subscription = profile->subscriptions;
		if (!subscription) continue;

		if (kind == ENTITY_FILE) {
			/* For files, trigger immediate command execution for all subscriptions in this profile */
			for (subscription_t *sub_iterator = subscription; sub_iterator; sub_iterator = sub_iterator->next) {
				event_t synthetic_event = {
					.path = path,
					.type = EVENT_CONTENT,
					.time = last_time,
					.wall_time = wall_time,
					.user_id = getuid()};

				command_execute(monitor, sub_iterator->watchref, &synthetic_event, true);
			}
		} else {
			/* For directories, perform preliminary scan before using stability system */
			subscription_t *root = stability_root(monitor, subscription);
			if (root && root->profile && root->profile->stability) {
				stats_t current_stats;
				watch_t *watch = registry_get(monitor->registry, root->watchref);
				if (watch) {
					scanner_scan(root->resource->path, watch, &current_stats);
					root->profile->stability->prev_stats = root->profile->stability->stats;
					root->profile->stability->stats = current_stats;
					scanner_update(root->profile, root->resource->path);
				}
			}
			stability_defer(monitor, subscription);
		}
	}
	free(path);
}

/* Check batch timeouts and trigger processing when activity gaps are detected */
void events_batch(monitor_t *monitor) {
	if (!monitor || !monitor->resources || !monitor->resources->buckets) return;

	struct timespec current_time;
	clock_gettime(CLOCK_MONOTONIC, &current_time);

	/* Iterate through all resources to check active batch timeouts */
	for (size_t i = 0; i < monitor->resources->bucket_count; i++) {
		resource_t *resource = monitor->resources->buckets[i];
		while (resource) {
			if (!resource->timeout_active) {
				resource = resource->next;
				continue;
			}

			/* Check if batch timeout has expired using current active duration */
			struct timespec timeout_end = resource->timeout_start;
			timespec_add(&timeout_end, resource->current_timeout);

			bool timeout_expired = timespec_after(&current_time, &timeout_end);
			if (!timeout_expired) {
				resource = resource->next;
				continue;
			}

			/* Timeout window expired, check if activity gap exceeds threshold */
			long gap_ms = timespec_diff(&current_time, &resource->last_event);
			long threshold_ms = (resource->current_timeout * 60) / 100; /* 60% hardcoded */

			if (gap_ms < threshold_ms) {
				/* Activity gap too small, reset batch timeout start time to last event */
				resource->timeout_start = resource->last_event;
				log_message(DEBUG, "Activity continues for %s, resetting batch timeout (gap: %ldms < %ldms)",
							resource->path, gap_ms, threshold_ms);
				resource = resource->next;
				continue;
			}

			log_message(DEBUG, "Activity gap detected (%ldms >= %ldms) for %s (timeout: %dms)",
						gap_ms, threshold_ms, resource->path, resource->current_timeout);

			resource_lock(resource);
			bool has_deferred_events = resource->deferred_count > 0;
			resource_unlock(resource);

			if (has_deferred_events) {
				/* Process deferred events through stability verification */
				events_deferred(monitor, resource);
			} else {
				/* No deferred events but batch timeout expired, trigger direct stability check */
				log_message(DEBUG, "No deferred events for %s, triggering stability check", resource->path);

				/* Deactivate batch timeout */
				resource->timeout_active = false;

				/* Find subscription to trigger stability verification */
				profile_t *profile = resource->profiles;
				if (profile) {
					for (; profile; profile = profile->next) {
						if (profile->subscriptions) {
							stability_ready(monitor, profile->subscriptions, OP_DIR_CONTENT_CHANGED, 0);
						}
					}
				} else {
					log_message(WARNING, "No subscription found for %s", resource->path);
				}
			}

			resource = resource->next;
		}
	}
}

/* Initialize a sync request structure */
void events_sync_init(sync_t *sync) {
	if (!sync) return;

	sync->paths = NULL;
	sync->paths_count = 0;
	sync->paths_capacity = 0;
}

/* Add a path to the sync request */
bool events_sync_add(sync_t *sync, const char *path) {
	if (!sync || !path) return false;

	/* Check if path already exists to avoid duplicates */
	for (int i = 0; i < sync->paths_count; i++) {
		if (strcmp(sync->paths[i], path) == 0) {
			return true; /* Already exists, no need to add */
		}
	}

	/* Expand array if needed */
	if (sync->paths_count >= sync->paths_capacity) {
		int new_capacity = sync->paths_capacity == 0 ? 4 : sync->paths_capacity * 2;
		char **new_paths = realloc(sync->paths, new_capacity * sizeof(char *));
		if (!new_paths) {
			log_message(ERROR, "Failed to allocate memory for sync request paths");
			return false;
		}
		sync->paths = new_paths;
		sync->paths_capacity = new_capacity;
	}

	/* Add the path */
	sync->paths[sync->paths_count] = strdup(path);
	if (!sync->paths[sync->paths_count]) {
		log_message(ERROR, "Failed to duplicate path for sync request: %s", path);
		return false;
	}
	sync->paths_count++;

	log_message(DEBUG, "Added path to sync request: %s", path);
	return true;
}

/* Clean up a sync request structure */
void events_sync_cleanup(sync_t *sync) {
	if (!sync) return;

	if (sync->paths) {
		for (int i = 0; i < sync->paths_count; i++) {
			free(sync->paths[i]);
		}
		free(sync->paths);
	}

	sync->paths = NULL;
	sync->paths_count = 0;
	sync->paths_capacity = 0;
}

/* Schedule an event for delayed processing */
void events_schedule(monitor_t *monitor, watchref_t watchref, event_t *event, kind_t kind) {
	if (!monitor || !event || !watchref_valid(watchref)) return;

	/* Resolve watch to get processing delay */
	watch_t *watch = registry_get(monitor->registry, watchref);
	if (!watch || watch->processing_delay <= 0) return;

	/* Calculate process time */
	struct timespec process_time;
	clock_gettime(CLOCK_MONOTONIC, &process_time);
	timespec_add(&process_time, watch->processing_delay);

	/* Look for existing delayed event for the same watch and path to enable debouncing */
	for (int i = 0; i < monitor->delayed_count; i++) {
		delayed_t *existing = &monitor->delayed_events[i];
		if (watchref_equal(existing->watchref, watchref) && strcmp(existing->event.path, event->path) == 0) {
			/* Merge event types to preserve all event information */
			existing->event.type |= event->type;

			/* Update timestamps to the most recent event */
			existing->event.time = event->time;
			existing->event.wall_time = event->wall_time;
			existing->event.user_id = event->user_id;

			/* Update the process time for the delayed event */
			existing->process_time = process_time;

			log_message(DEBUG, "Updated existing delayed event for %s (watch: %s) to process in %d ms",
						existing->event.path, watch->name, watch->processing_delay);
			return;
		}
	}

	/* No existing event found, create new entry */
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

	/* Store the delayed event, preserving the original path */
	delayed_t *delayed = &monitor->delayed_events[monitor->delayed_count++];
	delayed->event.path = strdup(event->path);
	delayed->event.type = event->type;
	delayed->event.time = event->time;
	delayed->event.wall_time = event->wall_time;
	delayed->event.user_id = event->user_id;
	delayed->watchref = watchref;
	delayed->kind = kind;
	delayed->process_time = process_time;

	log_message(DEBUG, "Scheduled delayed event for %s (watch: %s) in %d ms", event->path,
				watch->name, watch->processing_delay);
}

/* Process delayed events that are ready */
void events_delayed(monitor_t *monitor) {
	if (!monitor || !monitor->delayed_events || monitor->delayed_count == 0) return;

	struct timespec current_time;
	clock_gettime(CLOCK_MONOTONIC, &current_time);

	int processed = 0;
	int write_idx = 0;
	for (int read_idx = 0; read_idx < monitor->delayed_count; read_idx++) {
		delayed_t *delayed = &monitor->delayed_events[read_idx];

		/* Check if this event is ready to process */
		if (!timespec_before(&current_time, &delayed->process_time)) {
			/* Resolve watch reference at processing time */
			watch_t *watch = registry_get(monitor->registry, delayed->watchref);
			if (!watch) {
				/* Watch was deactivated, skip this event */
				log_message(DEBUG, "Delayed event for %s skipped, watch was deactivated", delayed->event.path);
				free(delayed->event.path);
				processed++;
				continue;
			}

			log_message(DEBUG, "Delayed event for %s (watch: %s) expired, initiating stability check",
						delayed->event.path, watch->name);

			/* Pass the event to the main processing function */
			events_process(monitor, delayed->watchref, &delayed->event, delayed->kind, false);

			/* The event is now handled, so we can remove it from the delayed queue */
			free(delayed->event.path);
			processed++;
		} else {
			/* This event is not ready yet, keep it */
			if (write_idx != read_idx) {
				monitor->delayed_events[write_idx] = monitor->delayed_events[read_idx];
			}
			write_idx++;
		}
	}
	monitor->delayed_count = write_idx;

	if (processed > 0) {
		log_message(DEBUG, "Processed %d delayed events", processed);
	}
}

/* Calculate timeout for delayed events, deferred events, and deferred checks */
int events_timeout(monitor_t *monitor, struct timespec *current_time) {
	if (!monitor || !current_time) return -1; /* No timeout needed */

	long shortest_timeout_ms = -1; /* No timeout by default */

	/* Check delayed events timeout */
	if (monitor->delayed_events && monitor->delayed_count > 0) {
		struct timespec earliest = monitor->delayed_events[0].process_time;

		/* Find the earliest process time in the delayed queue */
		for (int i = 1; i < monitor->delayed_count; i++) {
			delayed_t *delayed = &monitor->delayed_events[i];
			if (timespec_before(&delayed->process_time, &earliest)) {
				earliest = delayed->process_time;
			}
		}

		/* Calculate timeout in milliseconds */
		long delayed_timeout_ms;
		if (timespec_after(current_time, &earliest)) {
			delayed_timeout_ms = 1; /* Already overdue */
		} else {
			delayed_timeout_ms = timespec_diff(&earliest, current_time);
		}

		if (delayed_timeout_ms >= 0) {
			shortest_timeout_ms = delayed_timeout_ms;
		}
	}

	/* Check batch timeout expiration for deferred events */
	if (monitor->resources && monitor->resources->buckets) {
		struct timespec soonest_batch_timeout = {0};
		bool has_batch_timeouts = false;

		/* Iterate through resources with active batch timeouts */
		for (size_t i = 0; i < monitor->resources->bucket_count; i++) {
			resource_t *resource = monitor->resources->buckets[i];
			while (resource) {
				if (resource->timeout_active) {
					/* Calculate when this batch timeout should expire */
					struct timespec timeout_expires = resource->timeout_start;
					timespec_add(&timeout_expires, resource->current_timeout);

					if (!has_batch_timeouts || timespec_before(&timeout_expires, &soonest_batch_timeout)) {
						soonest_batch_timeout = timeout_expires;
						has_batch_timeouts = true;
					}
				}
				resource = resource->next;
			}
		}

		if (has_batch_timeouts) {
			long batch_timeout_ms;
			if (timespec_after(current_time, &soonest_batch_timeout)) {
				batch_timeout_ms = 1; /* Already overdue */
			} else {
				batch_timeout_ms = timespec_diff(&soonest_batch_timeout, current_time);
			}

			if (batch_timeout_ms >= 0) {
				if (shortest_timeout_ms < 0 || batch_timeout_ms < shortest_timeout_ms) {
					shortest_timeout_ms = batch_timeout_ms;
				}
			}
		}
	}

	/* Check deferred checks timeout from queue */
	if (monitor->check_queue && monitor->check_queue->size > 0) {
		/* Get the earliest check time */
		struct timespec next_check = monitor->check_queue->items[0].next_check;

		long deferred_timeout_ms;
		if (timespec_after(current_time, &next_check)) {
			deferred_timeout_ms = 1; /* Already overdue */
		} else {
			deferred_timeout_ms = timespec_diff(&next_check, current_time);
		}

		if (deferred_timeout_ms >= 0) {
			if (shortest_timeout_ms < 0 || deferred_timeout_ms < shortest_timeout_ms) {
				shortest_timeout_ms = deferred_timeout_ms;
			}
		}
	}

	return shortest_timeout_ms >= 0 ? (int) shortest_timeout_ms : -1;
}

/* Convert kqueue flags to filter type bitmask */
static filter_t flags_to_filter(uint32_t flags) {
	filter_t event = EVENT_NONE;

	/* Structural changes to directories */
	if (flags & (NOTE_WRITE | NOTE_EXTEND)) {
		event |= EVENT_STRUCTURE;
	}

	/* Metadata changes */
	if (flags & (NOTE_ATTRIB | NOTE_LINK)) {
		event |= EVENT_METADATA;
	}

	/* File content changes */
	if (flags & (NOTE_DELETE | NOTE_RENAME | NOTE_REVOKE | NOTE_WRITE)) {
		event |= EVENT_CONTENT;
	}

	return event;
}

/* Handle kqueue events */
bool events_handle(monitor_t *monitor, struct kevent *events, int event_count, struct timespec *time, sync_t *sync) {
	if (!monitor || !events || event_count <= 0) return false;

	/* Process new events */
	for (int i = 0; i < event_count; i++) {
		int fd = (int) events[i].ident;

		/* Find all watches that share this file descriptor */
		for (int j = 0; j < monitor->num_watches; j++) {
			watcher_t *watcher = monitor->watches[j];

			if (watcher->wd == fd) {
				event_t event;
				memset(&event, 0, sizeof(event));
				event.path = watcher->path;
				event.type = flags_to_filter(events[i].fflags);
				event.time = *time;
				clock_gettime(CLOCK_REALTIME, &event.wall_time);
				event.user_id = getuid();

				watch_t *watch = registry_get(monitor->registry, watcher->watchref);
				if (!watch) continue;

				kind_t kind = (watch->target == WATCH_FILE) ? ENTITY_FILE : ENTITY_DIRECTORY;

				log_message(DEBUG, "Event: path=%s, flags=0x%x -> type=%s (watch: %s)", watcher->path,
							events[i].fflags, filter_to_string(event.type), watch->name);

				/* Proactive validation for directory events on NOTE_WRITE */
				if (watch->target == WATCH_DIRECTORY && (events[i].fflags & NOTE_WRITE)) {
					log_message(DEBUG, "Write event on dir %s, requesting validation", watcher->path);
					if (sync) {
						events_sync_add(sync, watcher->path);
					}
				}

				/* Keep watchref before pending_process, as watcher may be freed during deactivation */
				watchref_t savedref = watcher->watchref;

				/* Process pending watches for any event that might create new paths */
				if (monitor->num_pending > 0) {
					pending_process(monitor, watcher->path);
				}

				/* Check if this watch has a processing delay configured */
				if (watch->processing_delay > 0) {
					/* Schedule the event for delayed processing */
					events_schedule(monitor, savedref, &event, kind);
				} else {
					/* Process the event immediately */
					events_process(monitor, savedref, &event, kind, false);
				}
			}
		}
	}

	return true;
}

/* Calculate timeouts for monitor based on deferred checks and delayed events */
struct timespec *timeout_calculate(monitor_t *monitor, struct timespec *timeout, struct timespec *current_time) {
	if (!monitor || !timeout || !current_time) return NULL;

	/* Initialize timeout buffer */
	memset(timeout, 0, sizeof(*timeout));

	/* Get unified timeout from events_timeout() */
	int timeout_ms = events_timeout(monitor, current_time);

	if (timeout_ms >= 0) {
		/* Convert milliseconds to timespec */
		timeout->tv_sec = timeout_ms / 1000;
		timeout->tv_nsec = (timeout_ms % 1000) * 1000000;

		/* Ensure minimum sensible timeout values */
		if (timeout->tv_sec == 0 && timeout->tv_nsec < 10000000) {
			timeout->tv_nsec = 10000000; /* 10ms minimum */
		}

		/* Debug output for the queue status if we have deferred checks */
		if (monitor->check_queue && monitor->check_queue->size > 0 && monitor->check_queue->items[0].path) {
			log_message(DEBUG, "Deferred queue status: %d entries, next check for path %s, timeout: %d ms",
						monitor->check_queue->size, monitor->check_queue->items[0].path, timeout_ms);
		}

		return timeout;
	} else {
		log_message(DEBUG, "No pending directory activity, delayed events, or batch timeouts, waiting indefinitely");
		return NULL;
	}
}

/* Convert operation type to corresponding event type */
filter_t operation_to_filter(optype_t optype) {
	switch (optype) {
		case OP_FILE_CONTENT_CHANGED:
		case OP_FILE_DELETED:
		case OP_FILE_RENAMED:
		case OP_FILE_CREATED:
			return EVENT_CONTENT;

		case OP_DIR_CONTENT_CHANGED:
		case OP_DIR_DELETED:
		case OP_DIR_CREATED:
			return EVENT_STRUCTURE;

		case OP_FILE_METADATA_CHANGED:
		case OP_DIR_METADATA_CHANGED:
			return EVENT_METADATA;

		default:
			return EVENT_NONE;
	}
}

/* Determine operation type based on subscription and event type */
optype_t events_operation(monitor_t *monitor, subscription_t *subscription, filter_t filter) {
	if (!subscription) return OP_NONE;

	/* Update resource change flags based on the new event type */
	if (filter & EVENT_STRUCTURE) subscription->resource->structure_changed = true;
	if (filter & EVENT_METADATA) subscription->resource->metadata_changed = true;
	if (filter & EVENT_CONTENT) subscription->resource->content_changed = true;

	/* Check current existence vs tracked existence */
	struct stat info;
	bool exists_now = (stat(subscription->resource->path, &info) == 0);

	optype_t determined_op = OP_NONE;

	if (subscription->resource->exists && !exists_now) {
		/* Deletion */
		determined_op = (subscription->resource->kind == ENTITY_FILE) ? OP_FILE_DELETED : OP_DIR_DELETED;
		log_message(DEBUG, "Entity %s detected as DELETED", subscription->resource->path);
		subscription->resource->exists = false;
	} else if (!subscription->resource->exists && exists_now) {
		/* Creation */
		determined_op = (subscription->resource->kind == ENTITY_FILE) ? OP_FILE_CREATED : OP_DIR_CREATED;
		log_message(DEBUG, "Entity %s detected as CREATED", subscription->resource->path);
		subscription->resource->exists = true;

		/* Update type if it was unknown */
		if (subscription->resource->kind == ENTITY_UNKNOWN) {
			if (S_ISDIR(info.st_mode)) subscription->resource->kind = ENTITY_DIRECTORY;
			else if (S_ISREG(info.st_mode)) subscription->resource->kind = ENTITY_FILE;
		}

		/* For directory creation, gather initial stats */
		if (subscription->resource->kind == ENTITY_DIRECTORY) {
			/* Profile stability state should already be created by resources_subscription() */

			if (!subscription->profile->stability) {
				subscription->profile->stability = stability_create();
			}
			if (subscription->profile->stability) {
				watch_t *watch = registry_get(monitor->registry, subscription->watchref);
				if (watch) {
					scanner_scan(subscription->resource->path, watch, &subscription->profile->stability->stats);
					subscription->profile->stability->prev_stats = subscription->profile->stability->stats;
				}
			}
		}
	} else if (exists_now) {
		/* Existed before and exists now - check for other changes */
		subscription->resource->exists = true;

		/* Prioritize which operation to report if multiple flags are set */
		if (subscription->resource->kind == ENTITY_DIRECTORY && (subscription->resource->content_changed ||
																 subscription->resource->structure_changed)) {
			determined_op = OP_DIR_CONTENT_CHANGED;
			log_message(DEBUG, "Directory %s structure changed", subscription->resource->path);
		} else if (subscription->resource->kind == ENTITY_FILE && subscription->resource->structure_changed) {
			determined_op = OP_FILE_CONTENT_CHANGED;
			log_message(DEBUG, "File %s content changed", subscription->resource->path);
		} else if (subscription->resource->kind == ENTITY_FILE && subscription->resource->content_changed) {
			determined_op = OP_FILE_RENAMED;
			log_message(DEBUG, "File %s renamed or replaced", subscription->resource->path);
		} else if (subscription->resource->metadata_changed) {
			determined_op = (subscription->resource->kind == ENTITY_FILE) ? OP_FILE_METADATA_CHANGED : OP_DIR_METADATA_CHANGED;
			log_message(DEBUG, "Entity %s metadata changed", subscription->resource->path);
		} else {
			log_message(DEBUG, "Entity %s exists but no relevant changes detected", subscription->resource->path);
			determined_op = OP_NONE;
		}
	} else {
		log_message(DEBUG, "Entity %s still does not exist", subscription->resource->path);
		determined_op = OP_NONE;
	}

	return determined_op;
}

/* Process a single filesystem event */
bool events_process(monitor_t *monitor, watchref_t watchref, event_t *event, kind_t kind, bool is_deferred) {
	if (event == NULL || event->path == NULL) return false;

	watch_t *watch = registry_get(monitor->registry, watchref);
	if (!watch) {
		return false; /* Error already logged by registry */
	}

	/* Handle internal watches - they only trigger pending_process, not commands */
	if (watch->name != NULL && strncmp(watch->name, "__", 2) == 0) {
		/* Specifically allow __config_file__ to pass through for hot-reloading */
		if (strcmp(watch->name, "__config_file__") != 0) {
			log_message(DEBUG, "Filtered proxy watch event: %s (watch: %s), served pending resolution purpose",
						event->path, watch->name);
			return false; /* Don't process further, event has served its purpose */
		}
	}

	/* Additional safety checks for watch structure */
	if (!watch->name || !watch->command) {
		log_message(ERROR, "events_process: Watch has NULL name or command");
		return false;
	}

	log_message(DEBUG, "Processing event for %s (watch: %s, type: %s)", event->path, watch->name,
				filter_to_string(event->type));

	/* Check if a monitored file is excluded by patterns */
	if (kind == ENTITY_FILE) {
		/* For file events, check if the file itself is excluded */
		if (config_exclude_match(watch, event->path)) {
			log_message(DEBUG, "Skipping excluded file: %s", event->path);
			return false;
		}
	}

	/* Handle config file events specially for hot reload */
	if (strcmp(watch->name, "__config_file__") == 0) {
		log_message(NOTICE, "Configuration changed: %s", event->path);
		monitor->reload = true;
		log_message(DEBUG, "Configuration reload requested");
		return true;
	}

	/* Get subscription using the event path and watch reference */
	subscription_t *subscription = resources_subscription(monitor->resources, monitor->registry, event->path, watchref, kind);
	if (subscription == NULL) {
		return false; /* Error already logged by resources_subscription */
	}

	/* Check if this watch has batch timeout configured */
	if (watch->batch_timeout > 0 && !is_deferred) {
		/* Get root resource to ensure consistent gating across watch hierarchies */
		subscription_t *root = stability_root(monitor, subscription);
		resource_t *resource = root ? root->resource : subscription->resource;

		events_defer(monitor, resource, watchref, event, kind);
		return false; /* Stop further processing */
	}

	/* Check if command is executing for this path or its root - defer events during execution */
	subscription_t *root = stability_root(monitor, subscription);
	resource_t *executing_resource = root ? root->resource : subscription->resource;
	if (executing_resource->executing) {
		log_message(DEBUG, "Deferring event for %s, command is currently executing for %s",
					event->path, executing_resource->path);
		/* Defer event on the resource itself until the current command completes */
		events_defer(monitor, executing_resource, watchref, event, kind);
		return false;
	}

	/* Update timestamps before determining operation */
	subscription->resource->last_time = event->time;
	subscription->resource->wall_time = event->wall_time;

	/* Determine the logical operation */
	optype_t optype = events_operation(monitor, subscription, event->type);
	if (optype == OP_NONE) return false; /* No relevant change detected */

	log_message(DEBUG, "Determined operation type %d for %s", optype, subscription->resource->path);

	/* Handle directory content changes, check for deleted child directories */
	if (optype == OP_DIR_CONTENT_CHANGED && monitor->num_pending > 0) {
		log_message(DEBUG, "Directory content changed, checking for deleted child directories: %s",
					subscription->resource->path);

		/* Check all pending watches to see if any are waiting for children of this directory */
		for (int i = monitor->num_pending - 1; i >= 0; i--) {
			pending_t *pending = monitor->pending[i];
			if (!pending || !pending->current_parent) continue;

			/* Check if this pending watch's current_parent is a child of the changed directory */
			size_t parent_len = strlen(subscription->resource->path);
			if (strlen(pending->current_parent) > parent_len &&
				strncmp(pending->current_parent, subscription->resource->path, parent_len) == 0 &&
				pending->current_parent[parent_len] == '/') {
				/* Check if the current_parent still exists */
				struct stat info;
				if (stat(pending->current_parent, &info) != 0) {
					log_message(DEBUG, "Detected deletion of pending watch parent: %s", pending->current_parent);
					pending_delete(monitor, pending->current_parent);
				}
			}
		}
	}

	/* Check if operation is included in watch mask */
	filter_t filter_for_mask = operation_to_filter(optype);
	if ((watch->filter & filter_for_mask) == 0) {
		log_message(DEBUG, "Operation maps to event type %s, which is not in watch mask for %s",
					filter_to_string(filter_for_mask), watch->name);
		return false;
	}

	/* Check debounce/deferral logic */
	if (stability_ready(monitor, subscription, optype, command_get_debounce_time())) {
		/* Execute command immediately (only for non-directory-content changes) */
		event_t synthetic_event = {
			.path = subscription->resource->path,
			.type = filter_for_mask,
			.time = subscription->resource->last_time,
			.wall_time = subscription->resource->wall_time,
			.user_id = event->user_id};

		log_message(INFO, "Executing command for %s (watch: %s, operation: %d)", subscription->resource->path,
					watch->name, optype);

		/* Set executing flag to prevent race condition for async commands */
		subscription_t *root = stability_root(monitor, subscription);
		if (root) {
			root->resource->executing = true;
		} else {
			subscription->resource->executing = true;
		}

		if (command_execute(monitor, watchref, &synthetic_event, true)) {
			log_message(INFO, "Command execution successful for %s", subscription->resource->path);

			/* Update last command time and reset change flags */
			subscription->command_time = subscription->resource->last_time.tv_sec;
			subscription->resource->structure_changed = false;
			subscription->resource->metadata_changed = false;
			subscription->resource->content_changed = false;

			return true;
		} else {
			log_message(WARNING, "Command execution failed for %s", subscription->resource->path);

			/* Clear executing flag on failure since command won't run */
			if (root) {
				root->resource->executing = false;
			} else {
				subscription->resource->executing = false;
			}
			return false;
		}
	} else {
		log_message(DEBUG, "Command for %s (optype %d) deferred or debounced",
					subscription->resource->path, optype);
		return false;
	}
}
