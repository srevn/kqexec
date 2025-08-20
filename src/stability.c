#include "stability.h"

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "command.h"
#include "events.h"
#include "logger.h"
#include "monitor.h"
#include "queue.h"
#include "registry.h"
#include "resource.h"
#include "scanner.h"
#include "utilities.h"

/* Create a stability state */
stability_t *stability_create(void) {
	stability_t *stability = calloc(1, sizeof(stability_t));
	if (!stability) {
		log_message(ERROR, "Failed to allocate stability state");
		return NULL;
	}

	stability->stability_lost = false;
	stability->reference_init = false;
	stability->checks_count = 0;
	stability->checks_failed = 0;
	stability->checks_required = 0;
	stability->unstable_count = 0;
	stability->delta_files = 0;
	stability->delta_dirs = 0;
	stability->delta_depth = 0;
	stability->delta_size = 0;

	return stability;
}

/* Destroy a stability state */
void stability_destroy(stability_t *stability) {
	if (stability) {
		free(stability);
	}
}

/* Find the root subscription for a given subscription */
subscription_t *stability_root(monitor_t *monitor, subscription_t *subscription) {
	if (!monitor || !subscription || !subscription->resource) return NULL;

	/* Get the watch for this subscription */
	watch_t *watch = registry_get(monitor->registry, subscription->watchref);
	if (!watch || !watch->path) {
		log_message(WARNING, "Invalid watch info for subscription %s", subscription->resource->path);
		return NULL;
	}

	/* If current subscription is already the root, return it */
	if (strcmp(subscription->resource->path, watch->path) == 0) return subscription;

	/* Otherwise, get the subscription for the watch path */
	return resources_subscription(monitor->resources, monitor->registry, watch->path, subscription->watchref, ENTITY_DIRECTORY);
}

/* Determine if a command should be executed based on operation type and debouncing */
bool stability_ready(monitor_t *monitor, subscription_t *subscription, optype_t optype, int base_debounce_ms) {
	if (!subscription) return false;

	struct timespec current_time;
	clock_gettime(CLOCK_MONOTONIC, &current_time);

	/* Record activity (updates timestamps and root tree time) */
	scanner_track(monitor, subscription, optype);

	/* Defer all directory-related operations to the stability system */
	if (subscription->resource->kind == ENTITY_DIRECTORY) {
		subscription_t *root = stability_root(monitor, subscription);
		if (!root || !monitor) return false;

		/* Ensure scanner is created for this profile */
		if (!root->profile->scanner) {
			root->profile->scanner = scanner_create(root->resource->path);
			if (!root->profile->scanner) {
				log_message(ERROR, "Failed to create scanner for directory: %s", root->resource->path);
				return false;
			}
		}

		/* Always trigger a queued check; queue deduplicates */
		root->profile->scanner->active = true;
		root->profile->stability->stability_lost = false;

		log_message(DEBUG, "Directory content change for %s, marked root %s as active, command deferred",
					subscription->resource->path, root->resource->path);

		stability_queue(monitor, root);
		log_message(DEBUG, "Added directory %s to queued check queue", root->resource->path);
		return false; /* Decision happens later */
	}

	/* Standard time-based debounce for non-directory-content operations */
	long elapsed_command = (current_time.tv_sec - subscription->command_time) * 1000;

	/* Adjust debounce based on operation type */
	int effective_debounce_ms = base_debounce_ms;
	switch (optype) {
		case OP_FILE_DELETED:
		case OP_DIR_DELETED:
		case OP_FILE_CREATED:
		case OP_DIR_CREATED:
			effective_debounce_ms = base_debounce_ms > 0 ? base_debounce_ms / 4 : 0; /* Shorter debounce */
			break;
		case OP_FILE_CONTENT_CHANGED:
			effective_debounce_ms = base_debounce_ms > 0 ? base_debounce_ms / 2 : 0; /* Medium debounce */
			break;
		default: /* METADATA, RENAME etc. use default */
			break;
	}
	if (effective_debounce_ms < 0) effective_debounce_ms = 0;

	log_message(DEBUG, "Debounce check for %s: %ld ms elapsed, %d ms required",
				subscription->resource->path, elapsed_command, effective_debounce_ms);

	/* Check if enough time has passed or if it's the first command */
	if (elapsed_command >= effective_debounce_ms || subscription->command_time == 0) {
		log_message(DEBUG, "Debounce check passed for %s, command allowed", subscription->resource->path);
		return true;
	}

	log_message(DEBUG, "Command execution debounced for %s", subscription->resource->path);
	return false;
}

/* Queue a stability check for a directory */
void stability_queue(monitor_t *monitor, subscription_t *subscription) {
	if (!monitor || !subscription) {
		log_message(WARNING, "Cannot queue stability check. invalid monitor or subscription");
		return;
	}

	watch_t *subscription_watch = registry_get(monitor->registry, subscription->watchref);
	if (!subscription->resource || !subscription_watch) {
		log_message(WARNING, "Cannot queue stability check, subscription has null resource or watch");
		return;
	}

	/* Find the root subscription for this entity */
	subscription_t *root = stability_root(monitor, subscription);
	if (!root) {
		/* If no root found, use the provided subscription if it's a directory */
		if (subscription->resource->kind == ENTITY_DIRECTORY) {
			root = subscription;
		} else {
			log_message(WARNING, "Cannot schedule check for %s, no root subscription found", subscription->resource->path);
			return;
		}
	}

	/* Lock the resource to ensure atomic updates to its state */
	resource_lock(root->resource);

	/* Ensure the root subscription has a scanner before we use it */
	if (!root->profile->scanner) {
		root->profile->scanner = scanner_create(root->resource->path);
		if (!root->profile->scanner) {
			log_message(ERROR, "Failed to create scanner for root %s in stability_queue", root->resource->path);
			resource_unlock(root->resource);
			return;
		}
	}

	/* Force root subscription to be active and update its activity time to now */
	root->profile->scanner->active = true;
	root->profile->stability->stability_lost = false;
	clock_gettime(CLOCK_MONOTONIC, &root->profile->scanner->latest_time);

	/* Initialize reference stats if needed */
	if (!root->profile->stability->reference_init) {
		root->profile->stability->ref_stats = root->profile->stability->stats;
		root->profile->stability->reference_init = true;
		log_message(DEBUG, "Initialized reference stats for %s: files=%d, dirs=%d, depth=%d",
					root->resource->path, root->profile->stability->stats.local_files,
					root->profile->stability->stats.local_dirs, root->profile->stability->stats.depth);
	}

	/* Calculate check time based on quiet period */
	struct timespec current_time;
	clock_gettime(CLOCK_MONOTONIC, &current_time);

	/* Ensure we don't use a timestamp in the past */
	if (root->profile->scanner->latest_time.tv_sec < current_time.tv_sec - 10) {
		log_message(DEBUG, "Last activity timestamp for %s is too old, using current time", root->resource->path);
		root->profile->scanner->latest_time = current_time;
	}

	/* Check if there's already a pending check to implement lock-in behavior */
	int existing_index = queue_find(monitor->check_queue, root->resource->path);

	if (existing_index >= 0) {
		/* A check is already pending. Use maximum of locked-in period and new calculation */
		check_t *check = &monitor->check_queue->items[existing_index];

		/* Add the current watch to the existing check to merge them */
		watch_t *root_watch = registry_get(monitor->registry, root->watchref);
		if (!queue_add(check, root->watchref)) {
			log_message(WARNING, "Failed to merge watch %s into existing check for %s",
						root_watch ? root_watch->name : "unknown", root->resource->path);
		} else {
			log_message(DEBUG, "Merged watch %s into existing queued check for %s",
						root_watch ? root_watch->name : "unknown", root->resource->path);
		}

		long locked_quiet = check->scheduled_quiet;

		if (locked_quiet <= 0) {
			/* Fallback if the period wasn't locked in correctly */
			locked_quiet = scanner_delay(monitor, root);
			check->scheduled_quiet = locked_quiet;
		}

		/* Calculate current complexity and use maximum with locked-in period */
		long current_complexity = scanner_delay(monitor, root);

		/* Allow responsive drops if new period is significantly lower */
		double responsiveness_factor = complexity_responsiveness(root_watch ? root_watch->complexity : 1.0);
		long effective_quiet;
		if (current_complexity < locked_quiet && current_complexity < (long) (locked_quiet * responsiveness_factor)) {
			/* Significant drop - use calculated period for responsiveness */
			effective_quiet = current_complexity;
		} else {
			/* Use maximum for stability */
			effective_quiet = (current_complexity > locked_quiet) ? current_complexity : locked_quiet;
		}

		/* Update activity time for true timer refresh */
		clock_gettime(CLOCK_MONOTONIC, &root->profile->scanner->latest_time);

		/* Use existing scheduling logic with effective period */
		stability_delay(monitor, check, root, &root->profile->scanner->latest_time, effective_quiet);

		log_message(DEBUG, "Event received, quiet period of %ld ms for %s (locked: %ld ms, calculated: %ld ms)",
					effective_quiet, root->resource->path, locked_quiet, current_complexity);
		resource_unlock(root->resource);
		return;
	}

	/* Calculate quiet period for first event of this burst */
	long required_quiet = scanner_delay(monitor, root);
	log_message(DEBUG, "Calculated new quiet period for %s: %ld ms (first event of burst)",
				root->resource->path, required_quiet);

	struct timespec next_check = root->profile->scanner->latest_time;
	timespec_add(&next_check, required_quiet);

	/* Add to queue */
	queue_upsert(monitor->check_queue, root->resource->path, root->watchref, next_check);

	/* Store the calculated quiet period for consistent use */
	int queue_index = queue_find(monitor->check_queue, root->resource->path);
	if (queue_index >= 0) {
		monitor->check_queue->items[queue_index].scheduled_quiet = required_quiet;
	}

	log_message(DEBUG, "Queued check for %s: in %ld ms (directory with %d files, %d dirs)",
				root->resource->path, required_quiet, root->profile->stability->stats.local_files,
				root->profile->stability->stats.local_dirs);

	resource_unlock(root->resource);
}

/* Get the root subscription for a queued check */
subscription_t *stability_entry(monitor_t *monitor, check_t *check) {
	if (!monitor || !check || check->num_watches <= 0) return NULL;

	/* Use the first watch reference to find the subscription. All watches for a check share the same path */
	watchref_t primaryref = check->watchrefs[0];

	subscription_t *root = resources_subscription(monitor->resources, monitor->registry, check->path, primaryref, ENTITY_DIRECTORY);
	if (!root) {
		log_message(WARNING, "Cannot find subscription for %s", check->path);
		return NULL;
	}

	return root;
}

/* Check if quiet period has elapsed for a directory */
bool stability_quiet(monitor_t *monitor, subscription_t *root, struct timespec *current_time, long required_quiet) {
	if (!monitor || !root || !current_time) return false;

	struct timespec scanner_time = root->profile->scanner->latest_time;
	long elapsed_ms;

	/* Robustly calculate elapsed time in milliseconds */
	if (timespec_before(current_time, &scanner_time)) {
		elapsed_ms = 0; /* Clock went backwards, treat as no time elapsed */
	} else {
		elapsed_ms = timespec_diff(current_time, &scanner_time);
	}

	log_message(DEBUG, "Path %s: %ld ms elapsed of %ld ms quiet period, direct_entries=%d+%d, recursive_entries=%d+%d, depth=%d",
				root->resource->path, elapsed_ms, required_quiet, root->profile->stability->stats.local_files,
				root->profile->stability->stats.local_dirs, root->profile->stability->stats.tree_files,
				root->profile->stability->stats.tree_dirs, root->profile->stability->stats.depth);

	return scanner_ready(monitor, root, current_time, required_quiet);
}

/* Requeue a queued check */
void stability_delay(monitor_t *monitor, check_t *check, subscription_t *root, struct timespec *current_time, long required_quiet) {
	if (!monitor || !check || !root || !current_time) return;

	/* Update next check time based on latest activity */
	struct timespec next_check = root->profile->scanner->latest_time;
	timespec_add(&next_check, required_quiet);

	/* Update the check in place and restore heap property */
	check->next_check = next_check;
	check->scheduled_quiet = required_quiet;
	heap_down(monitor->check_queue->items, monitor->check_queue->size, 0);
}

/* Check for new directories in recursive watches */
bool stability_new(monitor_t *monitor, check_t *check) {
	if (!monitor || !check) return false;

	int prev_num_watches = monitor->num_watches;

	/* For recursive watches, scan for new directories */
	for (int i = 0; i < check->num_watches; i++) {
		watch_t *watch = registry_get(monitor->registry, check->watchrefs[i]);
		if (watch && watch->recursive) {
			monitor_tree(monitor, check->path, check->watchrefs[i]);
		}
	}

	return monitor->num_watches > prev_num_watches;
}

/* Perform directory stability verification */
bool stability_scan(monitor_t *monitor, subscription_t *root, const char *path, stats_t *stats_out) {
	if (!monitor || !root || !path || !stats_out) return false;

	/* Perform recursive stability verification */
	watch_t *watch = registry_get(monitor->registry, root->watchref);
	bool is_stable = scanner_stable(monitor, watch, path, stats_out);

	/* Always update stats and cumulative changes, even if unstable, to track progress */
	root->profile->stability->checks_failed = is_stable ? 0 : root->profile->stability->checks_failed;

	/* Save previous stats for comparison before overwriting */
	stats_t temp_stats = root->profile->stability->stats;
	root->profile->stability->stats = *stats_out;

	/* Update cumulative changes based on the difference */
	root->profile->stability->prev_stats = temp_stats;
	scanner_update(root->profile, root->resource->path);

	log_message(DEBUG, "Stability scan for %s: files=%d, dirs=%d, size=%s, recursive_files=%d, recursive_dirs=%d, max_depth=%d",
				path, stats_out->local_files, stats_out->local_dirs, format_size((ssize_t) stats_out->tree_size, false),
				stats_out->tree_files, stats_out->tree_dirs, stats_out->max_depth);

	return is_stable;
}

/* Handle scan failure cases */
failure_t stability_fail(monitor_t *monitor, check_t *check, subscription_t *root, struct timespec *current_time) {
	if (!monitor || !check || !root || !current_time) {
		return SCAN_FAILURE_TEMPORARY_ERROR;
	}

	/* Check if the directory still exists */
	struct stat info;
	if (stat(check->path, &info) != 0 || !S_ISDIR(info.st_mode)) {
		root->profile->stability->checks_failed++;
		log_message(DEBUG, "Directory %s not found (attempt %d/%d)", check->path,
					root->profile->stability->checks_failed, MAX_CHECKS_FAILED);

		/* After multiple consecutive failures, consider it permanently deleted */
		if (root->profile->stability->checks_failed >= MAX_CHECKS_FAILED) {
			log_message(INFO, "Directory %s confirmed deleted after %d failed checks, cleaning up",
						check->path, root->profile->stability->checks_failed);

			/* Mark as not active for all watches */
			root->profile->scanner->active = false;
			root->resource->exists = false;

			return SCAN_FAILURE_MAX_ATTEMPTS_REACHED;
		}

		return SCAN_FAILURE_DIRECTORY_DELETED;
	} else {
		/* Scan failed for other reasons */
		root->profile->stability->checks_failed = 0; /* Reset counter */
		return SCAN_FAILURE_TEMPORARY_ERROR;
	}
}

/* Calculate required stability checks based on complexity */
int stability_require(monitor_t *monitor, subscription_t *root, const stats_t *current_stats) {
	if (!monitor || !root || !current_stats) return 1;

	int tree_entries = current_stats->tree_files + current_stats->tree_dirs;
	int tree_depth = current_stats->max_depth > 0 ? current_stats->max_depth : current_stats->depth;

	/* Use cumulative changes for adapting stability requirements */
	int abs_file_change = abs(root->profile->stability->delta_files);
	int abs_dir_change = abs(root->profile->stability->delta_dirs);
	int abs_depth_change = abs(root->profile->stability->delta_depth);
	int abs_change = abs_file_change + abs_dir_change;

	/* Get complexity from watch configuration */
	watch_t *watch = registry_get(monitor->registry, root->watchref);
	double complexity = watch ? watch->complexity : 1.0;

	/* Base check requirements determined by change magnitude */
	int base_checks;
	if (abs_change <= 1 && abs_depth_change == 0) {
		base_checks = 1;
		if (tree_depth >= 5 || tree_entries > 1000) base_checks = 2;
	} else if (abs_change <= 5 && abs_depth_change == 0) {
		base_checks = 2;
	} else if (abs_depth_change > 0) {
		base_checks = 2;
		if (abs_depth_change > 1) base_checks = 3;
	} else if (abs_change < 20) {
		base_checks = 2;
		if (tree_depth >= 4 || tree_entries > 500) base_checks = 3;
	} else {
		base_checks = 3;
		if (tree_depth >= 5 || tree_entries > 1000) base_checks = 4;
	}

	/* Apply complexity scaling to check requirements */
	double check_multiplier = complexity_sensitivity(complexity, 0); /* Use max sensitivity */
	int checks_required = (int) (base_checks * check_multiplier);

	/* Ensure reasonable bounds */
	if (checks_required < 1) checks_required = 1;
	if (checks_required > 6) checks_required = 6; /* Cap at 6 checks */

	return checks_required;
}

/* Determine if directory is stable */
bool stability_stable(subscription_t *root, const stats_t *current_stats, bool scan_completed) {
	if (!root || !current_stats || !scan_completed) return false;

	bool has_prev_stats = (root->profile->stability->prev_stats.local_files > 0 || root->profile->stability->prev_stats.local_dirs > 0);
	if (has_prev_stats && !scanner_compare(&root->profile->stability->prev_stats, (stats_t *) current_stats)) {
		return false;
	}

	return true;
}

/* Reset stability tracking to establish a new baseline */
void stability_reset(monitor_t *monitor, subscription_t *root) {
	if (!monitor || !root || !root->profile || !root->resource) return;

	/* Only process directories with stability tracking */
	if (root->resource->kind != ENTITY_DIRECTORY || !root->profile->stability) {
		log_message(DEBUG, "Skipping baseline reset for non-directory or non-tracked entity: %s",
					root->resource->path);
		return;
	}

	/* Scan current directory state to establish new baseline */
	stats_t new_baseline;
	memset(&new_baseline, 0, sizeof(new_baseline));
	watch_t *watch = registry_get(monitor->registry, root->watchref);
	if (watch && !scanner_scan(root->resource->path, watch, &new_baseline)) {
		log_message(WARNING, "Failed to scan directory %s for baseline reset", root->resource->path);
		return;
	}

	log_message(INFO, "Resetting baseline for %s: %d files, %d dirs, depth %d", root->resource->path,
				new_baseline.tree_files, new_baseline.tree_dirs, new_baseline.max_depth);

	/* Reset stability state to reflect new baseline as authoritative */
	root->profile->stability->stats = new_baseline;
	root->profile->stability->prev_stats = new_baseline;
	root->profile->stability->ref_stats = new_baseline;

	/* Clear all tracking deltas */
	root->profile->stability->delta_files = 0;
	root->profile->stability->delta_dirs = 0;
	root->profile->stability->delta_depth = 0;
	root->profile->stability->delta_size = 0;

	/* Reset stability verification tracking */
	root->profile->stability->checks_count = 0;
	root->profile->stability->checks_failed = 0;
	root->profile->stability->checks_required = 1;
	root->profile->stability->unstable_count = 0;
	root->profile->stability->stability_lost = false;
	root->profile->stability->reference_init = true;

	/* Clear deferred event queue */
	if (root->resource->deferred_head) {
		log_message(DEBUG, "Clearing %d deferred events for %s after processing",
					root->resource->deferred_count, root->resource->path);
		deferred_t *deferred = root->resource->deferred_head;
		while (deferred) {
			deferred_t *next_deferred = deferred->next;
			free(deferred->event.path);
			free(deferred);
			deferred = next_deferred;
		}
		root->resource->deferred_head = NULL;
		root->resource->deferred_tail = NULL;
		root->resource->deferred_count = 0;
	}

	/* Deactivate any pending batch timeout to prevent duplicate triggers */
	root->resource->batch_active = false;

	/* Clear activity tracking flag to mark the directory as idle */
	if (root->profile->scanner) {
		root->profile->scanner->active = false;
	}
}

/* Execute commands for all watches of a stable directory */
bool stability_execute(monitor_t *monitor, check_t *check, subscription_t *root, struct timespec *current_time, int *commands_executed) {
	if (!monitor || !check || !root || !current_time) return false;

	int executed_count = 0;
	const char *active_path = root->profile->scanner->active_path ? root->profile->scanner->active_path : check->path;

	/* Determine if any command needs the trigger file path (%f or %F) */
	bool needs_trigger = false;
	for (int i = 0; i < check->num_watches; i++) {
		watch_t *watch = registry_get(monitor->registry, check->watchrefs[i]);
		if (watch && (strstr(watch->command, "%f") || strstr(watch->command, "%F"))) {
			needs_trigger = true;
			break;
		}
	}

	/* If needed, find the most recently modified file to use as the trigger */
	if (needs_trigger) {
		free(root->trigger);
		root->trigger = NULL; /* Clear previous path */

		struct stat info;
		if (stat(active_path, &info) == 0 && S_ISDIR(info.st_mode)) {
			/* It's a directory, scan it for the most recent file */
			root->trigger = scanner_newest(active_path);
		} else {
			/* It's a file, or doesn't exist; use the path directly */
			root->trigger = strdup(active_path);
		}
		if (root->trigger) {
			log_message(DEBUG, "Found trigger file for %%f/%%F: %s", root->trigger);
		}
	}

	/* Create a synthetic event to pass to the command execution function */
	event_t synthetic_event = {
		.path = (char *) active_path,
		.type = EVENT_STRUCTURE,
		.time = root->resource->last_time,
		.wall_time = root->resource->wall_time,
		.user_id = getuid()};

	/* Set the executing flag for the root resource before starting any commands */
	root->resource->executing = true;

	/* Execute commands for all watches associated with the stability check */
	for (int i = 0; i < check->num_watches; i++) {
		watch_t *watch = registry_get(monitor->registry, check->watchrefs[i]);

		if (!watch) {
			log_message(DEBUG, "Skipping command for stale watch reference: ID %u (gen %u)",
						check->watchrefs[i].watch_id, check->watchrefs[i].generation);
			continue;
		}

		/* Find existing subscription in the root profile */
		subscription_t *subscription = NULL;
		for (subscription_t *existing = root->profile->subscriptions; existing != NULL; existing = existing->next) {
			if (watchref_equal(existing->watchref, check->watchrefs[i])) {
				subscription = existing;
				break;
			}
		}

		if (!subscription) {
			log_message(WARNING, "Unable to find existing subscription for %s with watch %s", check->path, watch->name);
			continue;
		}

		/* Execute command */
		log_message(INFO, "Executing queued command for %s (watch: %s)", check->path, watch->name);
		if (command_execute(monitor, check->watchrefs[i], &synthetic_event, true)) {
			executed_count++;
			/* Update the specific subscription's command time for debouncing purposes */
			subscription->command_time = current_time->tv_sec;
		} else {
			log_message(WARNING, "Command execution failed for %s (watch: %s)", check->path, watch->name);
		}
	}

	if (commands_executed) {
		*commands_executed = executed_count;
	}

	return executed_count > 0;
}

/* Main stability processing function */
void stability_process(monitor_t *monitor, struct timespec *current_time) {
	int commands_attempted = 0;
	int commands_executed = 0;
	bool item_processed = false;

	if (!monitor || !monitor->check_queue) return;

	/* Process one overdue check to maintain main loop responsiveness */
	if (monitor->check_queue->size > 0) {
		/* Get the earliest scheduled check */
		check_t *check = &monitor->check_queue->items[0];

		/* Validate the top check before processing */
		if (!check || !check->path) {
			log_message(WARNING, "Corrupted check in queue, removing");
			queue_remove(monitor->check_queue, NULL);
			return; /* Try again on next call */
		}

		/* Check if it's time to process this check */
		if (timespec_before(current_time, &check->next_check)) {
			/* Not yet time for this check. Since it's a min-heap, no other checks are ready */
			return;
		}

		item_processed = true;

		log_message(DEBUG, "Processing queued check for %s with %d watches", check->path, check->num_watches);

		/* Get the root subscription state */
		subscription_t *root = stability_entry(monitor, check);
		if (!root) {
			queue_remove(monitor->check_queue, check->path);
			return;
		}

		/* Lock the resource mutex to protect shared state during stability processing */
		pthread_mutex_lock(&root->resource->mutex);

		/* If the entity is no longer active, just remove from queue */
		if (!root->profile->scanner->active) {
			log_message(DEBUG, "Directory %s no longer active, removing from queue", check->path);
			pthread_mutex_unlock(&root->resource->mutex);
			queue_remove(monitor->check_queue, check->path);
			return;
		}

		/* Check if we're in verification mode or need to verify quiet period */
		bool elapsed_quiet = check->verifying;
		long required_quiet = check->scheduled_quiet;

		if (!elapsed_quiet) {
			/* Use the stored quiet period from when this check was scheduled */
			if (required_quiet <= 0) {
				/* Fallback: calculate if not stored (shouldn't happen) */
				required_quiet = scanner_delay(monitor, root);
				check->scheduled_quiet = required_quiet;
			}

			elapsed_quiet = stability_quiet(monitor, root, current_time, required_quiet);

			if (!elapsed_quiet) {
				/* Quiet period not yet elapsed, reschedule */
				watch_t *primary_watch = registry_get(monitor->registry, check->watchrefs[0]);
				log_message(DEBUG, "Quiet period not yet elapsed for %s (watch: %s), rescheduling",
							root->resource->path, primary_watch ? primary_watch->name : "unknown");

				stability_delay(monitor, check, root, current_time, required_quiet);
				pthread_mutex_unlock(&root->resource->mutex);
				return;
			}

			/* Quiet period has elapsed, enter verification mode */
			check->verifying = true;
			log_message(DEBUG, "Quiet period elapsed for %s, entering verification mode", check->path);
		}

		log_message(DEBUG, "Performing stability verification for %s", check->path);

		/* Check for new directories */
		if (stability_new(monitor, check)) {
			log_message(DEBUG, "Found new directories during scan, scheduling quick follow-up");

			/* This is activity, but we don't need a full quiet period reset */
			root->profile->scanner->latest_time = *current_time;

			/* Update directory stats to reflect new directory structure */
			stats_t new_stats;
			watch_t *watch = registry_get(monitor->registry, root->watchref);
			if (watch && scanner_scan(root->resource->path, watch, &new_stats)) {
				root->profile->stability->prev_stats = root->profile->stability->stats;
				root->profile->stability->stats = new_stats;
				scanner_update(root->profile, root->resource->path);
			}

			/* We stay in verification mode, but reset the check count since the scope has changed */
			root->profile->stability->checks_count = 0;
			root->profile->stability->checks_required = 0; /* Recalculate required checks */

			/* Schedule a short follow-up check instead of a full quiet period */
			struct timespec next_check = *current_time;
			timespec_add(&next_check, 200); /* 200ms */
			check->next_check = next_check;
			heap_down(monitor->check_queue->items, monitor->check_queue->size, 0);
			pthread_mutex_unlock(&root->resource->mutex);
			return;
		}

		/* Perform directory stability scan */
		stats_t current_stats;
		bool scan_completed = stability_scan(monitor, root, check->path, &current_stats);

		/* Handle scan failure */
		if (!scan_completed) {
			failure_t failure_type = stability_fail(monitor, check, root, current_time);

			if (failure_type == SCAN_FAILURE_MAX_ATTEMPTS_REACHED) {
				/* Remove from queue */
				pthread_mutex_unlock(&root->resource->mutex);
				queue_remove(monitor->check_queue, check->path);
				return;
			} else if (failure_type == SCAN_FAILURE_DIRECTORY_DELETED) {
				/* Reschedule for another check */
				struct timespec next_check = *current_time;
				timespec_add(&next_check, 2000); /* 2 seconds */

				/* Update check */
				check->next_check = next_check;
				heap_down(monitor->check_queue->items, monitor->check_queue->size, 0);
				pthread_mutex_unlock(&root->resource->mutex);
				return;
			}
		}

		/* Determine stability */
		bool is_stable = stability_stable(root, &current_stats, scan_completed);

		if (!is_stable) {
			/* Directory is unstable - reset counter and reschedule */
			root->profile->stability->checks_count = 0;
			root->profile->stability->checks_required = 0; /* Reset required checks */
			root->profile->stability->unstable_count++;	   /* Increment instability counter */

			/* Update activity timestamp and reset verification flag*/
			root->profile->scanner->latest_time = *current_time;
			check->verifying = false;

			log_message(DEBUG, "Directory %s failed stability scan (instability count: %d), rescheduling",
						check->path, root->profile->stability->unstable_count);

			/* Recalculate quiet period based on new instability */
			required_quiet = scanner_delay(monitor, root);
			log_message(DEBUG, "Recalculated quiet period for instability: %ld ms", required_quiet);
			stability_delay(monitor, check, root, current_time, required_quiet);
			pthread_mutex_unlock(&root->resource->mutex);
			return;
		}

		/* Directory is stable - determine if enough checks have been completed */
		root->profile->stability->checks_count++;

		/* Calculate required checks based on complexity factors (only if not already set) */
		if (root->profile->stability->checks_required == 0) {
			root->profile->stability->checks_required = stability_require(monitor, root, &current_stats);
		}
		int checks_required = root->profile->stability->checks_required;

		log_message(DEBUG, "Stability check %d/%d for %s: changes (%+d files, %+d dirs, %+d depth) total (%d entries, depth %d)",
					root->profile->stability->checks_count, checks_required, root->resource->path,
					root->profile->stability->delta_files, root->profile->stability->delta_dirs,
					root->profile->stability->delta_depth, current_stats.tree_files + current_stats.tree_dirs,
					current_stats.max_depth > 0 ? current_stats.max_depth : current_stats.depth);

		/* Check if we have enough consecutive stable checks */
		if (root->profile->stability->checks_count < checks_required) {
			/* Not enough checks yet, schedule quick follow-up check */
			struct timespec next_check = *current_time;
			timespec_add(&next_check, 200); /* 200ms */

			/* Update check and restore heap property */
			check->next_check = next_check;
			heap_down(monitor->check_queue->items, monitor->check_queue->size, 0);

			pthread_mutex_unlock(&root->resource->mutex);
			return;
		}

		/* Directory is stable with sufficient consecutive checks - check for exclude-only changes */
		stats_t *baseline_stats = &root->profile->stability->ref_stats;
		stats_t *execution_stats = &current_stats;

		/* Check if the included set of files has changed in any way (count, dirs, or total size) */
		bool included_changed = (execution_stats->tree_files != baseline_stats->tree_files) ||
								(execution_stats->tree_dirs != baseline_stats->tree_dirs) ||
								(execution_stats->tree_size != baseline_stats->tree_size);

		/* Check if the excluded set of files has changed (count, total size, or latest mtime) */
		bool excluded_changed = (execution_stats->excluded_files != baseline_stats->excluded_files) ||
								(execution_stats->excluded_size != baseline_stats->excluded_size) ||
								(execution_stats->excluded_mtime != baseline_stats->excluded_mtime);

		/* If the included is unchanged and the excluded has changed then we ignore this event */
		if (!included_changed && excluded_changed) {
			log_message(INFO, "Ignoring event for %s, all recent changes were to excluded files", root->resource->path);

			/* Reset the stability baseline to this new state */
			stability_reset(monitor, root);

			/* Clean up the queue and do not execute the command */
			pthread_mutex_unlock(&root->resource->mutex);
			queue_remove(monitor->check_queue, check->path);
			return;
		}

		/* Legitimate changes - execute commands */
		commands_attempted++;
		log_message(INFO, "Directory %s stability confirmed (%d/%d checks), proceeding to command execution",
					root->resource->path, root->profile->stability->checks_count, checks_required);

		/* Execute commands */
		int executed_now = 0;
		stability_execute(monitor, check, root, current_time, &executed_now);
		commands_executed += executed_now;

		/* Unlock the group mutex before queue operations */
		pthread_mutex_unlock(&root->resource->mutex);

		/* Remove check from queue after processing all watches */
		queue_remove(monitor->check_queue, check->path);
	}

	if (item_processed) {
		log_message(DEBUG, "Processed queued check. Commands attempted: %d, executed: %d. Remaining queue size: %d",
					commands_attempted, commands_executed, monitor->check_queue->size);
	}
}
