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
#include "scanner.h"
#include "states.h"

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

/* Find the root state for a given entity state */
entity_t *stability_root(monitor_t *monitor, entity_t *state) {
	if (!monitor || !state || !state->node) {
		return NULL;
	}

	/* Get the watch for this state */
	watch_t *watch = registry_get(monitor->registry, state->watchref);
	if (!watch || !watch->path) {
		if (state->node) {
			log_message(WARNING, "Invalid watch info for state %s", state->node->path);
		}
		return NULL;
	}

	/* If current state is already the root, return it */
	if (strcmp(state->node->path, watch->path) == 0) {
		return state;
	}

	/* Otherwise, get the state for the watch path */
	return states_get(monitor->states, monitor->registry, watch->path, state->watchref, ENTITY_DIRECTORY);
}

/* Determine if a command should be executed based on operation type and debouncing */
bool stability_ready(monitor_t *monitor, entity_t *state, optype_t optype, int base_debounce_ms) {
	if (!state) return false;

	struct timespec current_time;
	clock_gettime(CLOCK_MONOTONIC, &current_time);

	/* Record activity (updates timestamps and root tree time) */
	scanner_track(monitor, state, optype);

	/* Defer all directory-related operations to the stability system */
	if (state->node->kind == ENTITY_DIRECTORY) {
		entity_t *root = stability_root(monitor, state);
		if (root && monitor) {
			/* Always trigger a deferred check; queue deduplicates */
			root->node->scanner->active = true;
			root->node->stability->stability_lost = false;

			log_message(DEBUG, "Directory content change for %s, marked root %s as active, command deferred",
						state->node->path, root->node->path);

			if (!root) {
				return false;
			}

			stability_defer(monitor, root);
			log_message(DEBUG, "Added directory %s to deferred check queue", root->node->path);
		}
		return false; /* Decision happens later */
	}

	/* Standard time-based debounce for non-directory-content operations */
	long elapsed_command = (current_time.tv_sec - state->command_time) * 1000;

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
				state->node->path, elapsed_command, effective_debounce_ms);

	/* Check if enough time has passed or if it's the first command */
	if (elapsed_command >= effective_debounce_ms || state->command_time == 0) {
		log_message(DEBUG, "Debounce check passed for %s, command allowed", state->node->path);
		return true;
	}

	log_message(DEBUG, "Command execution debounced for %s", state->node->path);
	return false;
}

/* Schedule a deferred stability check for a directory */
void stability_defer(monitor_t *monitor, entity_t *state) {
	if (!monitor || !state) {
		log_message(WARNING, "Cannot schedule deferred check - invalid monitor or state");
		return;
	}

	watch_t *state_watch = registry_get(monitor->registry, state->watchref);
	if (!state->node || !state_watch) {
		log_message(WARNING, "Cannot schedule deferred check - state has null node or watch");
		return;
	}

	/* Find the root state for this entity */
	entity_t *root = stability_root(monitor, state);
	if (!root) {
		/* If no root found, use the provided state if it's a directory */
		if (state->node->kind == ENTITY_DIRECTORY) {
			root = state;
		} else {
			log_message(WARNING, "Cannot schedule check for %s: no root state found", state->node->path);
			return;
		}
	}

	/* Ensure the root state has a scanner before we use it */
	if (!root->node->scanner) {
		root->node->scanner = scanner_create(root->node->path);
		if (!root->node->scanner) {
			log_message(ERROR, "Failed to create scanner for root %s in stability_defer", root->node->path);
			return;
		}
	}

	/* Force root state to be active and update its activity time to now */
	root->node->scanner->active = true;
	root->node->stability->stability_lost = false;
	clock_gettime(CLOCK_MONOTONIC, &root->node->scanner->latest_time);

	/* Initialize reference stats if needed */
	if (!root->node->stability->reference_init) {
		root->node->stability->ref_stats = root->node->stability->stats;
		root->node->stability->reference_init = true;
		log_message(DEBUG, "Initialized reference stats for %s: files=%d, dirs=%d, depth=%d",
					root->node->path, root->node->stability->stats.local_files,
					root->node->stability->stats.local_dirs, root->node->stability->stats.depth);
	}

	/* Calculate check time based on quiet period */
	struct timespec current_time;
	clock_gettime(CLOCK_MONOTONIC, &current_time);

	/* Ensure we don't use a timestamp in the past */
	if (root->node->scanner->latest_time.tv_sec < current_time.tv_sec - 10) {
		log_message(DEBUG, "Last activity timestamp for %s is too old, using current time", root->node->path);
		root->node->scanner->latest_time = current_time;
	}

	/* Check if there's already a pending check to implement lock-in behavior */
	int existing_index = queue_find(monitor->check_queue, root->node->path);

	if (existing_index >= 0) {
		/* A check is already pending. Use maximum of locked-in period and new calculation */
		check_t *check = &monitor->check_queue->items[existing_index];

		/* Add the current watch to the existing check to merge them */
		watch_t *root_watch = registry_get(monitor->registry, root->watchref);
		if (!queue_add(check, root->watchref)) {
			log_message(WARNING, "Failed to merge watch %s into existing check for %s",
						root_watch ? root_watch->name : "unknown", root->node->path);
		} else {
			log_message(DEBUG, "Merged watch %s into existing deferred check for %s",
						root_watch ? root_watch->name : "unknown", root->node->path);
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
		long effective_quiet;
		if (current_complexity < locked_quiet && current_complexity < (locked_quiet * 0.7)) {
			/* Significant drop - use calculated period for responsiveness */
			effective_quiet = current_complexity;
		} else {
			/* Use maximum for stability */
			effective_quiet = (current_complexity > locked_quiet) ? current_complexity : locked_quiet;
		}

		/* Update activity time for true timer refresh */
		clock_gettime(CLOCK_MONOTONIC, &root->node->scanner->latest_time);

		/* Use existing scheduling logic with effective period */
		stability_delay(monitor, check, root, &root->node->scanner->latest_time, effective_quiet);

		log_message(DEBUG, "Event received, using quiet period of %ld ms for %s (locked: %ld ms, calculated: %ld ms)",
					effective_quiet, root->node->path, locked_quiet, current_complexity);
		return;
	}

	/* Calculate quiet period for first event of this burst */
	long required_quiet = scanner_delay(monitor, root);
	log_message(DEBUG, "Calculated new quiet period for %s: %ld ms (first event of burst)",
				root->node->path, required_quiet);

	struct timespec next_check;
	next_check.tv_sec = root->node->scanner->latest_time.tv_sec + (required_quiet / 1000);
	next_check.tv_nsec = root->node->scanner->latest_time.tv_nsec + ((required_quiet % 1000) * 1000000);

	/* Normalize nsec */
	if (next_check.tv_nsec >= 1000000000) {
		next_check.tv_sec++;
		next_check.tv_nsec -= 1000000000;
	}

	/* Add to queue */
	queue_upsert(monitor->check_queue, root->node->path, root->watchref, next_check);

	/* Store the calculated quiet period for consistent use */
	int queue_index = queue_find(monitor->check_queue, root->node->path);
	if (queue_index >= 0) {
		monitor->check_queue->items[queue_index].scheduled_quiet = required_quiet;
	}

	log_message(DEBUG, "Scheduled deferred check for %s: in %ld ms (directory with %d files, %d dirs)",
				root->node->path, required_quiet, root->node->stability->stats.local_files,
				root->node->stability->stats.local_dirs);
}

/* Get the root entity state for a deferred check */
entity_t *stability_entry(monitor_t *monitor, check_t *check) {
	if (!monitor || !check || check->num_watches <= 0) {
		log_message(ERROR, "Invalid parameters for stability_entry");
		return NULL;
	}

	/* Use the first watch reference to find the state. All watches for a check share the same path */
	watchref_t primary_watchref = check->watchrefs[0];

	entity_t *root = states_get(monitor->states, monitor->registry, check->path, primary_watchref, ENTITY_DIRECTORY);
	if (!root) {
		log_message(WARNING, "Cannot find state for %s", check->path);
		return NULL;
	}

	return root;
}

/* Check if quiet period has elapsed for a directory */
bool stability_quiet(monitor_t *monitor, entity_t *root, struct timespec *current_time, long required_quiet) {
	if (!monitor || !root || !current_time) {
		return false;
	}

	struct timespec scanner_time = root->node->scanner->latest_time;
	long elapsed_ms;

	/* Robustly calculate elapsed time in milliseconds */
	if (current_time->tv_sec < scanner_time.tv_sec ||
		(current_time->tv_sec == scanner_time.tv_sec && current_time->tv_nsec < scanner_time.tv_nsec)) {
		elapsed_ms = 0; /* Clock went backwards, treat as no time elapsed */
	} else {
		struct timespec diff_time;
		diff_time.tv_sec = current_time->tv_sec - scanner_time.tv_sec;
		if (current_time->tv_nsec >= scanner_time.tv_nsec) {
			diff_time.tv_nsec = current_time->tv_nsec - scanner_time.tv_nsec;
		} else {
			diff_time.tv_sec--;
			diff_time.tv_nsec = 1000000000 + current_time->tv_nsec - scanner_time.tv_nsec;
		}
		elapsed_ms = diff_time.tv_sec * 1000 + diff_time.tv_nsec / 1000000;
	}

	log_message(DEBUG, "Path %s: %ld ms elapsed of %ld ms quiet period, direct_entries=%d+%d, recursive_entries=%d+%d, depth=%d",
				root->node->path, elapsed_ms, required_quiet, root->node->stability->stats.local_files,
				root->node->stability->stats.local_dirs, root->node->stability->stats.tree_files, root->node->stability->stats.tree_dirs,
				root->node->stability->stats.depth);

	return scanner_ready(monitor, root, current_time, required_quiet);
}

/* Reschedule a deferred check */
void stability_delay(monitor_t *monitor, check_t *check, entity_t *root, struct timespec *current_time, long required_quiet) {
	if (!monitor || !check || !root || !current_time) {
		return;
	}

	/* Update next check time based on latest activity */
	struct timespec next_check;
	next_check.tv_sec = root->node->scanner->latest_time.tv_sec + (required_quiet / 1000);
	next_check.tv_nsec = root->node->scanner->latest_time.tv_nsec + ((required_quiet % 1000) * 1000000);

	/* Normalize timestamp */
	if (next_check.tv_nsec >= 1000000000) {
		next_check.tv_sec++;
		next_check.tv_nsec -= 1000000000;
	}

	/* Update the check in place and restore heap property */
	check->next_check = next_check;
	check->scheduled_quiet = required_quiet;
	heap_down(monitor->check_queue->items, monitor->check_queue->size, 0);
}

/* Check for new directories in recursive watches */
bool stability_new(monitor_t *monitor, check_t *check) {
	if (!monitor || !check) {
		return false;
	}

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
bool stability_scan(monitor_t *monitor, entity_t *root, const char *path, stats_t *stats_out) {
	if (!monitor || !root || !path || !stats_out) {
		return false;
	}

	/* Perform recursive stability verification */
	watch_t *watch = registry_get(monitor->registry, root->watchref);
	bool is_stable = scanner_stable(monitor, root->node, path, watch, stats_out);

	/* Always update stats and cumulative changes, even if unstable, to track progress */
	root->node->stability->checks_failed = is_stable ? 0 : root->node->stability->checks_failed;

	/* Save previous stats for comparison before overwriting */
	stats_t temp_stats = root->node->stability->stats;
	root->node->stability->stats = *stats_out;

	/* Update cumulative changes based on the difference */
	root->node->stability->prev_stats = temp_stats;
	scanner_update(root->node);

	log_message(DEBUG, "Stability scan for %s: files=%d, dirs=%d, size=%s, recursive_files=%d, recursive_dirs=%d, max_depth=%d",
				path, stats_out->local_files, stats_out->local_dirs, format_size((ssize_t) stats_out->tree_size, false),
				stats_out->tree_files, stats_out->tree_dirs, stats_out->max_depth);

	return is_stable;
}

/* Handle scan failure cases */
failure_t stability_fail(monitor_t *monitor, check_t *check, entity_t *root, struct timespec *current_time) {
	if (!monitor || !check || !root || !current_time) {
		return SCAN_FAILURE_TEMPORARY_ERROR;
	}

	/* Check if the directory still exists */
	struct stat info;
	if (stat(check->path, &info) != 0 || !S_ISDIR(info.st_mode)) {
		root->node->stability->checks_failed++;
		log_message(DEBUG, "Directory %s not found (attempt %d/%d)", check->path,
					root->node->stability->checks_failed, MAX_CHECKS_FAILED);

		/* After multiple consecutive failures, consider it permanently deleted */
		if (root->node->stability->checks_failed >= MAX_CHECKS_FAILED) {
			log_message(INFO, "Directory %s confirmed deleted after %d failed checks, cleaning up",
						check->path, root->node->stability->checks_failed);

			/* Mark as not active for all watches */
			root->node->scanner->active = false;
			root->node->exists = false;

			return SCAN_FAILURE_MAX_ATTEMPTS_REACHED;
		}

		return SCAN_FAILURE_DIRECTORY_DELETED;
	} else {
		/* Scan failed for other reasons */
		root->node->stability->checks_failed = 0; /* Reset counter */
		return SCAN_FAILURE_TEMPORARY_ERROR;
	}
}

/* Calculate required stability checks based on complexity */
int stability_require(entity_t *root, const stats_t *current_stats) {
	if (!root || !current_stats) {
		return 1;
	}

	int tree_entries = current_stats->tree_files + current_stats->tree_dirs;
	int tree_depth = current_stats->max_depth > 0 ? current_stats->max_depth : current_stats->depth;

	/* Use cumulative changes for adapting stability requirements */
	int abs_file_change = abs(root->node->stability->delta_files);
	int abs_dir_change = abs(root->node->stability->delta_dirs);
	int abs_depth_change = abs(root->node->stability->delta_depth);
	int abs_change = abs_file_change + abs_dir_change;

	int checks_required;

	/* Determine required checks based on change magnitude and complexity */
	if (abs_change <= 1 && abs_depth_change == 0) {
		checks_required = 1;
		if (tree_depth >= 5 || tree_entries > 1000) checks_required = 2;
	} else if (abs_change <= 5 && abs_depth_change == 0) {
		checks_required = 2;
	} else if (abs_depth_change > 0) {
		checks_required = 2;
		if (abs_depth_change > 1) checks_required = 3;
	} else if (abs_change < 20) {
		checks_required = 2;
		if (tree_depth >= 4 || tree_entries > 500) checks_required = 3;
	} else {
		checks_required = 3;
		if (tree_depth >= 5 || tree_entries > 1000) checks_required = 4;
	}

	/* Consider previous stability for check reduction */
	if (root->node->stability->stability_lost && checks_required > 1) {
		log_message(DEBUG, "Stability was lost, maintaining required checks at %d", checks_required);
	}

	/* Ensure at least one check is required */
	if (checks_required < 1) checks_required = 1;

	return checks_required;
}

/* Determine if directory is stable */
bool stability_stable(entity_t *root, const stats_t *current_stats, bool scan_completed) {
	if (!root || !current_stats || !scan_completed) {
		return false;
	}

	bool has_prev_stats = (root->node->stability->prev_stats.local_files > 0 || root->node->stability->prev_stats.local_dirs > 0);
	if (has_prev_stats && !scanner_compare(&root->node->stability->prev_stats, (stats_t *) current_stats)) {
		return false;
	}

	return true;
}

/* Reset stability tracking after successful command execution */
void stability_reset(monitor_t *monitor, entity_t *root) {
	if (!monitor || !root) {
		return;
	}

	/* Only process directories with stability tracking */
	if (root->node->kind != ENTITY_DIRECTORY || !root->node->stability) {
		log_message(DEBUG, "Skipping baseline reset for non-directory or non-tracked entity: %s", root->node->path);
		return;
	}

	/* Scan current directory state to establish new baseline */
	stats_t new_baseline;
	memset(&new_baseline, 0, sizeof(new_baseline));
	watch_t *watch = registry_get(monitor->registry, root->watchref);
	if (watch && !scanner_scan(root->node->path, watch, &new_baseline)) {
		log_message(WARNING, "Failed to scan directory %s for baseline reset", root->node->path);
		return;
	}

	log_message(INFO, "Resetting baseline for %s after command: %d files, %d dirs, depth %d",
				root->node->path, new_baseline.tree_files, new_baseline.tree_dirs, new_baseline.max_depth);

	/* Reset stability state to reflect new baseline as authoritative */
	root->node->stability->stats = new_baseline;
	root->node->stability->prev_stats = new_baseline;
	root->node->stability->ref_stats = new_baseline;

	/* Clear all tracking deltas */
	root->node->stability->delta_files = 0;
	root->node->stability->delta_dirs = 0;
	root->node->stability->delta_depth = 0;
	root->node->stability->delta_size = 0;

	/* Reset stability verification tracking */
	root->node->stability->checks_count = 0;
	root->node->stability->checks_failed = 0;
	root->node->stability->checks_required = 1;
	root->node->stability->unstable_count = 0;
	root->node->stability->stability_lost = false;
	root->node->stability->reference_init = true;

	/* Clear activity tracking flag to mark the directory as idle */
	if (root->node->scanner) {
		root->node->scanner->active = false;
	}
}

/* Execute commands for all watches of a stable directory */
bool stability_execute(monitor_t *monitor, check_t *check, entity_t *root, struct timespec *current_time, int *commands_executed) {
	if (!monitor || !check || !root || !current_time) {
		return false;
	}

	int executed_count = 0;
	const char *active_path = root->node->scanner->active_path ? root->node->scanner->active_path : check->path;

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
			watch_t *watch = registry_get(monitor->registry, root->watchref);
			root->trigger = scanner_newest(active_path, watch);
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
		.time = root->node->last_time,
		.wall_time = root->node->wall_time,
		.user_id = getuid()};

	/* Set the executing flag for the root node before starting any commands */
	root->node->executing = true;

	/* Execute commands for all watches associated with the stability check */
	for (int i = 0; i < check->num_watches; i++) {
		watch_t *watch = registry_get(monitor->registry, check->watchrefs[i]);

		if (!watch) {
			log_message(DEBUG, "Skipping command for stale watch reference: ID %u (gen %u)",
						check->watchrefs[i].watch_id, check->watchrefs[i].generation);
			continue;
		}

		/* Get or create state for this specific watch to update its command time */
		entity_t *state = states_get(monitor->states, monitor->registry, check->path, check->watchrefs[i], ENTITY_DIRECTORY);
		if (!state) {
			log_message(WARNING, "Unable to get state for %s with watch %s", check->path, watch->name);
			continue;
		}

		/* Execute command */
		log_message(INFO, "Executing deferred command for %s (watch: %s)", check->path, watch->name);
		if (command_execute(monitor, check->watchrefs[i], &synthetic_event, true)) {
			executed_count++;
			/* Update the specific state's command time for debouncing purposes */
			state->command_time = current_time->tv_sec;
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

	if (!monitor || !monitor->check_queue) {
		return;
	}

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
		if (current_time->tv_sec < check->next_check.tv_sec ||
			(current_time->tv_sec == check->next_check.tv_sec && current_time->tv_nsec < check->next_check.tv_nsec)) {
			/* Not yet time for this check. Since it's a min-heap, no other checks are ready */
			return;
		}

		item_processed = true;

		log_message(DEBUG, "Processing deferred check for %s with %d watches", check->path, check->num_watches);

		/* Get the root entity state */
		entity_t *root = stability_entry(monitor, check);
		if (!root) {
			queue_remove(monitor->check_queue, check->path);
			return;
		}

		/* If the entity is no longer active, just remove from queue */
		if (!root->node->scanner->active) {
			log_message(DEBUG, "Directory %s no longer active, removing from queue", check->path);
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
							root->node->path, primary_watch ? primary_watch->name : "unknown");

				stability_delay(monitor, check, root, current_time, required_quiet);
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
			root->node->scanner->latest_time = *current_time;

			/* Update directory stats to reflect new directory structure */
			stats_t new_stats;
			watch_t *watch = registry_get(monitor->registry, root->watchref);
			if (watch && scanner_scan(root->node->path, watch, &new_stats)) {
				root->node->stability->prev_stats = root->node->stability->stats;
				root->node->stability->stats = new_stats;
				scanner_update(root->node);
			}

			/* We stay in verification mode, but reset the check count since the scope has changed */
			root->node->stability->checks_count = 0;
			root->node->stability->checks_required = 0; /* Recalculate required checks */

			/* Schedule a short follow-up check instead of a full quiet period */
			struct timespec next_check;
			next_check.tv_sec = current_time->tv_sec;
			next_check.tv_nsec = current_time->tv_nsec + 200000000; /* 200ms */
			if (next_check.tv_nsec >= 1000000000) {
				next_check.tv_sec++;
				next_check.tv_nsec -= 1000000000;
			}
			check->next_check = next_check;
			heap_down(monitor->check_queue->items, monitor->check_queue->size, 0);
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
				queue_remove(monitor->check_queue, check->path);
				return;
			} else if (failure_type == SCAN_FAILURE_DIRECTORY_DELETED) {
				/* Reschedule for another check */
				struct timespec next_check;
				next_check.tv_sec = current_time->tv_sec + 2; /* 2 seconds */
				next_check.tv_nsec = current_time->tv_nsec;

				/* Update check */
				check->next_check = next_check;
				heap_down(monitor->check_queue->items, monitor->check_queue->size, 0);
				return;
			}
		}

		/* Determine stability */
		bool is_stable = stability_stable(root, &current_stats, scan_completed);

		if (!is_stable) {
			/* Directory is unstable - reset counter and reschedule */
			root->node->stability->checks_count = 0;
			root->node->stability->checks_required = 0; /* Reset required checks */
			root->node->stability->unstable_count++;	/* Increment instability counter */

			/* Update activity timestamp and reset verification flag*/
			root->node->scanner->latest_time = *current_time;
			check->verifying = false;

			log_message(DEBUG, "Directory %s failed stability scan (instability count: %d), rescheduling",
						check->path, root->node->stability->unstable_count);

			/* Recalculate quiet period based on new instability */
			required_quiet = scanner_delay(monitor, root);
			log_message(DEBUG, "Recalculated quiet period for instability: %ld ms", required_quiet);
			stability_delay(monitor, check, root, current_time, required_quiet);
			return;
		}

		/* Directory is stable - determine if enough checks have been completed */
		root->node->stability->checks_count++;

		/* Calculate required checks based on complexity factors (only if not already set) */
		if (root->node->stability->checks_required == 0) {
			root->node->stability->checks_required = stability_require(root, &current_stats);
		}
		int checks_required = root->node->stability->checks_required;

		log_message(DEBUG, "Stability check %d/%d for %s: changes (%+d files, %+d dirs, %+d depth) total (%d entries, depth %d)",
					root->node->stability->checks_count, checks_required, root->node->path, root->node->stability->delta_files,
					root->node->stability->delta_dirs, root->node->stability->delta_depth, current_stats.tree_files + current_stats.tree_dirs,
					current_stats.max_depth > 0 ? current_stats.max_depth : current_stats.depth);

		/* Check if we have enough consecutive stable checks */
		if (root->node->stability->checks_count < checks_required) {
			/* Not enough checks yet, schedule quick follow-up check */
			struct timespec next_check;
			next_check.tv_sec = current_time->tv_sec;
			next_check.tv_nsec = current_time->tv_nsec + 200000000; /* 200ms */

			/* Normalize timestamp */
			if (next_check.tv_nsec >= 1000000000) {
				next_check.tv_sec++;
				next_check.tv_nsec -= 1000000000;
			}

			/* Update check and restore heap property */
			check->next_check = next_check;
			heap_down(monitor->check_queue->items, monitor->check_queue->size, 0);

			return;
		}

		/* Directory is stable with sufficient consecutive checks - execute commands */
		commands_attempted++;
		log_message(INFO, "Directory %s stability confirmed (%d/%d checks), proceeding to command execution",
					root->node->path, root->node->stability->checks_count, checks_required);

		/* Execute commands */
		int executed_now = 0;
		stability_execute(monitor, check, root, current_time, &executed_now);
		commands_executed += executed_now;

		/* Remove check from queue after processing all watches */
		queue_remove(monitor->check_queue, check->path);
	}

	if (item_processed) {
		log_message(DEBUG, "Processed deferred check. Commands attempted: %d, executed: %d. Remaining queue size: %d",
					commands_attempted, commands_executed, monitor->check_queue->size);
	}
}
