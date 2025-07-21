#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "monitor.h"
#include "stability.h"
#include "scanner.h"
#include "states.h"
#include "logger.h"
#include "command.h"
#include "queue.h"
#include "events.h"

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
	if (!monitor || !state || !state->watch || !state->watch->path || !state->node) {
		if (state && state->node) {
			log_message(WARNING, "Invalid watch info for state %s", state->node->path);
		}
		return NULL;
	}

	/* If current state is already the root, return it */
	if (strcmp(state->node->path, state->watch->path) == 0) {
		return state;
	}

	/* Otherwise, get the state for the watch path */
	return state_get(monitor->states, state->watch->path, ENTITY_DIRECTORY, state->watch);
}

/* Determine if a command should be executed based on operation type and debouncing */
bool stability_ready(monitor_t *monitor, entity_t *state, optype_t optype, int base_debounce_ms) {
	if (!state) return false;

	struct timespec current_time;
	clock_gettime(CLOCK_MONOTONIC, &current_time);

	/* Record activity (updates timestamps and root tree time) */
	scanner_track(monitor, state, optype);

	/* Directory content changes always defer execution */
	if (optype == OP_DIR_CONTENT_CHANGED) {
		entity_t *root = stability_root(monitor, state);
		if (root && monitor) {
			/* Always trigger a deferred check; queue deduplicates */
			root->scanner->active = true;
			root->stability->stability_lost = false;
			scanner_sync(monitor, root->node, root);

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

	if (!state->node || !state->watch) {
		log_message(WARNING, "Cannot schedule deferred check - state has null node or watch");
		return;
	}

	/* Find the root state for this entity */
	entity_t *root = stability_root(monitor, state);
	if (!root) {
		/* If no root found, use the provided state if it's a directory */
		if (state->kind == ENTITY_DIRECTORY) {
			root = state;
		} else {
			log_message(WARNING, "Cannot schedule check for %s: no root state found", state->node->path);
			return;
		}
	}

	/* Force root state to be active */
	root->scanner->active = true;
	root->stability->stability_lost = false;

	/* Initialize reference stats if needed */
	if (!root->stability->reference_init) {
		root->stability->ref_stats = root->stability->stats;
		root->stability->reference_init = true;
		log_message(DEBUG, "Initialized reference stats for %s: files=%d, dirs=%d, depth=%d",
		        			root->node->path, root->stability->stats.local_files,
		            		root->stability->stats.local_dirs, root->stability->stats.depth);
	}

	/* Calculate check time based on quiet period */
	struct timespec current_time;
	clock_gettime(CLOCK_MONOTONIC, &current_time);

	/* Ensure we don't use a timestamp in the past */
	if (root->scanner->latest_time.tv_sec < current_time.tv_sec - 10) {
		log_message(DEBUG, "Last activity timestamp for %s is too old, using current time", root->node->path);
		root->scanner->latest_time = current_time;
	}

	/* Check if there's already a pending check to implement lock-in behavior */
	int existing_index = queue_find(monitor->check_queue, root->node->path);
	
	if (existing_index >= 0) {
		/* A check is already pending. Use maximum of locked-in period and new calculation */
		check_t *check = &monitor->check_queue->items[existing_index];
		long locked_quiet = check->scheduled_quiet;
		
		if (locked_quiet <= 0) {
			/* Fallback if the period wasn't locked in correctly */
			locked_quiet = scanner_delay(root);
			check->scheduled_quiet = locked_quiet;
		}
		
		/* Calculate current complexity and use maximum with locked-in period */
		long current_complexity = scanner_delay(root);
		
		/* Allow responsive drops if new period is significantly lower */
		long effective_quiet;
		if (current_complexity < locked_quiet && current_complexity < (locked_quiet * 0.6)) {
			/* Significant drop - use calculated period for responsiveness */
			effective_quiet = current_complexity;
		} else {
			/* Use maximum for stability */
			effective_quiet = (current_complexity > locked_quiet) ? current_complexity : locked_quiet;
		}
		
		/* Update activity time for true timer refresh */
		clock_gettime(CLOCK_MONOTONIC, &root->scanner->latest_time);
		scanner_sync(monitor, root->node, root); /* Propagate new activity time */
		
		/* Use existing scheduling logic with effective period */
		stability_delay(monitor, check, root, &root->scanner->latest_time, effective_quiet);
		               
		log_message(DEBUG, "Event received during quiet period, using period of %ld ms for %s (locked: %ld ms, calculated: %ld ms)",
							effective_quiet, root->node->path, locked_quiet, current_complexity);
		return;
	}

	/* Calculate quiet period for first event of this burst */
	long required_quiet = scanner_delay(root);
	log_message(DEBUG, "Calculated new quiet period for %s: %ld ms (first event of burst)", 
	            		root->node->path, required_quiet);

	struct timespec next_check;
	next_check.tv_sec = root->scanner->latest_time.tv_sec + (required_quiet / 1000);
	next_check.tv_nsec = root->scanner->latest_time.tv_nsec + ((required_quiet % 1000) * 1000000);

	/* Normalize nsec */
	if (next_check.tv_nsec >= 1000000000) {
		next_check.tv_sec++;
		next_check.tv_nsec -= 1000000000;
	}

	/* Add to queue */
	queue_upsert(monitor->check_queue, root->node->path, root->watch, next_check);
	
	/* Store the calculated quiet period for consistent use */
	int queue_index = queue_find(monitor->check_queue, root->node->path);
	if (queue_index >= 0) {
		monitor->check_queue->items[queue_index].scheduled_quiet = required_quiet;
	}

	log_message(DEBUG, "Scheduled deferred check for %s: in %ld ms (directory with %d files, %d dirs)",
	            		root->node->path, required_quiet, root->stability->stats.local_files,
						root->stability->stats.local_dirs);
}

/* Get the primary watch from a deferred check check */
watch_t *stability_watch(check_t *check) {
	if (!check || check->num_watches <= 0) {
		return NULL;
	}
	return check->watches[0];
}

/* Get the root entity state for a deferred check */
entity_t *stability_entry(monitor_t *monitor, check_t *check) {
	if (!monitor) {
		log_message(ERROR, "Monitor is null in stability_entry");
		return NULL;
	}
	
	watch_t *primary_watch = stability_watch(check);
	if (!primary_watch) {
		log_message(WARNING, "Deferred check for %s has no watches", check->path);
		return NULL;
	}

	entity_t *root = state_get(monitor->states, check->path, ENTITY_DIRECTORY, primary_watch);
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

	struct timespec scanner_time = root->scanner->latest_time;
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
	        			root->node->path, elapsed_ms, required_quiet, root->stability->stats.local_files,
						root->stability->stats.local_dirs, root->stability->stats.tree_files, root->stability->stats.tree_dirs,
	        			root->stability->stats.depth);

	return scanner_ready(monitor, root, current_time, required_quiet);
}

/* Reschedule a deferred check */
void stability_delay(monitor_t *monitor, check_t *check, entity_t *root, struct timespec *current_time, long required_quiet) {
	if (!monitor || !check || !root || !current_time) {
		return;
	}

	/* Update next check time based on latest activity */
	struct timespec next_check;
	next_check.tv_sec = root->scanner->latest_time.tv_sec + (required_quiet / 1000);
	next_check.tv_nsec = root->scanner->latest_time.tv_nsec + ((required_quiet % 1000) * 1000000);

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
		if (check->watches[i]->recursive) {
			monitor_tree(monitor, check->path, check->watches[i]);
		}
	}

	return monitor->num_watches > prev_num_watches;
}

/* Perform directory stability verification */
bool stability_scan(entity_t *root, const char *path, stats_t *stats_out) {
	if (!root || !path || !stats_out) {
		return false;
	}

	/* Perform recursive stability verification */
	bool is_stable = scanner_stable(root, path, stats_out);

	/* Always update stats and cumulative changes, even if unstable, to track progress */
	root->stability->checks_failed = is_stable ? 0 : root->stability->checks_failed;

	/* Save previous stats for comparison before overwriting */
	stats_t temp_stats = root->stability->stats;
	root->stability->stats = *stats_out;

	/* Update cumulative changes based on the difference */
	root->stability->prev_stats = temp_stats;
	scanner_update(root);

	log_message(DEBUG, "Stability scan for %s: files=%d, dirs=%d, size=%s, recursive_files=%d, recursive_dirs=%d, max_depth=%d",
						path, stats_out->local_files, stats_out->local_dirs, format_size((ssize_t)stats_out->tree_size, false),
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
		root->stability->checks_failed++;
		log_message(DEBUG, "Directory %s not found (attempt %d/%d)", check->path, root->stability->checks_failed, MAX_CHECKS_FAILED);

		/* After multiple consecutive failures, consider it permanently deleted */
		if (root->stability->checks_failed >= MAX_CHECKS_FAILED) {
			log_message(INFO, "Directory %s confirmed deleted after %d failed checks, cleaning up",
							   check->path, root->stability->checks_failed);

			/* Mark as not active for all watches */
			root->scanner->active = false;
			root->exists = false;
			scanner_sync(monitor, root->node, root);

			return SCAN_FAILURE_MAX_ATTEMPTS_REACHED;
		}

		return SCAN_FAILURE_DIRECTORY_DELETED;
	} else {
		/* Scan failed for other reasons (e.g., temp files) */
		root->stability->checks_failed = 0; /* Reset counter */
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
	int abs_file_change = abs(root->stability->delta_files);
	int abs_dir_change = abs(root->stability->delta_dirs);
	int abs_depth_change = abs(root->stability->delta_depth);
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
	if (root->stability->stability_lost && checks_required > 1) {
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

	bool has_prev_stats = (root->stability->prev_stats.local_files > 0 || root->stability->prev_stats.local_dirs > 0);
	if (has_prev_stats && !scanner_compare(&root->stability->prev_stats, (stats_t *) current_stats)) {
		return false;
	}

	return true;
}

/* Reset stability tracking after successful command execution */
void stability_reset(monitor_t *monitor, entity_t *root) {
	if (!monitor || !root) {
		return;
	}

	/* Reset activity flag, stability counter, and all change tracking on the root state */
	root->scanner->active = false;
	root->stability->checks_count = 0;
	root->stability->checks_required = 0;
	root->stability->ref_stats = root->stability->stats;
	root->stability->reference_init = true;
	root->stability->delta_files = 0;
	root->stability->delta_dirs = 0;
	root->stability->delta_depth = 0;
	root->stability->delta_size = 0;
	root->stability->unstable_count = 0;
	root->stability->stability_lost = false;
	
	/* Update prev_stats to current stats for next cycle's comparison */
	root->stability->prev_stats = root->stability->stats;

	/* Propagate the reset state to all related states for this path */
	scanner_sync(monitor, root->node, root);
}

/* Execute commands for all watches of a stable directory */
bool stability_execute(monitor_t *monitor, check_t *check, entity_t *root, struct timespec *current_time, int *commands_executed) {
	if (!monitor || !check || !root || !current_time) {
		return false;
	}

	int executed_count = 0;
	const char *active_path = root->scanner->active_path ? root->scanner->active_path : check->path;

	/* Find the most recent file if any command needs it */
	for (int i = 0; i < check->num_watches; i++) {
		if (strstr(check->watches[i]->command, "%f") || strstr(check->watches[i]->command, "%F")) {
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
			break; /* Only need to find it once */
		}
	}

	/* Create synthetic event */
	event_t synthetic_event = {
		.path = (char *)active_path,
		.type = EVENT_STRUCTURE,
		.time = root->last_time,
		.wall_time = root->wall_time,
		.user_id = getuid()
	};

	/* Execute commands for ALL watches of this path */
	for (int i = 0; i < check->num_watches; i++) {
		watch_t *watch = check->watches[i];

		/* Get or create state for this specific watch */
		entity_t *state = state_get(monitor->states, check->path, ENTITY_DIRECTORY, watch);
		if (!state) {
			log_message(WARNING, "Unable to get state for %s with watch %s during command execution",
								  check->path, watch->name);
			continue;
		}

		/* Execute command */
		log_message(INFO, "Executing deferred command for %s (watch: %s)", check->path, watch->name);

		if (command_execute(monitor, watch, &synthetic_event, true)) {
			executed_count++;
			state->command_time = current_time->tv_sec;

			log_message(DEBUG, "Command execution successful for %s (watch: %s)", check->path, watch->name);
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
	int commands_attempted_total = 0;
	int commands_executed_total = 0;
	int items_processed = 0;

	if (!monitor || !monitor->check_queue) {
		return;
	}

	/* Loop to process all overdue checks */
	while (monitor->check_queue->size > 0) {
		/* Get the top check (earliest scheduled check) */
		check_t *check = &monitor->check_queue->items[0];

		/* Validate the top check before processing */
		if (!check || !check->path) {
			log_message(WARNING, "Corrupted check in queue, removing");
			queue_remove(monitor->check_queue, NULL);
			continue; /* Process next item */
		}

		/* Check if it's time to process this check */
		if (current_time->tv_sec < check->next_check.tv_sec ||
		    (current_time->tv_sec == check->next_check.tv_sec && current_time->tv_nsec < check->next_check.tv_nsec)) {
			/* Not yet time for this check. Since it's a min-heap, no other checks are ready */
			break;
		}

		items_processed++;

		log_message(DEBUG, "Processing deferred check for %s with %d watches", check->path, check->num_watches);

		/* Get the root entity state */
		entity_t *root = stability_entry(monitor, check);
		if (!root) {
			queue_remove(monitor->check_queue, check->path);
			continue;
		}

		/* If the entity is no longer active, just remove from queue */
		if (!root->scanner->active) {
			log_message(DEBUG, "Directory %s no longer active, removing from queue", check->path);
			queue_remove(monitor->check_queue, check->path);
			continue;
		}

		/* Check if we're in verification mode or need to verify quiet period */
		bool elapsed_quiet = check->verifying;
		long required_quiet = check->scheduled_quiet;
		
		if (!elapsed_quiet) {
			/* Use the stored quiet period from when this check was scheduled */
			if (required_quiet <= 0) {
				/* Fallback: calculate if not stored (shouldn't happen) */
				required_quiet = scanner_delay(root);
				check->scheduled_quiet = required_quiet;
			}
			
			elapsed_quiet = stability_quiet(monitor, root, current_time, required_quiet);

			if (!elapsed_quiet) {
				/* Quiet period not yet elapsed, reschedule */
				watch_t *primary_watch = stability_watch(check);
				log_message(DEBUG, "Quiet period not yet elapsed for %s (watch: %s), rescheduling",
				        			root->node->path, primary_watch ? primary_watch->name : "unknown");

				stability_delay(monitor, check, root, current_time, required_quiet);
				continue;
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
			root->scanner->latest_time = *current_time;

			/* Update directory stats to reflect new directory structure */
			stats_t new_stats;
			if (scanner_scan(root->node->path, &new_stats)) {
				root->stability->prev_stats = root->stability->stats;
				root->stability->stats = new_stats;
				scanner_update(root);
			}

			/* We stay in verification mode, but reset the check count since the scope has changed */
			root->stability->checks_count = 0;
			root->stability->checks_required = 0; /* Recalculate required checks */

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
			continue;
		}

		/* Perform directory stability scan */
		stats_t current_stats;
		bool scan_completed = stability_scan(root, check->path, &current_stats);

		/* Handle scan failure */
		if (!scan_completed) {
			failure_t failure_type = stability_fail(monitor, check, root, current_time);

			if (failure_type == SCAN_FAILURE_MAX_ATTEMPTS_REACHED) {
				/* Remove from queue */
				queue_remove(monitor->check_queue, check->path);
				continue;
			} else if (failure_type == SCAN_FAILURE_DIRECTORY_DELETED) {
				/* Reschedule for another check */
				struct timespec next_check;
				next_check.tv_sec = current_time->tv_sec + 2; /* 2 seconds */
				next_check.tv_nsec = current_time->tv_nsec;

				/* Update check */
				check->next_check = next_check;
				heap_down(monitor->check_queue->items, monitor->check_queue->size, 0);
				continue;
			}
		}

		/* Determine stability */
		bool is_stable = stability_stable(root, &current_stats, scan_completed);

		/* Synchronize updated stats with other watches for the same path */
		scanner_sync(monitor, root->node, root);

		if (!is_stable) {
			/* Directory is unstable - reset counter and reschedule */
			root->stability->checks_count = 0;
			root->stability->checks_required = 0; /* Reset required checks */
			root->stability->unstable_count++; /* Increment instability counter */

			/* Update activity timestamp and reset verification flag*/
			root->scanner->latest_time = *current_time;
			scanner_sync(monitor, root->node, root);
			check->verifying = false;

			log_message(DEBUG, "Directory %s failed stability scan (instability count: %d), rescheduling",
			            		check->path, root->stability->unstable_count);

			/* Recalculate quiet period based on new instability */
			required_quiet = scanner_delay(root);
			log_message(DEBUG, "Recalculated quiet period for instability: %ld ms", required_quiet);
			stability_delay(monitor, check, root, current_time, required_quiet);
			continue;
		}

		/* Directory is stable - determine if enough checks have been completed */
		root->stability->checks_count++;

		/* Calculate required checks based on complexity factors (only if not already set) */
		if (root->stability->checks_required == 0) {
			root->stability->checks_required = stability_require(root, &current_stats);
		}
		int checks_required = root->stability->checks_required;

		log_message(DEBUG, "Stability check %d/%d for %s: changes (%+d files, %+d dirs, %+d depth) total (%d entries, depth %d)",
		    				root->stability->checks_count, checks_required, root->node->path, root->stability->delta_files, 
							root->stability->delta_dirs, root->stability->delta_depth, current_stats.tree_files + current_stats.tree_dirs,
		            		current_stats.max_depth > 0 ? current_stats.max_depth : current_stats.depth);

		/* Check if we have enough consecutive stable checks */
		if (root->stability->checks_count < checks_required) {
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

			continue;
		}

		/* Directory is stable with sufficient consecutive checks - execute commands */
		commands_attempted_total++;
		log_message(INFO, "Directory %s stability confirmed (%d/%d checks), proceeding to command execution",
						   root->node->path, root->stability->checks_count, checks_required);

		/* Reset stability tracking */
		stability_reset(monitor, root);

		/* Execute commands */
		int executed_now = 0;
		stability_execute(monitor, check, root, current_time, &executed_now);
		commands_executed_total += executed_now;

		/* Remove check from queue after processing all watches */
		queue_remove(monitor->check_queue, check->path);
	}

	if (items_processed > 0) {
		log_message(DEBUG, "Finished processing %d overdue deferred checks. Attempted: %d, Executed: %d. Remaining queue size: %d",
		        			items_processed, commands_attempted_total, commands_executed_total, monitor->check_queue->size);
	}
}
