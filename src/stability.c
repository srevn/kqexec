#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "monitor.h"
#include "stability.h"
#include "states.h"
#include "logger.h"
#include "command.h"
#include "queue.h"

/* Maximum allowed failures before giving up */
#define MAX_FAILED_CHECKS 3

/* Validate a deferred check entry */
bool validate_entry(deferred_check_t *entry) {
	if (!entry || !entry->path) {
		log_message(WARNING, "Corrupted entry in queue, removing");
		return false;
	}
	return true;
}

/* Get the primary watch from a deferred check entry */
watch_entry_t *get_primary_watch(deferred_check_t *entry) {
	if (!entry || entry->watch_count <= 0) {
		return NULL;
	}
	return entry->watches[0];
}

/* Get the root entity state for a deferred check entry */
entity_state_t *get_root_state_for_entry(deferred_check_t *entry) {
	watch_entry_t *primary_watch = get_primary_watch(entry);
	if (!primary_watch) {
		log_message(WARNING, "Deferred check for %s has no watches", entry->path);
		return NULL;
	}

	entity_state_t *root_state = get_entity_state(entry->path, ENTITY_DIRECTORY, primary_watch);
	if (!root_state) {
		log_message(WARNING, "Cannot find state for %s", entry->path);
		return NULL;
	}

	return root_state;
}

/* Check if quiet period has elapsed for a directory */
bool check_quiet_elapsed(entity_state_t *root_state, struct timespec *current_time, long *elapsed_ms_out) {
	if (!root_state || !current_time) {
		return false;
	}

	struct timespec last_activity = root_state->last_activity_in_tree;
	long elapsed_ms;

	/* Robustly calculate elapsed time in milliseconds */
	if (current_time->tv_sec < last_activity.tv_sec ||
	    (current_time->tv_sec == last_activity.tv_sec && current_time->tv_nsec < last_activity.tv_nsec)) {
		elapsed_ms = 0; /* Clock went backwards, treat as no time elapsed */
	} else {
		struct timespec diff;
		diff.tv_sec = current_time->tv_sec - last_activity.tv_sec;
		if (current_time->tv_nsec >= last_activity.tv_nsec) {
			diff.tv_nsec = current_time->tv_nsec - last_activity.tv_nsec;
		} else {
			diff.tv_sec--;
			diff.tv_nsec = 1000000000 + current_time->tv_nsec - last_activity.tv_nsec;
		}
		elapsed_ms = diff.tv_sec * 1000 + diff.tv_nsec / 1000000;
	}

	if (elapsed_ms_out) {
		*elapsed_ms_out = elapsed_ms;
	}

	long required_quiet_period_ms = get_required_quiet_period(root_state);

	log_message(DEBUG, "Path %s: %ld ms elapsed of %ld ms quiet period, direct_entries=%d+%d, recursive_entries=%d+%d, depth=%d",
	        			root_state->path_state->path, elapsed_ms, required_quiet_period_ms,
	        			root_state->dir_stats.file_count, root_state->dir_stats.dir_count,
	        			root_state->dir_stats.recursive_file_count, root_state->dir_stats.recursive_dir_count,
	        			root_state->dir_stats.depth);

	return is_quiet_period_elapsed(root_state, current_time);
}

/* Reschedule a deferred check */
void reschedule_check(monitor_t *monitor, deferred_check_t *entry, entity_state_t *root_state, struct timespec *current_time) {
	if (!monitor || !entry || !root_state || !current_time) {
		return;
	}

	long required_quiet_period_ms = get_required_quiet_period(root_state);

	/* Update next check time based on latest activity */
	struct timespec next_check;
	next_check.tv_sec = root_state->last_activity_in_tree.tv_sec + (required_quiet_period_ms / 1000);
	next_check.tv_nsec = root_state->last_activity_in_tree.tv_nsec + ((required_quiet_period_ms % 1000) * 1000000);

	/* Normalize timestamp */
	if (next_check.tv_nsec >= 1000000000) {
		next_check.tv_sec++;
		next_check.tv_nsec -= 1000000000;
	}

	/* Update the entry in place and restore heap property */
	entry->next_check = next_check;
	heap_down(monitor->check_queue->items, monitor->check_queue->size, 0);
}

/* Check for new directories in recursive watches */
bool check_for_new_directories(monitor_t *monitor, deferred_check_t *entry) {
	if (!monitor || !entry) {
		return false;
	}

	int prev_watch_count = monitor->watch_count;

	/* For recursive watches, scan for new directories */
	for (int i = 0; i < entry->watch_count; i++) {
		if (entry->watches[i]->recursive) {
			monitor_add_dir_recursive(monitor, entry->path, entry->watches[i]);
		}
	}

	return monitor->watch_count > prev_watch_count;
}

/* Perform directory stability verification */
bool scan_directory_stability(entity_state_t *root_state, const char *path, dir_stats_t *current_stats_out) {
	if (!root_state || !path || !current_stats_out) {
		return false;
	}

	/* Perform recursive stability verification */
	bool scan_completed = verify_directory_stability(root_state, path, current_stats_out, 0);

	/* Only update directory stats if the scan was fully completed */
	if (scan_completed) {
		root_state->failed_checks = 0; /* Reset failed checks on success */

		/* Save previous stats for comparison before overwriting */
		dir_stats_t temp_prev_stats = root_state->dir_stats;
		root_state->dir_stats = *current_stats_out;

		/* Update cumulative changes based on the difference */
		root_state->prev_stats = temp_prev_stats;
		update_cumulative_changes(root_state);

		/* Set previous stats to current for the next cycle's comparison */
		root_state->prev_stats = *current_stats_out;

		log_message(DEBUG, "Stability scan for %s: files=%d, dirs=%d, size=%.2f MB, recursive_files=%d, recursive_dirs=%d, max_depth=%d, stable=yes",
		    				path, current_stats_out->file_count, current_stats_out->dir_count, current_stats_out->total_size / (1024.0 * 1024.0),
		        			current_stats_out->recursive_file_count, current_stats_out->recursive_dir_count, current_stats_out->max_depth);
	}

	return scan_completed;
}

/* Handle scan failure cases */
scan_failure_type_t handle_scan_failure(monitor_t *monitor, deferred_check_t *entry, entity_state_t *root_state, struct timespec *current_time) {
	if (!monitor || !entry || !root_state || !current_time) {
		return SCAN_FAILURE_TEMPORARY_ERROR;
	}

	/* Check if the directory still exists */
	struct stat st;
	if (stat(entry->path, &st) != 0 || !S_ISDIR(st.st_mode)) {
		root_state->failed_checks++;
		log_message(DEBUG, "Directory %s not found (attempt %d/%d)", entry->path, root_state->failed_checks, MAX_FAILED_CHECKS);

		/* After multiple consecutive failures, consider it permanently deleted */
		if (root_state->failed_checks >= MAX_FAILED_CHECKS) {
			log_message(INFO, "Directory %s confirmed deleted after %d failed checks, cleaning up", entry->path, root_state->failed_checks);

			/* Mark as not active for all watches */
			root_state->activity_in_progress = false;
			root_state->exists = false;
			synchronize_activity_states(root_state->path_state, root_state);

			return SCAN_FAILURE_MAX_ATTEMPTS_REACHED;
		}

		return SCAN_FAILURE_DIRECTORY_DELETED;
	} else {
		/* Scan failed for other reasons (e.g., temp files) */
		root_state->failed_checks = 0; /* Reset counter */
		return SCAN_FAILURE_TEMPORARY_ERROR;
	}
}

/* Calculate required stability checks based on complexity */
int calculate_required_checks(entity_state_t *root_state, const dir_stats_t *current_stats) {
	if (!root_state || !current_stats) {
		return 1;
	}

	int total_entries = current_stats->recursive_file_count + current_stats->recursive_dir_count;
	int tree_depth = current_stats->max_depth > 0 ? current_stats->max_depth : current_stats->depth;

	/* Use cumulative changes for adapting stability requirements */
	int abs_file_change = abs(root_state->cumulative_file_change);
	int abs_dir_change = abs(root_state->cumulative_dir_change);
	int abs_depth_change = abs(root_state->cumulative_depth_change);
	int abs_change = abs_file_change + abs_dir_change;

	int required_checks;

	/* Determine required checks based on change magnitude and complexity */
	if (abs_change <= 1 && abs_depth_change == 0) {
		required_checks = 1;
		if (tree_depth >= 5 || total_entries > 1000) required_checks = 2;
	} else if (abs_change <= 5 && abs_depth_change == 0) {
		required_checks = 2;
	} else if (abs_depth_change > 0) {
		required_checks = 2;
		if (abs_depth_change > 1) required_checks = 3;
	} else if (abs_change < 20) {
		required_checks = 2;
		if (tree_depth >= 4 || total_entries > 500) required_checks = 3;
	} else {
		required_checks = 3;
		if (tree_depth >= 5 || total_entries > 1000) required_checks = 4;
	}

	/* Consider previous stability for check reduction */
	if (root_state->stability_lost && required_checks > 1) {
		log_message(DEBUG, "Stability was lost, maintaining required checks at %d", required_checks);
	}

	/* Ensure at least one check is required */
	if (required_checks < 1) required_checks = 1;

	return required_checks;
}

/* Determine if directory is stable */
bool is_directory_stable(entity_state_t *root_state, const dir_stats_t *current_stats, bool scan_completed) {
	if (!root_state || !current_stats || !scan_completed) {
		return false;
	}

	bool has_prev_stats = (root_state->prev_stats.file_count > 0 || root_state->prev_stats.dir_count > 0);
	if (has_prev_stats && !compare_dir_stats(&root_state->prev_stats, (dir_stats_t *) current_stats)) {
		log_message(DEBUG, "Directory unstable: content changed from %d/%d to %d/%d",
		        			root_state->prev_stats.recursive_file_count, root_state->prev_stats.recursive_dir_count,
		        			current_stats->recursive_file_count, current_stats->recursive_dir_count);
		return false;
	}

	return true;
}

/* Reset stability tracking after successful command execution */
void reset_stability_tracking(entity_state_t *root_state) {
	if (!root_state) {
		return;
	}

	/* Reset activity flag, stability counter, and all change tracking on the root state */
	root_state->activity_in_progress = false;
	root_state->stability_check_count = 0;
	root_state->stable_reference_stats = root_state->dir_stats;
	root_state->reference_stats_initialized = true;
	root_state->cumulative_file_change = 0;
	root_state->cumulative_dir_change = 0;
	root_state->cumulative_depth_change = 0;
	root_state->stability_lost = false;
	root_state->instability_count = 0;

	/* Propagate the reset state to all related states for this path */
	synchronize_activity_states(root_state->path_state, root_state);
}

/* Execute commands for all watches of a stable directory */
bool execute_deferred_commands(monitor_t *monitor, deferred_check_t *entry, entity_state_t *root_state, struct timespec *current_time, int *count) {
	if (!monitor || !entry || !root_state || !current_time) {
		return false;
	}

	int commands_executed = 0;

	/* Find the most recent file if any command needs it */
	for (int i = 0; i < entry->watch_count; i++) {
		if (strstr(entry->watches[i]->command, "%f") || strstr(entry->watches[i]->command, "%F")) {
			free(root_state->trigger_file_path);
			root_state->trigger_file_path = NULL; /* Clear previous path */

			char *scan_path = root_state->last_activity_path ? root_state->last_activity_path : entry->path;
			struct stat st;

			if (stat(scan_path, &st) == 0 && S_ISDIR(st.st_mode)) {
				/* It's a directory, scan it for the most recent file */
				root_state->trigger_file_path = find_most_recent_file_in_dir(scan_path);
			} else {
				/* It's a file, or doesn't exist; use the path directly */
				root_state->trigger_file_path = strdup(scan_path);
			}

			if (root_state->trigger_file_path) {
				log_message(DEBUG, "Found trigger file for %%f/%%F: %s", root_state->trigger_file_path);
			}
			break; /* Only need to find it once */
		}
	}

	/* Create synthetic event */
	file_event_t synthetic_event = {
		.path = root_state->last_activity_path ? root_state->last_activity_path : entry->path,
		.type = EVENT_STRUCTURE,
		.time = root_state->last_update,
		.wall_time = root_state->wall_time,
		.user_id = getuid()
	};

	/* Execute commands for ALL watches of this path */
	for (int i = 0; i < entry->watch_count; i++) {
		watch_entry_t *watch = entry->watches[i];

		/* Get or create state for this specific watch */
		entity_state_t *watch_state = get_entity_state(entry->path, ENTITY_DIRECTORY, watch);
		if (!watch_state) {
			log_message(WARNING, "Unable to get state for %s with watch %s during command execution", entry->path, watch->name);
			continue;
		}

		/* Execute command */
		log_message(INFO, "Executing deferred command for %s (watch: %s)", entry->path, watch->name);

		if (command_execute(watch, &synthetic_event)) {
			commands_executed++;

			/* Update last command time for this specific watch */
			watch_state->last_command_time = current_time->tv_sec;

			log_message(DEBUG, "Command execution successful for %s (watch: %s), updated last command time", entry->path, watch->name);
		} else {
			log_message(WARNING, "Command execution failed for %s (watch: %s)", entry->path, watch->name);
		}
	}

	if (count) {
		*count = commands_executed;
	}

	return commands_executed > 0;
}

/* Main stability processing function - coordinator that replaces process_deferred_dir_scans */
void stability_process_queue(monitor_t *monitor, struct timespec *current_time) {
	int commands_attempted_total = 0;
	int commands_executed_total = 0;
	int items_processed = 0;

	if (!monitor || !monitor->check_queue) {
		return;
	}

	/* Loop to process all overdue checks */
	while (monitor->check_queue->size > 0) {
		/* Get the top entry (earliest scheduled check) */
		deferred_check_t *entry = &monitor->check_queue->items[0];

		/* Validate the top entry before processing */
		if (!validate_entry(entry)) {
			queue_remove(monitor->check_queue, NULL);
			continue; /* Process next item */
		}

		/* Check if it's time to process this entry */
		if (current_time->tv_sec < entry->next_check.tv_sec ||
		    (current_time->tv_sec == entry->next_check.tv_sec &&
		     current_time->tv_nsec < entry->next_check.tv_nsec)) {
			/* Not yet time for this check. Since it's a min-heap, no other checks are ready. */
			break;
		}

		items_processed++;

		log_message(DEBUG, "Processing deferred check for %s with %d watches", entry->path, entry->watch_count);

		/* Get the root entity state */
		entity_state_t *root_state = get_root_state_for_entry(entry);
		if (!root_state) {
			queue_remove(monitor->check_queue, entry->path);
			continue;
		}

		/* If the entity is no longer active, just remove from queue */
		if (!root_state->activity_in_progress) {
			log_message(DEBUG, "Directory %s no longer active, removing from queue", entry->path);
			queue_remove(monitor->check_queue, entry->path);
			continue;
		}

		/* Verify if the quiet period has truly elapsed */
		long elapsed_ms;
		bool quiet_period_has_elapsed = check_quiet_elapsed(root_state, current_time, &elapsed_ms);

		if (!quiet_period_has_elapsed) {
			/* Quiet period not yet elapsed, reschedule */
			watch_entry_t *primary_watch = get_primary_watch(entry);
			log_message(DEBUG, "Quiet period not yet elapsed for %s (watch: %s), rescheduling",
			        			root_state->path_state->path, primary_watch ? primary_watch->name : "unknown");

			reschedule_check(monitor, entry, root_state, current_time);
			continue;
		}

		log_message(DEBUG, "Quiet period elapsed for %s, performing stability verification", entry->path);

		/* Check for new directories */
		if (check_for_new_directories(monitor, entry)) {
			log_message(DEBUG, "Found new directories during scan, deferring command execution");

			/* Synchronize state after adding watches but before rescheduling */
			synchronize_activity_states(root_state->path_state, root_state);

			/* Reschedule with a shorter interval for quick follow-up */
			struct timespec next_check;
			next_check.tv_sec = current_time->tv_sec;
			next_check.tv_nsec = current_time->tv_nsec + 200000000; /* 200ms */
			if (next_check.tv_nsec >= 1000000000) {
				next_check.tv_sec++;
				next_check.tv_nsec -= 1000000000;
			}

			/* Update entry and restore heap property */
			entry->next_check = next_check;
			heap_down(monitor->check_queue->items, monitor->check_queue->size, 0);

			continue;
		}

		/* Perform directory stability scan */
		dir_stats_t current_stats;
		bool scan_completed = scan_directory_stability(root_state, entry->path, &current_stats);

		/* Handle scan failure */
		if (!scan_completed) {
			scan_failure_type_t failure_type = handle_scan_failure(monitor, entry, root_state, current_time);

			if (failure_type == SCAN_FAILURE_MAX_ATTEMPTS_REACHED) {
				/* Remove from queue */
				queue_remove(monitor->check_queue, entry->path);
				continue;
			} else if (failure_type == SCAN_FAILURE_DIRECTORY_DELETED) {
				/* Reschedule for another check */
				struct timespec next_check;
				next_check.tv_sec = current_time->tv_sec + 2; /* 2 seconds */
				next_check.tv_nsec = current_time->tv_nsec;

				/* Update entry */
				entry->next_check = next_check;
				heap_down(monitor->check_queue->items, monitor->check_queue->size, 0);
				continue;
			}
		}

		/* Determine stability */
		bool is_stable = is_directory_stable(root_state, &current_stats, scan_completed);

		/* Synchronize updated stats with other watches for the same path */
		synchronize_activity_states(root_state->path_state, root_state);

		if (!is_stable) {
			/* Directory is unstable - reset counter and reschedule */
			root_state->stability_check_count = 0;
			root_state->instability_count++; /* Increment instability counter */

			/* Update activity timestamp */
			root_state->last_activity_in_tree = *current_time;
			synchronize_activity_states(root_state->path_state, root_state);

			log_message(DEBUG, "Directory %s is still unstable (instability count: %d), rescheduling",
			            		entry->path, root_state->instability_count);

			reschedule_check(monitor, entry, root_state, current_time);
			continue;
		}

		/* Directory is stable - determine if enough checks have been completed */
		root_state->stability_check_count++;

		/* Calculate required checks based on complexity factors */
		int required_checks = calculate_required_checks(root_state, &current_stats);

		log_message(DEBUG, "Stability check %d/%d for %s: cumulative changes (%+d files, %+d dirs, %+d depth) in dir with %d entries, depth %d",
		    				root_state->stability_check_count, required_checks, root_state->path_state->path,
		            		root_state->cumulative_file_change, root_state->cumulative_dir_change, root_state->cumulative_depth_change,
		            		current_stats.recursive_file_count + current_stats.recursive_dir_count,
		            		current_stats.max_depth > 0 ? current_stats.max_depth : current_stats.depth);

		/* Check if we have enough consecutive stable checks */
		if (root_state->stability_check_count < required_checks) {
			/* Not enough checks yet, schedule quick follow-up check */
			struct timespec next_check;
			next_check.tv_sec = current_time->tv_sec;
			next_check.tv_nsec = current_time->tv_nsec + 200000000; /* 200ms */

			/* Normalize timestamp */
			if (next_check.tv_nsec >= 1000000000) {
				next_check.tv_sec++;
				next_check.tv_nsec -= 1000000000;
			}

			/* Update entry and restore heap property */
			entry->next_check = next_check;
			heap_down(monitor->check_queue->items, monitor->check_queue->size, 0);

			continue;
		}

		/* Directory is stable with sufficient consecutive checks - execute commands */
		commands_attempted_total++;
		log_message(INFO, "Directory %s stability confirmed (%d/%d checks), proceeding to command execution",
						   root_state->path_state->path, root_state->stability_check_count, required_checks);

		/* Reset stability tracking */
		reset_stability_tracking(root_state);

		/* Execute commands */
		int commands_executed;
		execute_deferred_commands(monitor, entry, root_state, current_time, &commands_executed);
		commands_executed_total += commands_executed;

		/* Remove entry from queue after processing all watches */
		queue_remove(monitor->check_queue, entry->path);
	}

	if (items_processed > 0) {
		log_message(DEBUG, "Finished processing %d overdue deferred checks. Attempted: %d, Executed: %d. Remaining queue size: %d",
		        			items_processed, commands_attempted_total, commands_executed_total, monitor->check_queue->size);
	}
}
