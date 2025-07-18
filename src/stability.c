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

/* Maximum allowed failures before giving up */
#define MAX_FAILED_CHECKS 3

/* Find the root state for a given entity state */
entity_state_t *stability_root(entity_state_t *state) {
	if (!state || !state->watch || !state->watch->path || !state->path_state) {
		if (state && state->path_state) {
			log_message(WARNING, "Invalid watch info for state %s", state->path_state->path);
		}
		return NULL;
	}

	/* If current state is already the root, return it */
	if (strcmp(state->path_state->path, state->watch->path) == 0) {
		return state;
	}

	/* Otherwise, get the state for the watch path */
	return states_get(state->watch->path, ENTITY_DIRECTORY, state->watch);
}

/* Determine if a command should be executed based on operation type and debouncing */
bool stability_ready(monitor_t *monitor, entity_state_t *state, operation_type_t op, int default_debounce_ms) {
	if (!state) return false;

	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	/* Record activity (updates timestamps and root tree time) */
	scanner_track(state, op);

	/* Directory content changes always defer execution to process_deferred_dir_scans */
	if (op == OP_DIR_CONTENT_CHANGED) {
		entity_state_t *root = stability_root(state);
		if (root && monitor) {
			/* Always trigger a deferred check; queue deduplicates */
			root->activity_active = true;

			/* Reset stability_lost flag when activity becomes active to prevent repeated penalties */
			root->stability_lost = false;

			log_message(DEBUG, "Directory content change for %s, marked root %s as active, command deferred",
			        			state->path_state->path, root->path_state->path);
			scanner_sync(root->path_state, root);

			if (!root) {
				return false;
			}

			stability_defer(monitor, root);
			log_message(DEBUG, "Added directory %s to deferred check queue", root->path_state->path);
		}
		return false; /* Decision happens later in process_deferred_dir_scans */
	}

	/* Standard time-based debounce for non-directory-content operations */
	long elapsed_ms_since_command = (now.tv_sec - state->command_time) * 1000;

	/* Adjust debounce based on operation type */
	int debounce_ms = default_debounce_ms;
	switch (op) {
		case OP_FILE_DELETED:
		case OP_DIR_DELETED:
		case OP_FILE_CREATED:
		case OP_DIR_CREATED:
			debounce_ms = default_debounce_ms > 0 ? default_debounce_ms / 4 : 0; /* Shorter debounce */
			break;
		case OP_FILE_CONTENT_CHANGED:
			debounce_ms = default_debounce_ms > 0 ? default_debounce_ms / 2 : 0; /* Medium debounce */
			break;
		default: /* METADATA, RENAME etc. use default */
			break;
	}
	if (debounce_ms < 0) debounce_ms = 0;

	log_message(DEBUG, "Debounce check for %s: %ld ms elapsed, %d ms required",
	        			state->path_state->path, elapsed_ms_since_command, debounce_ms);

	/* Check if enough time has passed or if it's the first command */
	if (elapsed_ms_since_command >= debounce_ms || state->command_time == 0) {
		log_message(DEBUG, "Debounce check passed for %s, command allowed", state->path_state->path);
		return true;
	}

	log_message(DEBUG, "Command execution debounced for %s", state->path_state->path);
	return false;
}

/* Schedule a deferred stability check for a directory */
void stability_defer(monitor_t *monitor, entity_state_t *state) {
	if (!monitor || !state) {
		log_message(WARNING, "Cannot schedule deferred check - invalid monitor or state");
		return;
	}

	if (!state->path_state || !state->watch) {
		log_message(WARNING, "Cannot schedule deferred check - state has null path_state or watch");
		return;
	}

	/* Find the root state for this entity */
	entity_state_t *root_state = stability_root(state);
	if (!root_state) {
		/* If no root found, use the provided state if it's a directory */
		if (state->type == ENTITY_DIRECTORY) {
			root_state = state;
		} else {
			log_message(WARNING, "Cannot schedule check for %s: no root state found", state->path_state->path);
			return;
		}
	}

	/* Force root state to be active */
	root_state->activity_active = true;

	/* Reset stability_lost flag when activity becomes active to prevent repeated penalties */
	root_state->stability_lost = false;

	/* Initialize reference stats if needed - CRITICAL for empty directories */
	if (!root_state->reference_init) {
		root_state->reference_stats = root_state->dir_stats;
		root_state->reference_init = true;
		log_message(DEBUG, "Initialized reference stats for %s: files=%d, dirs=%d, depth=%d",
		        			root_state->path_state->path, root_state->dir_stats.file_count,
		            		root_state->dir_stats.dir_count, root_state->dir_stats.depth);
	}

	/* Calculate check time based on quiet period */
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	/* Ensure we don't use a timestamp in the past */
	if (root_state->tree_activity.tv_sec < now.tv_sec - 10) {
		log_message(DEBUG, "Last activity timestamp for %s is too old, using current time", root_state->path_state->path);
		root_state->tree_activity = now;
	}

	long required_quiet = scanner_delay(root_state);

	struct timespec next_check;
	next_check.tv_sec = root_state->tree_activity.tv_sec + (required_quiet / 1000);
	next_check.tv_nsec = root_state->tree_activity.tv_nsec + ((required_quiet % 1000) * 1000000);

	/* Normalize nsec */
	if (next_check.tv_nsec >= 1000000000) {
		next_check.tv_sec++;
		next_check.tv_nsec -= 1000000000;
	}

	/* Add to queue */
	queue_upsert(monitor->check_queue, root_state->path_state->path, root_state->watch, next_check);
	
	/* Store the calculated quiet period for consistent use */
	int index = queue_find(monitor->check_queue, root_state->path_state->path);
	if (index >= 0) {
		monitor->check_queue->items[index].scheduled_period = required_quiet;
	}

	log_message(DEBUG, "Scheduled deferred check for %s: in %ld ms (directory with %d files, %d dirs)",
	            		root_state->path_state->path, required_quiet, root_state->dir_stats.file_count,
						root_state->dir_stats.dir_count);
}

/* Get the primary watch from a deferred check entry */
watch_entry_t *stability_watch(deferred_check_t *entry) {
	if (!entry || entry->watch_count <= 0) {
		return NULL;
	}
	return entry->watches[0];
}

/* Get the root entity state for a deferred check entry */
entity_state_t *stability_entry(deferred_check_t *entry) {
	watch_entry_t *primary_watch = stability_watch(entry);
	if (!primary_watch) {
		log_message(WARNING, "Deferred check for %s has no watches", entry->path);
		return NULL;
	}

	entity_state_t *root_state = states_get(entry->path, ENTITY_DIRECTORY, primary_watch);
	if (!root_state) {
		log_message(WARNING, "Cannot find state for %s", entry->path);
		return NULL;
	}

	return root_state;
}

/* Check if quiet period has elapsed for a directory */
bool stability_quiet(entity_state_t *root_state, struct timespec *current_time, long *elapsed_ms_out, long required_quiet) {
	if (!root_state || !current_time) {
		return false;
	}

	struct timespec last_activity = root_state->tree_activity;
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

	log_message(DEBUG, "Path %s: %ld ms elapsed of %ld ms quiet period, direct_entries=%d+%d, recursive_entries=%d+%d, depth=%d",
	        			root_state->path_state->path, elapsed_ms, required_quiet, root_state->dir_stats.file_count,
						root_state->dir_stats.dir_count, root_state->dir_stats.tree_files, root_state->dir_stats.tree_dirs,
	        			root_state->dir_stats.depth);

	return scanner_ready(root_state, current_time, required_quiet);
}

/* Reschedule a deferred check */
void stability_delay(monitor_t *monitor, deferred_check_t *entry, entity_state_t *root_state, struct timespec *current_time, long required_quiet) {
	if (!monitor || !entry || !root_state || !current_time) {
		return;
	}

	/* Update next check time based on latest activity */
	struct timespec next_check;
	next_check.tv_sec = root_state->tree_activity.tv_sec + (required_quiet / 1000);
	next_check.tv_nsec = root_state->tree_activity.tv_nsec + ((required_quiet % 1000) * 1000000);

	/* Normalize timestamp */
	if (next_check.tv_nsec >= 1000000000) {
		next_check.tv_sec++;
		next_check.tv_nsec -= 1000000000;
	}

	/* Update the entry in place and restore heap property */
	entry->next_check = next_check;
	entry->scheduled_period = required_quiet;
	heap_down(monitor->check_queue->items, monitor->check_queue->size, 0);
}

/* Check for new directories in recursive watches */
bool stability_new(monitor_t *monitor, deferred_check_t *entry) {
	if (!monitor || !entry) {
		return false;
	}

	int prev_watch_count = monitor->watch_count;

	/* For recursive watches, scan for new directories */
	for (int i = 0; i < entry->watch_count; i++) {
		if (entry->watches[i]->recursive) {
			monitor_tree(monitor, entry->path, entry->watches[i]);
		}
	}

	return monitor->watch_count > prev_watch_count;
}

/* Perform directory stability verification */
bool stability_scan(entity_state_t *root_state, const char *path, dir_stats_t *stats_out) {
	if (!root_state || !path || !stats_out) {
		return false;
	}

	/* Perform recursive stability verification */
	bool scan_completed = scanner_stable(root_state, path, stats_out);

	/* Only update directory stats if the scan was fully completed */
	if (scan_completed) {
		root_state->checks_failed = 0; /* Reset failed checks on success */

		/* Save previous stats for comparison before overwriting */
		dir_stats_t temp_stats = root_state->dir_stats;
		root_state->dir_stats = *stats_out;

		/* Update cumulative changes based on the difference */
		root_state->prev_stats = temp_stats;
		scanner_update(root_state);

		log_message(DEBUG, "Stability scan for %s: files=%d, dirs=%d, size=%s, recursive_files=%d, recursive_dirs=%d, max_depth=%d",
		    				path, stats_out->file_count, stats_out->dir_count, format_size((ssize_t)stats_out->tree_size, false),
		        			stats_out->tree_files, stats_out->tree_dirs, stats_out->max_depth);
	}

	return scan_completed;
}

/* Handle scan failure cases */
failure_type_t stability_fail(monitor_t *monitor, deferred_check_t *entry, entity_state_t *root_state, struct timespec *current_time) {
	if (!monitor || !entry || !root_state || !current_time) {
		return SCAN_FAILURE_TEMPORARY_ERROR;
	}

	/* Check if the directory still exists */
	struct stat st;
	if (stat(entry->path, &st) != 0 || !S_ISDIR(st.st_mode)) {
		root_state->checks_failed++;
		log_message(DEBUG, "Directory %s not found (attempt %d/%d)", entry->path, root_state->checks_failed, MAX_FAILED_CHECKS);

		/* After multiple consecutive failures, consider it permanently deleted */
		if (root_state->checks_failed >= MAX_FAILED_CHECKS) {
			log_message(INFO, "Directory %s confirmed deleted after %d failed checks, cleaning up",
							   entry->path, root_state->checks_failed);

			/* Mark as not active for all watches */
			root_state->activity_active = false;
			root_state->exists = false;
			scanner_sync(root_state->path_state, root_state);

			return SCAN_FAILURE_MAX_ATTEMPTS_REACHED;
		}

		return SCAN_FAILURE_DIRECTORY_DELETED;
	} else {
		/* Scan failed for other reasons (e.g., temp files) */
		root_state->checks_failed = 0; /* Reset counter */
		return SCAN_FAILURE_TEMPORARY_ERROR;
	}
}

/* Calculate required stability checks based on complexity */
int stability_require(entity_state_t *root_state, const dir_stats_t *current_stats) {
	if (!root_state || !current_stats) {
		return 1;
	}

	int total_entries = current_stats->tree_files + current_stats->tree_dirs;
	int tree_depth = current_stats->max_depth > 0 ? current_stats->max_depth : current_stats->depth;

	/* Use cumulative changes for adapting stability requirements */
	int abs_file_change = abs(root_state->cumulative_file);
	int abs_dir_change = abs(root_state->cumulative_dirs);
	int abs_depth_change = abs(root_state->cumulative_depth);
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
bool stability_stable(entity_state_t *root_state, const dir_stats_t *current_stats, bool scan_completed) {
	if (!root_state || !current_stats || !scan_completed) {
		return false;
	}

	bool has_prev_stats = (root_state->prev_stats.file_count > 0 || root_state->prev_stats.dir_count > 0);
	if (has_prev_stats && !scanner_compare(&root_state->prev_stats, (dir_stats_t *) current_stats)) {
		log_message(DEBUG, "Directory unstable: content changed from %d/%d to %d/%d",
		        			root_state->prev_stats.tree_files, root_state->prev_stats.tree_dirs,
		        			current_stats->tree_files, current_stats->tree_dirs);
		return false;
	}

	return true;
}

/* Reset stability tracking after successful command execution */
void stability_reset(entity_state_t *root_state) {
	if (!root_state) {
		return;
	}

	/* Reset activity flag, stability counter, and all change tracking on the root state */
	root_state->activity_active = false;
	root_state->checks_count = 0;
	root_state->reference_stats = root_state->dir_stats;
	root_state->reference_init = true;
	root_state->cumulative_file = 0;
	root_state->cumulative_dirs = 0;
	root_state->cumulative_depth = 0;
	root_state->cumulative_size = 0;
	root_state->unstable_count = 0;
	root_state->stability_lost = false;
	
	/* Update prev_stats to current stats for next cycle's comparison */
	root_state->prev_stats = root_state->dir_stats;

	/* Propagate the reset state to all related states for this path */
	scanner_sync(root_state->path_state, root_state);
}

/* Execute commands for all watches of a stable directory */
bool stability_execute(monitor_t *monitor, deferred_check_t *entry, entity_state_t *root_state, struct timespec *current_time, int *count) {
	if (!monitor || !entry || !root_state || !current_time) {
		return false;
	}

	int commands_executed = 0;

	/* Find the most recent file if any command needs it */
	for (int i = 0; i < entry->watch_count; i++) {
		if (strstr(entry->watches[i]->command, "%f") || strstr(entry->watches[i]->command, "%F")) {
			free(root_state->trigger_path);
			root_state->trigger_path = NULL; /* Clear previous path */

			char *scan_path = root_state->active_path ? root_state->active_path : entry->path;
			struct stat st;

			if (stat(scan_path, &st) == 0 && S_ISDIR(st.st_mode)) {
				/* It's a directory, scan it for the most recent file */
				root_state->trigger_path = scanner_newest(scan_path);
			} else {
				/* It's a file, or doesn't exist; use the path directly */
				root_state->trigger_path = strdup(scan_path);
			}

			if (root_state->trigger_path) {
				log_message(DEBUG, "Found trigger file for %%f/%%F: %s", root_state->trigger_path);
			}
			break; /* Only need to find it once */
		}
	}

	/* Create synthetic event */
	file_event_t synthetic_event = {
		.path = root_state->active_path ? root_state->active_path : entry->path,
		.type = EVENT_STRUCTURE,
		.time = root_state->last_update,
		.wall_time = root_state->wall_time,
		.user_id = getuid()
	};

	/* Execute commands for ALL watches of this path */
	for (int i = 0; i < entry->watch_count; i++) {
		watch_entry_t *watch = entry->watches[i];

		/* Get or create state for this specific watch */
		entity_state_t *watch_state = states_get(entry->path, ENTITY_DIRECTORY, watch);
		if (!watch_state) {
			log_message(WARNING, "Unable to get state for %s with watch %s during command execution",
								  entry->path, watch->name);
			continue;
		}

		/* Execute command */
		log_message(INFO, "Executing deferred command for %s (watch: %s)",
						   entry->path, watch->name);

		if (command_execute(watch, &synthetic_event, false)) {
			commands_executed++;

			/* Update last command time for this specific watch */
			watch_state->command_time = current_time->tv_sec;

			log_message(DEBUG, "Command execution successful for %s (watch: %s), updated last command time",
								entry->path, watch->name);
		} else {
			log_message(WARNING, "Command execution failed for %s (watch: %s)",
								  entry->path, watch->name);
		}
	}

	if (count) {
		*count = commands_executed;
	}

	return commands_executed > 0;
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
		/* Get the top entry (earliest scheduled check) */
		deferred_check_t *entry = &monitor->check_queue->items[0];

		/* Validate the top entry before processing */
		if (!entry || !entry->path) {
			log_message(WARNING, "Corrupted entry in queue, removing");
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
		entity_state_t *root_state = stability_entry(entry);
		if (!root_state) {
			queue_remove(monitor->check_queue, entry->path);
			continue;
		}

		/* If the entity is no longer active, just remove from queue */
		if (!root_state->activity_active) {
			log_message(DEBUG, "Directory %s no longer active, removing from queue", entry->path);
			queue_remove(monitor->check_queue, entry->path);
			continue;
		}

		/* Check if we're in verification mode or need to verify quiet period */
		bool quiet_period_has_elapsed = entry->in_verification;
		long required_quiet = entry->scheduled_period;
		
		if (!quiet_period_has_elapsed) {
			/* Use the stored quiet period from when this check was scheduled */
			if (required_quiet <= 0) {
				/* Fallback: calculate if not stored (shouldn't happen) */
				required_quiet = scanner_delay(root_state);
				entry->scheduled_period = required_quiet;
			}
			
			long elapsed_ms;
			quiet_period_has_elapsed = stability_quiet(root_state, current_time, &elapsed_ms, required_quiet);

			if (!quiet_period_has_elapsed) {
				/* Quiet period not yet elapsed, reschedule */
				watch_entry_t *primary_watch = stability_watch(entry);
				log_message(DEBUG, "Quiet period not yet elapsed for %s (watch: %s), rescheduling",
				        			root_state->path_state->path, primary_watch ? primary_watch->name : "unknown");

				stability_delay(monitor, entry, root_state, current_time, required_quiet);
				continue;
			}
			
			/* Quiet period has elapsed, enter verification mode */
			entry->in_verification = true;
			log_message(DEBUG, "Quiet period elapsed for %s, entering verification mode", entry->path);
		}

		log_message(DEBUG, "Performing stability verification for %s", entry->path);

		/* Check for new directories */
		if (stability_new(monitor, entry)) {
			log_message(DEBUG, "Found new directories during scan, treating as new activity");
		
			/* Synchronize state after adding watches */
			scanner_sync(root_state->path_state, root_state);
		
			/* Treat new directory discovery as activity - update timestamp and reschedule with full quiet period */
			root_state->tree_activity = *current_time;
			root_state->unstable_count++; /* Increment since directory structure is still changing */
			
			/* Reset verification flag since this is new activity */
			entry->in_verification = false;
			
			log_message(DEBUG, "New directory discovery updated activity timestamp, exiting verification mode and rescheduling with full quiet period");
			
			/* Reschedule with proper quiet period calculation based on new complexity */
			required_quiet = scanner_delay(root_state);
			log_message(DEBUG, "Recalculated quiet period for new directories: %ld ms", required_quiet);
			stability_delay(monitor, entry, root_state, current_time, required_quiet);
			continue;
		}

		/* Perform directory stability scan */
		dir_stats_t current_stats;
		bool scan_completed = stability_scan(root_state, entry->path, &current_stats);

		/* Handle scan failure */
		if (!scan_completed) {
			failure_type_t failure_type = stability_fail(monitor, entry, root_state, current_time);

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
		bool is_stable = stability_stable(root_state, &current_stats, scan_completed);

		/* Synchronize updated stats with other watches for the same path */
		scanner_sync(root_state->path_state, root_state);

		if (!is_stable) {
			/* Directory is unstable - reset counter and reschedule */
			root_state->checks_count = 0;
			root_state->unstable_count++; /* Increment only for actual stability scan failures */

			/* Update activity timestamp */
			root_state->tree_activity = *current_time;
			scanner_sync(root_state->path_state, root_state);

			/* Reset verification flag since this is new activity */
			entry->in_verification = false;

			log_message(DEBUG, "Directory %s failed stability scan (instability count: %d), exiting verification mode and rescheduling",
			            		entry->path, root_state->unstable_count);

			/* Recalculate quiet period based on new instability */
			required_quiet = scanner_delay(root_state);
			log_message(DEBUG, "Recalculated quiet period for instability: %ld ms", required_quiet);
			stability_delay(monitor, entry, root_state, current_time, required_quiet);
			continue;
		}

		/* Directory is stable - determine if enough checks have been completed */
		root_state->checks_count++;

		/* Calculate required checks based on complexity factors */
		int required_checks = stability_require(root_state, &current_stats);

		log_message(DEBUG, "Stability check %d/%d for %s: changes (%+d files, %+d dirs, %+d depth) total (%d entries, depth %d)",
		    				root_state->checks_count, required_checks, root_state->path_state->path, root_state->cumulative_file, 
							root_state->cumulative_dirs, root_state->cumulative_depth, current_stats.tree_files + current_stats.tree_dirs,
		            		current_stats.max_depth > 0 ? current_stats.max_depth : current_stats.depth);

		/* Check if we have enough consecutive stable checks */
		if (root_state->checks_count < required_checks) {
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
						   root_state->path_state->path, root_state->checks_count, required_checks);

		/* Reset stability tracking */
		stability_reset(root_state);

		/* Execute commands */
		int commands_executed;
		stability_execute(monitor, entry, root_state, current_time, &commands_executed);
		commands_executed_total += commands_executed;

		/* Remove entry from queue after processing all watches */
		queue_remove(monitor->check_queue, entry->path);
	}

	if (items_processed > 0) {
		log_message(DEBUG, "Finished processing %d overdue deferred checks. Attempted: %d, Executed: %d. Remaining queue size: %d",
		        			items_processed, commands_attempted_total, commands_executed_total, monitor->check_queue->size);
	}
}
