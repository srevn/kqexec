#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/stat.h>

#include "monitor.h"
#include "command.h"
#include "states.h"
#include "log.h"

/* Maximum number of events to process at once */
#define MAX_EVENTS 64

/* Maximum path length */
#define MAX_PATH_LEN 1024

/* Create a new file/directory monitor */
monitor_t *monitor_create(config_t *config) {
	monitor_t *monitor;
	
	if (config == NULL) {
		log_message(LOG_LEVEL_ERR, "Invalid configuration for monitor");
		return NULL;
	}
	
	monitor = calloc(1, sizeof(monitor_t));
	if (monitor == NULL) {
		log_message(LOG_LEVEL_ERR, "Failed to allocate memory for monitor");
		return NULL;
	}
	
	monitor->config = config;
	monitor->kq = -1;
	monitor->watches = NULL;
	monitor->watch_count = 0;
	monitor->running = false;
	
	return monitor;
}

/* Free resources used by a watch_info structure */
static void watch_info_destroy(watch_info_t *info) {
	if (info == NULL) {
		return;
	}
	
	/* Only close the file descriptor if it's not shared with other watches */
	if (info->wd >= 0 && !info->is_shared_fd) {
		close(info->wd);
	}
	
	free(info->path);
	free(info);
}

/* Destroy a monitor and free all associated resources */
void monitor_destroy(monitor_t *monitor) {
	if (monitor == NULL) {
		return;
	}
	
	/* Close kqueue */
	if (monitor->kq >= 0) {
		close(monitor->kq);
	}
	
	/* Free watches */
	for (int i = 0; i < monitor->watch_count; i++) {
		watch_info_destroy(monitor->watches[i]);
	}
	
	free(monitor->watches);
	free(monitor);
}

/* Add a watch info to the monitor's array */
static bool monitor_add_watch_info(monitor_t *monitor, watch_info_t *info) {
	watch_info_t **new_watches;
	
	new_watches = realloc(monitor->watches, (monitor->watch_count + 1) * sizeof(watch_info_t *));
	if (new_watches == NULL) {
		log_message(LOG_LEVEL_ERR, "Failed to allocate memory for watch info");
		return false;
	}
	
	monitor->watches = new_watches;
	monitor->watches[monitor->watch_count] = info;
	monitor->watch_count++;
	
	return true;
}

/* Find a watch info entry by path */
static watch_info_t *monitor_find_watch_info_by_path(monitor_t *monitor, const char *path) {
	for (int i = 0; i < monitor->watch_count; i++) {
		if (strcmp(monitor->watches[i]->path, path) == 0) {
			return monitor->watches[i];
		}
	}
	
	return NULL;
}

/* Set up kqueue monitoring for a file or directory */
static bool monitor_add_kqueue_watch(monitor_t *monitor, watch_info_t *info) {
	struct kevent changes[1];
	int flags = 0;
	
	/* Set up flags based on consolidated events */
	if (info->watch->events & EVENT_CONTENT) {
		flags |= NOTE_WRITE | NOTE_EXTEND;
	}
	if (info->watch->events & EVENT_METADATA) {
		flags |= NOTE_ATTRIB | NOTE_LINK;
	}
	if (info->watch->events & EVENT_MODIFY) {
		flags |= NOTE_DELETE | NOTE_RENAME | NOTE_REVOKE;
	}
	
	/* Register for events */
	EV_SET(&changes[0], info->wd, EVFILT_VNODE, EV_ADD | EV_CLEAR, flags, 0, info);
	
	if (kevent(monitor->kq, changes, 1, NULL, 0, NULL) == -1) {
		log_message(LOG_LEVEL_ERR, "Failed to register kqueue events for %s: %s", 
				  info->path, strerror(errno));
		return false;
	}
	
	return true;
}

/* Check if a path is a hidden file or directory (starts with dot) */
static bool is_hidden_path(const char *path) {
	const char *basename = strrchr(path, '/');
	if (basename) {
		basename++; /* Skip the slash */
	} else {
		basename = path; /* No slash, use the whole path */
	}
	
	/* Check if the basename starts with a dot (hidden) */
	return basename[0] == '.';
}

/* Recursively add watches for a directory and its subdirectories */
static bool monitor_add_dir_recursive(monitor_t *monitor, const char *dir_path, watch_entry_t *watch, bool skip_existing) {
	DIR *dir;
	struct dirent *entry;
	
	/* Skip hidden directories unless hidden is true */
	if (!watch->hidden && is_hidden_path(dir_path)) {
		log_message(LOG_LEVEL_DEBUG, "Skipping hidden directory: %s", dir_path);
		return true; /* Not an error, just skipping */
	}
	
	dir = opendir(dir_path);
	if (dir == NULL) {
		log_message(LOG_LEVEL_ERR, "Failed to open directory %s: %s", 
				  dir_path, strerror(errno));
		return false;
	}
	
	/* Check if there's an existing watch for this directory path that we can reuse */
	watch_info_t *existing_info = monitor_find_watch_info_by_path(monitor, dir_path);
	
	if (existing_info != NULL && !skip_existing) {
		/* Reuse the existing file descriptor */
		int fd = existing_info->wd;
		
		watch_info_t *info = calloc(1, sizeof(watch_info_t));
		if (info == NULL) {
			log_message(LOG_LEVEL_ERR, "Failed to allocate memory for watch info");
			closedir(dir);
			return false;
		}
		
		info->wd = fd;
		info->path = strdup(dir_path);
		info->watch = watch;
		info->is_shared_fd = true; /* Mark as shared */
		
		/* Update the existing info to also mark it as shared */
		existing_info->is_shared_fd = true;
		
		if (!monitor_add_watch_info(monitor, info)) {
			watch_info_destroy(info);
			closedir(dir);
			return false;
		}
		
		log_message(LOG_LEVEL_DEBUG, "Added additional watch for directory: %s (with shared FD)", dir_path);
	}
	/* If no existing watch or if skip_existing is true but no watch exists yet */
	else if (existing_info == NULL || (skip_existing && monitor_find_watch_info_by_path(monitor, dir_path) == NULL)) {
		int fd = open(dir_path, O_RDONLY);
		if (fd == -1) {
			log_message(LOG_LEVEL_ERR, "Failed to open %s: %s", 
					  dir_path, strerror(errno));
			closedir(dir);
			return false;
		}
		
		watch_info_t *info = calloc(1, sizeof(watch_info_t));
		if (info == NULL) {
			log_message(LOG_LEVEL_ERR, "Failed to allocate memory for watch info");
			close(fd);
			closedir(dir);
			return false;
		}
		
		info->wd = fd;
		info->path = strdup(dir_path);
		info->watch = watch;
		info->is_shared_fd = false; /* Initially not shared */
		
		if (!monitor_add_watch_info(monitor, info)) {
			watch_info_destroy(info);
			closedir(dir);
			return false;
		}
		
		if (!monitor_add_kqueue_watch(monitor, info)) {
			closedir(dir);
			return false;
		}
		
		log_message(LOG_LEVEL_DEBUG, "Added new watch for directory: %s", dir_path);
	}
	
	/* If recursive monitoring is enabled, process subdirectories */
	if (watch->recursive) {
		while ((entry = readdir(dir)) != NULL) {
			char path[MAX_PATH_LEN];
			struct stat st;
			
			/* Skip . and .. */
			if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
				continue;
			}
			
			/* Skip hidden files/directories unless hidden is true */
			if (!watch->hidden && entry->d_name[0] == '.') {
				log_message(LOG_LEVEL_DEBUG, "Skipping hidden file/directory: %s/%s", dir_path, entry->d_name);
				continue;
			}
			
			snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);
			
			/* Check for existence if we're skipping existing paths */
			bool path_exists = false;
			if (skip_existing) {
				for (int i = 0; i < monitor->watch_count; i++) {
					if (strcmp(monitor->watches[i]->path, path) == 0 && 
						monitor->watches[i]->watch == watch) {
						path_exists = true;
						break;
					}
				}
				if (path_exists) continue;
			}
			
			if (stat(path, &st) == -1) {
				log_message(LOG_LEVEL_WARNING, "Failed to stat %s: %s", 
						  path, strerror(errno));
				continue;
			}
			
			if (S_ISDIR(st.st_mode)) {
				/* Recursively add subdirectory */
				if (!monitor_add_dir_recursive(monitor, path, watch, skip_existing)) {
					log_message(LOG_LEVEL_WARNING, "Failed to add recursive watch for %s", path);
					/* Continue with other directories */
				}
			}
		}
	}
	
	closedir(dir);
	return true;
}

/* Add a watch for a file or directory based on a watch entry */
bool monitor_add_watch(monitor_t *monitor, watch_entry_t *watch) {
	struct stat st;
	
	if (monitor == NULL || watch == NULL) {
		log_message(LOG_LEVEL_ERR, "Invalid arguments to monitor_add_watch");
		return false;
	}
	
	/* Check if we already have a watch for this path, and reuse the file descriptor if we do */
	watch_info_t *existing_info = monitor_find_watch_info_by_path(monitor, watch->path);
	if (existing_info != NULL) {
		log_message(LOG_LEVEL_INFO, "Adding additional watch for %s (watch: %s)", watch->path, watch->name);
		
		/* Create a new watch_info that reuses the file descriptor */
		watch_info_t *info = calloc(1, sizeof(watch_info_t));
		if (info == NULL) {
			log_message(LOG_LEVEL_ERR, "Failed to allocate memory for watch info");
			return false;
		}
		
		/* Reuse the existing file descriptor */
		info->wd = existing_info->wd;
		info->path = strdup(watch->path);
		info->watch = watch;
		info->is_shared_fd = true; /* Mark that this FD is shared */
		
		if (!monitor_add_watch_info(monitor, info)) {
			watch_info_destroy(info);
			return false;
		}
		
		/* Update the existing info to also mark it as shared */
		existing_info->is_shared_fd = true;
		
		/* No need to add kqueue watch again since we're using the same FD */
		return true;
	}
	
	/* Get file/directory stats */
	if (stat(watch->path, &st) == -1) {
		log_message(LOG_LEVEL_ERR, "Failed to stat %s: %s", watch->path, strerror(errno));
		return false;
	}
	
	/* Handle directories (possibly recursively) */
	if (S_ISDIR(st.st_mode)) {
		if (watch->type != WATCH_DIRECTORY) {
			log_message(LOG_LEVEL_WARNING, "%s is a directory but configured as a file", watch->path);
			watch->type = WATCH_DIRECTORY;
		}
		
		return monitor_add_dir_recursive(monitor, watch->path, watch, false);  /* false = don't skip existing */
	} 
	/* Handle regular files */
	else if (S_ISREG(st.st_mode)) {
		if (watch->type != WATCH_FILE) {
			log_message(LOG_LEVEL_WARNING, "%s is a file but configured as a directory", watch->path);
			watch->type = WATCH_FILE;
		}
		
		int fd = open(watch->path, O_RDONLY);
		if (fd == -1) {
			log_message(LOG_LEVEL_ERR, "Failed to open %s: %s", 
					  watch->path, strerror(errno));
			return false;
		}
		
		watch_info_t *info = calloc(1, sizeof(watch_info_t));
		if (info == NULL) {
			log_message(LOG_LEVEL_ERR, "Failed to allocate memory for watch info");
			close(fd);
			return false;
		}
		
		info->wd = fd;
		info->path = strdup(watch->path);
		info->watch = watch;
		info->is_shared_fd = false; /* Initially not shared */
		
		if (!monitor_add_watch_info(monitor, info)) {
			watch_info_destroy(info);
			return false;
		}
		
		return monitor_add_kqueue_watch(monitor, info);
	} 
	/* Unsupported file type */
	else {
		log_message(LOG_LEVEL_ERR, "Unsupported file type for %s", watch->path);
		return false;
	}
}

/* Set up the monitor by creating kqueue and adding watches */
bool monitor_setup(monitor_t *monitor) {
	if (monitor == NULL) {
		log_message(LOG_LEVEL_ERR, "Invalid monitor");
		return false;
	}
	
	/* Create kqueue */
	monitor->kq = kqueue();
	if (monitor->kq == -1) {
		log_message(LOG_LEVEL_ERR, "Failed to create kqueue: %s", strerror(errno));
		return false;
	}
	
	/* Add watches for each entry in the configuration */
	for (int i = 0; i < monitor->config->watch_count; i++) {
		if (!monitor_add_watch(monitor, monitor->config->watches[i])) {
			log_message(LOG_LEVEL_ERR, "Failed to add watch for %s", 
					  monitor->config->watches[i]->path);
			return false;
		}
	}
	
	return true;
}

/* Convert kqueue flags to event type bitmask */
static event_type_t flags_to_event_type(uint32_t flags) {
	event_type_t event = EVENT_NONE;
	
	/* Content changes */
	if (flags & (NOTE_WRITE | NOTE_EXTEND)) {
		event |= EVENT_CONTENT;
	}
	
	/* Metadata changes */
	if (flags & (NOTE_ATTRIB | NOTE_LINK)) {
		event |= EVENT_METADATA;
	}
	
	/* Modification events */
	if (flags & (NOTE_DELETE | NOTE_RENAME | NOTE_REVOKE)) {
		event |= EVENT_MODIFY;
	}
	
	return event;
}

/* Process deferred directory scans after quiet periods */
static void process_deferred_dir_scans(monitor_t *monitor, struct timespec *current_time) {
	int total_dir_watches = 0;
	int watches_with_activity = 0;
	int commands_attempted = 0;
	int commands_executed = 0;
	bool new_directories_found = false;
	
	/* Track paths we've already processed in this cycle */
	char processed_paths[MAX_WATCHES][MAX_PATH_LEN];
	int processed_count = 0;

	/* Iterate through configured watches */
	for (int i = 0; i < monitor->config->watch_count; i++) {
		watch_entry_t *watch = monitor->config->watches[i];
		
		/* Only process directory watches */
		if (watch->type != WATCH_DIRECTORY) continue;
		
		total_dir_watches++;
		
		/* Check if we've already processed this path */
		bool already_processed = false;
		for (int j = 0; j < processed_count; j++) {
			if (strcmp(processed_paths[j], watch->path) == 0) {
				already_processed = true;
				break;
			}
		}
		if (already_processed) continue;
		
		/* Add to processed paths */
		if (processed_count < MAX_WATCHES) {
			strncpy(processed_paths[processed_count], watch->path, MAX_PATH_LEN - 1);
			processed_paths[processed_count][MAX_PATH_LEN - 1] = '\0';
			processed_count++;
		}
		
		/* Get root state */
		entity_state_t *root_state = get_entity_state(watch->path, ENTITY_DIRECTORY, watch);
		if (!root_state) {
			log_message(LOG_LEVEL_WARNING, "Failed to get root state for deferred check: %s (watch: %s)",
					  watch->path, watch->name);
			continue;
		}
		
		/* If not previously set, calculate and store the depth */
		if (root_state->depth == 0) {
			root_state->depth = calculate_path_depth(root_state->path);
		}
		
		/* Check for activity in progress */
		if (root_state->activity_in_progress) {
			watches_with_activity++;
			
			/* First check if the regular quiet period has elapsed */
			bool quiet_period_has_elapsed = is_quiet_period_elapsed(root_state, current_time);
			
			if (quiet_period_has_elapsed) {
				/* Quiet period elapsed, now do a deeper stability check */
				log_message(LOG_LEVEL_DEBUG, 
						  "Quiet period elapsed for %s (watch: %s), performing stability verification",
						  root_state->path, watch->name);
				
				/* For recursive watches, scan for new directories first */
				int prev_watch_count = monitor->watch_count;
				if (watch->recursive) {
					monitor_add_dir_recursive(monitor, root_state->path, watch, true);
				}
				
				/* Check if we found new directories */
				if (monitor->watch_count > prev_watch_count) {
					log_message(LOG_LEVEL_DEBUG, "Found %d new directories during scan, deferring command execution",
							  monitor->watch_count - prev_watch_count);
					new_directories_found = true;
					
					/* Reset the activity timestamp but keep monitoring */
					root_state->last_activity_in_tree = *current_time;
					synchronize_activity_states(root_state->path, root_state);
					continue;
				}
				
				/* Perform recursive stability verification */
				dir_stats_t current_stats;
				bool scan_completed = verify_directory_stability(root_state->path, &current_stats, 0);
				
				/* Always store the stats, regardless of stability */
				root_state->dir_stats = current_stats;
				
				/* Log the scan results */
				log_message(LOG_LEVEL_DEBUG, 
					"Stability check #%d for %s: files=%d, dirs=%d, size=%zu, stable=%s",
					root_state->stability_check_count + 1, root_state->path, 
					current_stats.file_count, current_stats.dir_count, 
					current_stats.total_size, scan_completed ? "yes" : "no");
				
				/* Determine stability based on scan result and comparison */
				bool is_stable = scan_completed;  /* Initially use scan result */
				
				/* Only compare with previous stats if we have a previous scan */
				if (scan_completed && root_state->stability_check_count > 0) {
					bool counts_stable = compare_dir_stats(&root_state->prev_stats, &current_stats);
					if (!counts_stable) {
						log_message(LOG_LEVEL_DEBUG, "Directory unstable: file/dir count changed from %d/%d to %d/%d",
								   root_state->prev_stats.file_count, root_state->prev_stats.dir_count, 
								   current_stats.file_count, current_stats.dir_count);
						is_stable = false;
					}
				}
				
				/* Always update previous stats for next comparison */
				root_state->prev_stats = current_stats;
				
				if (is_stable) {
					/* Only increment stability counter if stable */
					root_state->stability_check_count++;
					
					/* Determine if we've reached enough consecutive stable checks */
					bool ready_for_command = false;
					int required_checks;
					
					/* Simplified check count logic based on directory classification */
					int total_entries = current_stats.file_count + current_stats.dir_count;
					
					/* Very small directories */
					if (total_entries < 10 && root_state->depth <= 2) {
						required_checks = 1;  /* One check is sufficient */
					}
					/* Small to medium directories */
					else if (total_entries < 100) {
						required_checks = 2;  /* Two checks */
					}
					/* Large directories */
					else if (total_entries < 1000 || root_state->depth > 4) {
						required_checks = 3;  /* Three checks */
					}
					/* Very large or complex directories */
					else {
						required_checks = 4;  /* Four checks */
					}
					
					/* Check if we have enough stable checks */
					ready_for_command = (root_state->stability_check_count >= required_checks);
					
					if (!ready_for_command) {
						/* Not yet ready, update timestamp and continue monitoring */
						root_state->last_activity_in_tree = *current_time;
						synchronize_activity_states(root_state->path, root_state);
						
						log_message(LOG_LEVEL_DEBUG, 
								  "Directory %s is stable but waiting for more confirmation (%d/%d checks)",
								  root_state->path, root_state->stability_check_count, required_checks);
						continue;
					}
					
					/* If we get here, we're ready to execute the command */
					log_message(LOG_LEVEL_INFO, 
							  "Directory %s stability confirmed (%d/%d checks), proceeding to command execution",
							  root_state->path, root_state->stability_check_count, required_checks);
				} else {
					/* Not stable, reset stability check counter */
					root_state->stability_check_count = 0;
					
					/* Store current stats for future comparison */
					root_state->prev_stats = current_stats;
					root_state->dir_stats = current_stats;
					
					/* Update timestamp and continue monitoring */
					root_state->last_activity_in_tree = *current_time;
					synchronize_activity_states(root_state->path, root_state);
					
					log_message(LOG_LEVEL_DEBUG, "Directory %s is still unstable, continuing to monitor",
							  root_state->path);
					continue;
				}
				
				/* We've confirmed stability, proceed with command execution */
				commands_attempted++;
				log_message(LOG_LEVEL_INFO,
						  "Directory %s (watch: %s) confirmed stable after %d checks, processing deferred events",
						  root_state->path, watch->name, root_state->stability_check_count);
				
				/* Reset activity flag and stability counter */
				root_state->activity_in_progress = false;
				root_state->stability_check_count = 0;
				
				/* Create synthetic event and execute command */
				file_event_t synthetic_event = {
					.path = root_state->path,
					.type = EVENT_CONTENT,
					.time = root_state->last_update,
					.wall_time = root_state->wall_time,
					.user_id = getuid()
				};
				
				/* Execute commands for ALL watches of this path */
				for (int j = 0; j < monitor->config->watch_count; j++) {
					watch_entry_t *other_watch = monitor->config->watches[j];
					
					/* Skip non-directory watches */
					if (other_watch->type != WATCH_DIRECTORY) continue;
					
					/* If this is another watch for the same path */
					if (strcmp(other_watch->path, root_state->path) == 0) {
						entity_state_t *other_state = get_entity_state(other_watch->path, ENTITY_DIRECTORY, other_watch);
						if (!other_state) continue;
						
						/* Reset activity flag */
						other_state->activity_in_progress = false;
						other_state->stability_check_count = 0;
						
						/* Execute command */
						log_message(LOG_LEVEL_INFO, "Executing deferred command for %s (watch: %s)",
								  other_state->path, other_watch->name);
						
						if (command_execute(other_watch, &synthetic_event)) {
							commands_executed++;
							
							/* Reset state change flags */
							other_state->content_changed = false;
							other_state->metadata_changed = false;
							other_state->structure_changed = false;
							
							/* Update last command time */
							other_state->last_command_time = current_time->tv_sec;
						}
					}
				}
			} else {
				log_message(LOG_LEVEL_DEBUG, "Quiet period not yet elapsed for %s (watch: %s), continuing to monitor",
						  root_state->path, watch->name);
			}
		}
	}

	/* Log summary if anything interesting happened */
	if (watches_with_activity > 0 || commands_attempted > 0 || commands_executed > 0 || new_directories_found) {
		log_message(LOG_LEVEL_DEBUG,
				  "Deferred processing summary: directories=%d, active=%d, commands_attempted=%d, executed=%d, new_dirs_found=%s",
				  total_dir_watches, watches_with_activity, commands_attempted, commands_executed, 
				  new_directories_found ? "yes" : "no");
	}
}

/* Process events from kqueue and handle commands */
bool monitor_process_events(monitor_t *monitor) {
	struct kevent events[MAX_EVENTS];
	int nev;
	struct timespec timeout, *p_timeout;

	if (!monitor || monitor->kq < 0) {
		log_message(LOG_LEVEL_ERR, "Invalid monitor state");
		return false;
	}
	
	/* Calculate timeout based on pending deferred scans */
	memset(&timeout, 0, sizeof(timeout));
	p_timeout = NULL;
	bool need_wakeup = false;
	struct timespec now_monotonic;
	clock_gettime(CLOCK_MONOTONIC, &now_monotonic);
	
	time_t earliest_wakeup_sec = now_monotonic.tv_sec + 3600; /* 1 hour is max timeout */
	long earliest_wakeup_nsec = now_monotonic.tv_nsec;
	
	/* Track unique paths to avoid duplicate processing */
	char unique_paths[MAX_WATCHES][PATH_MAX];
	int max_quiet_period_ms[MAX_WATCHES];
	int path_count = 0;
	
	/* First pass: find unique paths and their maximum quiet periods */
	for (int i = 0; i < monitor->config->watch_count; i++) {
		watch_entry_t *watch = monitor->config->watches[i];
		if (watch->type != WATCH_DIRECTORY) continue;
		
		/* Get the state for the root of the watch */
		entity_state_t *root_state = get_entity_state(watch->path, ENTITY_DIRECTORY, watch);
		if (!root_state || !root_state->activity_in_progress) continue;
		
		/* Check if we've already seen this path */
		bool path_seen = false;
		for (int j = 0; j < path_count; j++) {
			if (strcmp(unique_paths[j], watch->path) == 0) {
				/* Update with maximum quiet period */
				int quiet_period = get_required_quiet_period(root_state);
				if (quiet_period > max_quiet_period_ms[j]) {
					max_quiet_period_ms[j] = quiet_period;
				}
				path_seen = true;
				break;
			}
		}
		
		/* If this is a new path, add to our tracking */
		if (!path_seen && path_count < MAX_WATCHES) {
			strncpy(unique_paths[path_count], watch->path, PATH_MAX - 1);
			unique_paths[path_count][PATH_MAX - 1] = '\0';
			max_quiet_period_ms[path_count] = get_required_quiet_period(root_state);
			path_count++;
		}
	}
	
	/* Second pass: calculate optimal wakeup time */
	for (int i = 0; i < path_count; i++) {
		/* Find the first watch entry for this path */
		entity_state_t *root_state = NULL;
		for (int j = 0; j < monitor->config->watch_count; j++) {
			watch_entry_t *watch = monitor->config->watches[j];
			if (watch->type == WATCH_DIRECTORY && strcmp(watch->path, unique_paths[i]) == 0) {
				root_state = get_entity_state(watch->path, ENTITY_DIRECTORY, watch);
				break;
			}
		}
		
		if (!root_state || !root_state->activity_in_progress) continue;
		
		need_wakeup = true;
		
		/* Use the root's last_activity_in_tree timestamp */
		struct timespec *last_activity = &root_state->last_activity_in_tree;
		
		/* Use the maximum quiet period for this path */
		long required_quiet_period_ms = max_quiet_period_ms[i];
		
		/* Calculate elapsed time since last activity */
		long elapsed_ms = (now_monotonic.tv_sec - last_activity->tv_sec) * 1000 +
						 (now_monotonic.tv_nsec - last_activity->tv_nsec) / 1000000;
		
		/* Calculate time remaining until quiet period elapses */
		long remaining_ms = required_quiet_period_ms - elapsed_ms;
		
		/* Progressive backoff for near-timeouts */
		if (remaining_ms <= 0) {
			/* Already elapsed - use a modest delay */
			remaining_ms = 200; /* 200ms */
		} else if (remaining_ms < 50) {
			/* Very close - don't check too quickly */
			remaining_ms = 50; /* 50ms */
		} else if (remaining_ms < 100) {
			/* Close but not imminent */
			remaining_ms = 100; /* 100ms */
		} else if (remaining_ms < 500) {
			/* Take a little longer before checking again */
			remaining_ms = remaining_ms / 2 + 50;
		}
		
		log_message(LOG_LEVEL_DEBUG, "Path %s: %ld ms elapsed of %ld ms quiet period, entries=%d, dirs=%d, adjusted wait: %ld ms",
									unique_paths[i], elapsed_ms, required_quiet_period_ms, 
									root_state->dir_stats.file_count, root_state->dir_stats.dir_count,
									remaining_ms);
		
		/* Calculate absolute wakeup time */
		time_t wake_sec = now_monotonic.tv_sec + (remaining_ms / 1000);
		long wake_nsec = now_monotonic.tv_nsec + ((remaining_ms % 1000) * 1000000);
		
		/* Normalize wake_nsec */
		if (wake_nsec >= 1000000000) {
			wake_sec++;
			wake_nsec -= 1000000000;
		}
		
		/* Update earliest wake time if this one is sooner */
		if (wake_sec < earliest_wakeup_sec ||
			(wake_sec == earliest_wakeup_sec && wake_nsec < earliest_wakeup_nsec)) {
			earliest_wakeup_sec = wake_sec;
			earliest_wakeup_nsec = wake_nsec;
		}
	}
	
	/* Calculate relative timeout if needed */
	if (need_wakeup) {
		/* Calculate timeout based on earliest_wakeup */
		timeout.tv_sec = earliest_wakeup_sec - now_monotonic.tv_sec;
		
		if (earliest_wakeup_nsec >= now_monotonic.tv_nsec) {
			timeout.tv_nsec = earliest_wakeup_nsec - now_monotonic.tv_nsec;
		} else {
			timeout.tv_sec--;
			timeout.tv_nsec = 1000000000 + earliest_wakeup_nsec - now_monotonic.tv_nsec;
		}
		
		/* Ensure sane values */
		if (timeout.tv_sec < 0) {
			timeout.tv_sec = 0;
			timeout.tv_nsec = 50000000; /* 50ms minimum */
		} else if (timeout.tv_sec == 0 && timeout.tv_nsec < 10000000) {
			timeout.tv_nsec = 50000000; /* 50ms minimum */
		}
		
		p_timeout = &timeout;
		log_message(LOG_LEVEL_DEBUG, "Next scheduled wakeup in %ld.%09ld seconds",
				  timeout.tv_sec, timeout.tv_nsec);
	} else {
		log_message(LOG_LEVEL_DEBUG, "No pending directory activity, waiting indefinitely");
		p_timeout = NULL;
	}

	/* Wait for events */
	nev = kevent(monitor->kq, NULL, 0, events, MAX_EVENTS, p_timeout);

	/* Get time after kevent returns */
	struct timespec after_kevent_time;
	clock_gettime(CLOCK_MONOTONIC, &after_kevent_time);

	/* Handle kevent result */
	if (nev == -1) {
		if (errno == EINTR) {
			log_message(LOG_LEVEL_DEBUG, "kevent interrupted by signal, continuing");
			return true; /* Continue monitoring */
		}
		log_message(LOG_LEVEL_ERR, "kevent error: %s", strerror(errno));
		return false; /* Stop monitoring on error */
	}

	/* Process new events */
	if (nev > 0) {
		log_message(LOG_LEVEL_DEBUG, "Processing %d new kqueue events", nev);
		for (int i = 0; i < nev; i++) {
			/* Find all watches that use this file descriptor */
			for (int j = 0; j < monitor->watch_count; j++) {
				watch_info_t *info = monitor->watches[j];
				
				if ((uintptr_t)info->wd == events[i].ident) {
					file_event_t event;
					memset(&event, 0, sizeof(event));
					event.path = info->path;
					event.type = flags_to_event_type(events[i].fflags);
					event.time = after_kevent_time;
					clock_gettime(CLOCK_REALTIME, &event.wall_time);
					event.user_id = getuid();
					
					entity_type_t entity_type = (info->watch->type == WATCH_FILE) ?
											   ENTITY_FILE : ENTITY_DIRECTORY;
					
					log_message(LOG_LEVEL_DEBUG, "Event: path=%s, flags=0x%x -> type=%s (watch: %s)",
							   info->path, events[i].fflags, event_type_to_string(event.type), info->watch->name);
					
					/* Process the event using the associated watch configuration */
					process_event(info->watch, &event, entity_type);
				}
			}
			
			/* Handle NOTE_DELETE / NOTE_REVOKE for watched descriptors */
			/* We need to find the first watch info for this FD to handle reopening */
			watch_info_t *primary_info = NULL;
			for (int j = 0; j < monitor->watch_count; j++) {
				if ((uintptr_t)monitor->watches[j]->wd == events[i].ident) {
					primary_info = monitor->watches[j];
					break;
				}
			}
			
			if (primary_info && (events[i].fflags & (NOTE_DELETE | NOTE_REVOKE))) {
				log_message(LOG_LEVEL_DEBUG, "DELETE/REVOKE detected for %s, re-opening", primary_info->path);
				close(primary_info->wd);
				
				int new_fd = open(primary_info->path, O_RDONLY);
				if (new_fd != -1) {
					/* Update all watch_info structures that share this FD */
					for (int j = 0; j < monitor->watch_count; j++) {
						if ((uintptr_t)monitor->watches[j]->wd == events[i].ident) {
							monitor->watches[j]->wd = new_fd;
						}
					}
					
					log_message(LOG_LEVEL_INFO, "Re-opened %s after DELETE/REVOKE (new descriptor: %d)", 
							 primary_info->path, new_fd);
							 
					if (!monitor_add_kqueue_watch(monitor, primary_info)) {
						log_message(LOG_LEVEL_WARNING, "Failed to re-add kqueue watch for %s", primary_info->path);
						/* Close and invalidate all related watch descriptors */
						close(new_fd);
						for (int j = 0; j < monitor->watch_count; j++) {
							if ((uintptr_t)monitor->watches[j]->wd == events[i].ident) {
								monitor->watches[j]->wd = -1;
							}
						}
					}
				} else {
					if (errno == ENOENT) {
						log_message(LOG_LEVEL_DEBUG, "Path %s no longer exists after DELETE/REVOKE", primary_info->path);
					} else {
						log_message(LOG_LEVEL_WARNING, "Failed to re-open %s: %s", 
								   primary_info->path, strerror(errno));
					}
					/* Invalidate all watch descriptors for this path */
					for (int j = 0; j < monitor->watch_count; j++) {
						if ((uintptr_t)monitor->watches[j]->wd == events[i].ident) {
							monitor->watches[j]->wd = -1;
						}
					}
				}
			}
		}
	} else {
		/* nev == 0 means timeout occurred */
		log_message(LOG_LEVEL_DEBUG, "Timeout occurred, checking deferred scans");
	}

	/* Check deferred scans */
	process_deferred_dir_scans(monitor, &after_kevent_time);

	return true; /* Continue monitoring */
}

/* Start the monitor and enter the main event loop */
bool monitor_start(monitor_t *monitor) {
	if (monitor == NULL) {
		log_message(LOG_LEVEL_ERR, "Invalid monitor");
		return false;
	}
	
	monitor->running = true;
	
	log_message(LOG_LEVEL_NOTICE, "Starting file monitor with %d watches", monitor->watch_count);
	
	/* Main event loop */
	while (monitor->running) {
		if (!monitor_process_events(monitor)) {
			log_message(LOG_LEVEL_ERR, "Error processing events, stopping monitor");
			return false;
		}
	}
	
	return true;
}

/* Stop the monitor by setting the running flag to false */
void monitor_stop(monitor_t *monitor) {
	if (monitor == NULL) {
		return;
	}
	
	monitor->running = false;
}
