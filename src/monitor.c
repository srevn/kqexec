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
#include "stability.h"
#include "command.h"
#include "states.h"
#include "logger.h"
#include "queue.h"
#include "events.h"
#include "scanner.h"

/* Maximum number of events to process at once */
#define MAX_EVENTS 64

/* Maximum path length */
#define MAX_PATH_LEN 1024

/* Define max allowed failures before giving up */
#define MAX_FAILED_CHECKS 3

/* Create a new file/directory monitor */
monitor_t *monitor_create(config_t *config) {
	monitor_t *monitor;

	if (config == NULL) {
		log_message(ERROR, "Invalid configuration for monitor");
		return NULL;
	}

	monitor = calloc(1, sizeof(monitor_t));
	if (monitor == NULL) {
		log_message(ERROR, "Failed to allocate memory for monitor");
		return NULL;
	}

	monitor->config = config;
	monitor->kq = -1;
	monitor->watches = NULL;
	monitor->watch_count = 0;
	monitor->running = false;
	monitor->reload_requested = false;

	/* Store config file path for reloading */
	if (config->config_file != NULL) {
		monitor->config_file = strdup(config->config_file);
	}

	/* Initialize the deferred check queue */
	monitor->check_queue = queue_create(16); /* Initial capacity of 16 */

	/* Initialize delayed event queue */
	monitor->delayed_events = NULL;
	monitor->delayed_event_count = 0;
	monitor->delayed_event_capacity = 0;

	return monitor;
}

/* Free resources used by a watch_info structure */
static void watch_destroy(watch_info_t *info) {
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
		watch_destroy(monitor->watches[i]);
	}

	free(monitor->watches);
	free(monitor->config_file);

	/* Clean up the check queue */
	queue_destroy(monitor->check_queue);

	/* Clean up delayed event queue */
	if (monitor->delayed_events) {
		for (int i = 0; i < monitor->delayed_event_count; i++) {
			free(monitor->delayed_events[i].event.path);
		}
		free(monitor->delayed_events);
	}

	/* Destroy the configuration */
	config_destroy(monitor->config);

	free(monitor);
}

/* Initialize inode and device information for a watch_info */
static bool watch_stat(watch_info_t *info) {
	struct stat st;
	if (fstat(info->wd, &st) == -1) {
		log_message(ERROR, "Failed to fstat file descriptor %d for %s: %s", info->wd, info->path, strerror(errno));
		return false;
	}

	info->inode = st.st_ino;
	info->device = st.st_dev;
	info->last_validation = time(NULL);
	return true;
}

/* Add a watch info to the monitor's array */
static bool watch_add(monitor_t *monitor, watch_info_t *info) {
	watch_info_t **new_watches;

	new_watches = realloc(monitor->watches, (monitor->watch_count + 1) * sizeof(watch_info_t *));
	if (new_watches == NULL) {
		log_message(ERROR, "Failed to allocate memory for watch info");
		return false;
	}

	monitor->watches = new_watches;
	monitor->watches[monitor->watch_count] = info;
	monitor->watch_count++;

	return true;
}

/* Find a watch info entry by path */
static watch_info_t *watch_find(monitor_t *monitor, const char *path) {
	for (int i = 0; i < monitor->watch_count; i++) {
		if (strcmp(monitor->watches[i]->path, path) == 0) {
			return monitor->watches[i];
		}
	}

	return NULL;
}

/* Set up kqueue monitoring for a file or directory */
static bool monitor_kqueue(monitor_t *monitor, watch_info_t *info) {
	struct kevent changes[1];
	int flags = 0;

	/* Set up flags based on consolidated events */
	if (info->watch->events & EVENT_STRUCTURE) {
		flags |= NOTE_WRITE | NOTE_EXTEND;
	}
	if (info->watch->events & EVENT_METADATA) {
		flags |= NOTE_ATTRIB | NOTE_LINK;
	}
	if (info->watch->events & EVENT_CONTENT) {
		flags |= NOTE_DELETE | NOTE_RENAME | NOTE_REVOKE;
	}

	/* Register for events */
	EV_SET(&changes[0], info->wd, EVFILT_VNODE, EV_ADD | EV_CLEAR, flags, 0, info);

	if (kevent(monitor->kq, changes, 1, NULL, 0, NULL) == -1) {
		log_message(ERROR, "Failed to register kqueue events for %s: %s", info->path, strerror(errno));
		return false;
	}

	return true;
}

/* Check if a path is a hidden file or directory (starts with dot) */
static bool path_hidden(const char *path) {
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
bool monitor_tree(monitor_t *monitor, const char *dir_path, watch_entry_t *watch) {
	DIR *dir;
	struct dirent *entry;

	/* Proactively validate the path to handle re-creations before adding watches */
	monitor_sync(monitor, dir_path);

	/* Skip hidden directories unless hidden is true */
	if (!watch->hidden && path_hidden(dir_path)) {
		log_message(DEBUG, "Skipping hidden directory: %s", dir_path);
		return true; /* Not an error, just skipping */
	}

	/* Check if a watch_info for this path and watch already exists */
	bool already_exists = false;
	for (int i = 0; i < monitor->watch_count; i++) {
		if (strcmp(monitor->watches[i]->path, dir_path) == 0 && monitor->watches[i]->watch == watch) {
			already_exists = true;
			break;
		}
	}

	if (!already_exists) {
		watch_info_t *existing_info = watch_find(monitor, dir_path);
		if (existing_info != NULL) {
			/* Reuse the existing file descriptor */
			int fd = existing_info->wd;
			watch_info_t *info = calloc(1, sizeof(watch_info_t));
			if (info == NULL) {
				log_message(ERROR, "Failed to allocate memory for watch info");
				return false;
			}

			info->wd = fd;
			info->path = strdup(dir_path);
			info->watch = watch;
			info->is_shared_fd = true;
			existing_info->is_shared_fd = true;

			if (!watch_stat(info)) {
				watch_destroy(info);
				return false;
			}

			if (!watch_add(monitor, info)) {
				watch_destroy(info);
				return false;
			}

			log_message(DEBUG, "Added additional watch for directory: %s (with shared FD)", dir_path);
		} else {
			/* Create a new watch with a new file descriptor */
			int fd = open(dir_path, O_RDONLY);
			if (fd == -1) {
				log_message(ERROR, "Failed to open %s: %s", dir_path, strerror(errno));
				return false;
			}

			watch_info_t *info = calloc(1, sizeof(watch_info_t));
			if (info == NULL) {
				log_message(ERROR, "Failed to allocate memory for watch info");
				close(fd);
				return false;
			}

			info->wd = fd;
			info->path = strdup(dir_path);
			info->watch = watch;
			info->is_shared_fd = false;

			if (!watch_stat(info)) {
				watch_destroy(info);
				close(fd);
				return false;
			}

			if (!watch_add(monitor, info)) {
				watch_destroy(info);
				close(fd);
				return false;
			}

			if (!monitor_kqueue(monitor, info)) {
				/* The watch_info is already in the monitor's list, so it will be cleaned up on monitor_destroy */
				return false;
			}
			log_message(DEBUG, "Added new watch for directory: %s", dir_path);
		}
	}

	dir = opendir(dir_path);
	if (dir == NULL) {
		log_message(ERROR, "Failed to open directory %s: %s", dir_path, strerror(errno));
		return false;
	}

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
				log_message(DEBUG, "Skipping hidden file/directory: %s/%s", dir_path, entry->d_name);
				continue;
			}

			snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);

			if (stat(path, &st) == -1) {
				log_message(WARNING, "Failed to stat %s: %s", path, strerror(errno));
				continue;
			}

			if (S_ISDIR(st.st_mode)) {
				/* Recursively add subdirectory */
				if (!monitor_tree(monitor, path, watch)) {
					log_message(WARNING, "Failed to add recursive watch for %s", path);
					/* Continue with other directories */
				}
			}
		}
	}

	closedir(dir);
	return true;
}

/* Add a watch for a file or directory based on a watch entry */
bool monitor_add(monitor_t *monitor, watch_entry_t *watch) {
	struct stat st;

	if (monitor == NULL || watch == NULL) {
		log_message(ERROR, "Invalid arguments to monitor_add_watch");
		return false;
	}

	/* Check if we already have a watch for this path, and reuse the file descriptor if we do */
	watch_info_t *existing_info = watch_find(monitor, watch->path);
	if (existing_info != NULL) {
		log_message(INFO, "Adding additional watch for %s (watch: %s)", watch->path, watch->name);

		/* Create a new watch_info that reuses the file descriptor */
		watch_info_t *info = calloc(1, sizeof(watch_info_t));
		if (info == NULL) {
			log_message(ERROR, "Failed to allocate memory for watch info");
			return false;
		}

		/* Reuse the existing file descriptor */
		info->wd = existing_info->wd;
		info->path = strdup(watch->path);
		info->watch = watch;
		info->is_shared_fd = true; /* Mark that this FD is shared */

		if (!watch_stat(info)) {
			watch_destroy(info);
			return false;
		}

		if (!watch_add(monitor, info)) {
			watch_destroy(info);
			return false;
		}

		/* Update the existing info to also mark it as shared */
		existing_info->is_shared_fd = true;

		/* For directories with recursive monitoring, we still need to discover subdirectories */
		if (watch->type == WATCH_DIRECTORY && watch->recursive) {
			struct stat st;
			if (stat(watch->path, &st) == 0 && S_ISDIR(st.st_mode)) {
				monitor_tree(monitor, watch->path, watch); /* true = skip existing main dir */
			}
		}

		/* No need to add kqueue watch again since we're using the same FD */
		return true;
	}

	/* Get file/directory stats */
	if (stat(watch->path, &st) == -1) {
		log_message(ERROR, "Failed to stat %s: %s", watch->path, strerror(errno));
		return false;
	}

	/* Handle directories (possibly recursively) */
	if (S_ISDIR(st.st_mode)) {
		if (watch->type != WATCH_DIRECTORY) {
			log_message(WARNING, "%s is a directory but configured as a file", watch->path);
			watch->type = WATCH_DIRECTORY;
		}

		return monitor_tree(monitor, watch->path, watch); /* false = don't skip existing */
	}
	/* Handle regular files */
	else if (S_ISREG(st.st_mode)) {
		if (watch->type != WATCH_FILE) {
			log_message(WARNING, "%s is a file but configured as a directory", watch->path);
			watch->type = WATCH_FILE;
		}

		int fd = open(watch->path, O_RDONLY);
		if (fd == -1) {
			log_message(ERROR, "Failed to open %s: %s", watch->path, strerror(errno));
			return false;
		}

		watch_info_t *info = calloc(1, sizeof(watch_info_t));
		if (info == NULL) {
			log_message(ERROR, "Failed to allocate memory for watch info");
			close(fd);
			return false;
		}

		info->wd = fd;
		info->path = strdup(watch->path);
		info->watch = watch;
		info->is_shared_fd = false; /* Initially not shared */

		if (!watch_stat(info)) {
			watch_destroy(info);
			close(fd);
			return false;
		}

		if (!watch_add(monitor, info)) {
			watch_destroy(info);
			return false;
		}

		return monitor_kqueue(monitor, info);
	}
	/* Unsupported file type */
	else {
		log_message(ERROR, "Unsupported file type for %s", watch->path);
		return false;
	}
}

/* Create a watch entry for the configuration file */
static watch_entry_t *config_entry(const char *config_file_path) {
	if (!config_file_path) return NULL;

	watch_entry_t *config_watch = calloc(1, sizeof(watch_entry_t));
	if (config_watch == NULL) {
		log_message(ERROR, "Failed to allocate memory for config file watch");
		return NULL;
	}

	config_watch->name = strdup("__config_file__");
	config_watch->path = strdup(config_file_path);
	config_watch->type = WATCH_FILE;
	config_watch->events = EVENT_CONTENT;
	config_watch->command = strdup("__config_reload__");
	config_watch->log_output = false;
	config_watch->buffer_output = false;
	config_watch->recursive = false;
	config_watch->hidden = false;
	config_watch->complexity = 1.0;
	config_watch->processing_delay = 0;

	/* Check for strdup failures, which can return NULL on error */
	if (!config_watch->name || !config_watch->path || !config_watch->command) {
		log_message(ERROR, "Failed to allocate strings for config watch");
		free(config_watch->name);
		free(config_watch->path);
		free(config_watch->command);
		free(config_watch);
		return NULL;
	}

	return config_watch;
}

/* Set up the monitor by creating kqueue and adding watches */
bool monitor_setup(monitor_t *monitor) {
	if (monitor == NULL) {
		log_message(ERROR, "Invalid monitor");
		return false;
	}

	/* Create kqueue */
	monitor->kq = kqueue();
	if (monitor->kq == -1) {
		log_message(ERROR, "Failed to create kqueue: %s", strerror(errno));
		return false;
	}

	/* Add watches for each entry in the configuration */
	for (int i = 0; i < monitor->config->watch_count; i++) {
		if (!monitor_add(monitor, monitor->config->watches[i])) {
			log_message(WARNING, "Failed to add watch for %s, skipping", monitor->config->watches[i]->path);
		}
	}

	/* Check if we have at least one active watch */
	if (monitor->watch_count == 0) {
		log_message(ERROR, "No valid watches could be set up, aborting");
		return false;
	}

	/* Add config file watch for hot reload by adding it to the config structure */
	if (monitor->config_file != NULL) {
		watch_entry_t *config_watch = config_entry(monitor->config_file);
		if (config_watch) {
			/* Add to config structure so it gets managed properly */
			watch_entry_t **new_watches = realloc(monitor->config->watches, (monitor->config->watch_count + 1) * sizeof(watch_entry_t *));
			if (new_watches == NULL) {
				log_message(WARNING, "Failed to add config watch to config structure");
				free(config_watch->name);
				free(config_watch->path);
				free(config_watch->command);
				free(config_watch);
			} else {
				monitor->config->watches = new_watches;
				monitor->config->watches[monitor->config->watch_count] = config_watch;
				monitor->config->watch_count++;

				if (!monitor_add(monitor, config_watch)) {
					log_message(WARNING, "Failed to add config file watch for %s", monitor->config_file);
					/* Remove from config since it wasn't added to monitor */
					monitor->config->watch_count--;
				} else {
					log_message(DEBUG, "Added config file watch for %s", monitor->config_file);
				}
			}
		}
	}

	return true;
}

/* Process events from kqueue and handle commands */
bool monitor_poll(monitor_t *monitor) {
	struct kevent events[MAX_EVENTS];
	int nev;
	struct timespec timeout, *p_timeout;

	/* Check for reload request */
	if (monitor->reload_requested) {
		monitor->reload_requested = false;
		if (!monitor_reload(monitor)) {
			log_message(ERROR, "Failed to reload configuration, continuing with existing config");
		}
	}

	if (!monitor || monitor->kq < 0) {
		log_message(ERROR, "Invalid monitor state");
		return false;
	}

	/* Calculate timeout based on pending deferred scans and delayed events */
	struct timespec now_monotonic;
	clock_gettime(CLOCK_MONOTONIC, &now_monotonic);
	
	p_timeout = timeout_calculate(monitor, &timeout, &now_monotonic);

	/* Wait for events */
	nev = kevent(monitor->kq, NULL, 0, events, MAX_EVENTS, p_timeout);

	/* Get time after kevent returns */
	struct timespec after_kevent_time;
	clock_gettime(CLOCK_MONOTONIC, &after_kevent_time);

	/* Handle kevent result */
	if (nev == -1) {
		if (errno == EINTR) {
			log_message(DEBUG, "kevent interrupted by signal, returning to main loop");
			return true; /* Return to main loop where running flag will be checked */
		}
		log_message(ERROR, "kevent error: %s", strerror(errno));
		return false; /* Stop monitoring on error */
	}

	/* Process new events */
	if (nev > 0) {
		log_message(DEBUG, "Processing %d new kqueue events", nev);
		events_handle(monitor, events, nev, &after_kevent_time);
	} else {
		/* nev == 0 means timeout occurred */
		if (p_timeout) {
			log_message(DEBUG, "Timeout occurred after %ld.%09ld seconds, checking deferred scans",
			            		p_timeout->tv_sec, p_timeout->tv_nsec);
		} else {
			log_message(DEBUG, "Timeout occurred, checking deferred scans");
		}
	}

	/* Check deferred scans */
	stability_process(monitor, &after_kevent_time);

	/* Process delayed events */
	events_process(monitor);

	/* Clean up expired command intents */
	command_intent_expire();

	return true; /* Continue monitoring */
}

/* Start the monitor and enter the main event loop */
bool monitor_start(monitor_t *monitor) {
	if (monitor == NULL) {
		log_message(ERROR, "Invalid monitor");
		return false;
	}

	monitor->running = true;

	log_message(NOTICE, "Starting file monitor with %d watches", monitor->watch_count);

	/* Main event loop */
	while (monitor->running) {
		if (!monitor_poll(monitor)) {
			log_message(ERROR, "Error processing events, stopping monitor");
			return false;
		}
	}

	return true;
}

/* Process a reload request */
bool monitor_reload(monitor_t *monitor) {
	if (monitor == NULL || monitor->config_file == NULL) {
		log_message(ERROR, "Invalid monitor or missing configuration file for reload");
		return false;
	}

	log_message(INFO, "Reloading configuration from %s", monitor->config_file);
	log_message(DEBUG, "Current configuration has %d watches", monitor->watch_count);

	/* Save existing config to compare later */
	config_t *old_config = monitor->config;

	/* Create new configuration */
	config_t *new_config = config_create();
	if (!new_config) {
		log_message(ERROR, "Failed to create new configuration during reload");
		return false;
	}

	/* Copy daemon mode and log level from existing config */
	new_config->daemon_mode = old_config->daemon_mode;
	new_config->syslog_level = old_config->syslog_level;

	/* Parse configuration file */
	if (!config_parse_file(new_config, monitor->config_file)) {
		log_message(ERROR, "Failed to parse new config, keeping old one: %s", monitor->config_file);
		config_destroy(new_config);
		/* Re-validate the watch on the config file to detect subsequent changes */
		monitor_sync(monitor, monitor->config_file);
		return false;
	}

	/* Add config file watch to the new config so it gets re-added */
	if (monitor->config_file != NULL) {
		watch_entry_t *config_watch = config_entry(monitor->config_file);
		if (config_watch) {
			watch_entry_t **new_watches_in_config = realloc(new_config->watches, (new_config->watch_count + 1) * sizeof(watch_entry_t *));
			if (new_watches_in_config == NULL) {
				log_message(WARNING, "Failed to add config watch to new config structure");
				free(config_watch->name);
				free(config_watch->path);
				free(config_watch->command);
				free(config_watch);
			} else {
				new_config->watches = new_watches_in_config;
				new_config->watches[new_config->watch_count] = config_watch;
				new_config->watch_count++;
			}
		}
	}

	/* Clear deferred and delayed queues to prevent access to old states */
	queue_destroy(monitor->check_queue);
	monitor->check_queue = queue_create(16);

	/* Also clear delayed events queue that may reference old watches */
	if (monitor->delayed_events) {
		for (int i = 0; i < monitor->delayed_event_count; i++) {
			free(monitor->delayed_events[i].event.path);
		}
		free(monitor->delayed_events);
		monitor->delayed_events = NULL;
		monitor->delayed_event_count = 0;
		log_message(DEBUG, "Cleared %d delayed events during config reload", monitor->delayed_event_count);
		monitor->delayed_event_capacity = 0;
	}

	/* Update entity states to point to new watch entries */
	states_update(new_config);

	/* Clean up states that are no longer associated with any new watch */
	states_prune(new_config);

	/* Save old watches to be destroyed later */
	watch_info_t **old_watches_list = monitor->watches;
	int old_watch_count = monitor->watch_count;

	/* Reset monitor's watch list to be populated with new watches */
	monitor->watches = NULL;
	monitor->watch_count = 0;

	/* Add watches from the new configuration (including the config file watch) */
	for (int i = 0; i < new_config->watch_count; i++) {
		if (!monitor_add(monitor, new_config->watches[i])) {
			log_message(WARNING, "Failed to add watch for %s", new_config->watches[i]->path);
		}
	}

	/* Destroy the old watches */
	for (int i = 0; i < old_watch_count; i++) {
		watch_destroy(old_watches_list[i]);
	}
	free(old_watches_list);

	/* Replace old config with new one */
	config_destroy(old_config);
	monitor->config = new_config;

	/* After reloading, explicitly validate the config file watch to handle editor atomic saves */
	monitor_sync(monitor, monitor->config_file);

	log_message(INFO, "Configuration reload complete: %d active watches", monitor->watch_count);
	return true;
}

/* Remove all watches for subdirectories of a given parent path */
bool monitor_prune(monitor_t *monitor, const char *parent_path) {
	if (!monitor || !parent_path) {
		return false;
	}

	int parent_len = strlen(parent_path);
	bool changed = false;

	for (int i = monitor->watch_count - 1; i >= 0; i--) {
		watch_info_t *info = monitor->watches[i];
		if (!info || !info->path) continue;

		/* Check if it's a subdirectory */
		if ((int) strlen(info->path) > parent_len &&
		    strncmp(info->path, parent_path, parent_len) == 0 &&
		    info->path[parent_len] == '/') {
			log_message(DEBUG, "Removing stale subdirectory watch: %s", info->path);

			/* Destroy the watch info (closes FD if not shared) */
			watch_destroy(info);

			/* Remove from array by shifting */
			for (int j = i; j < monitor->watch_count - 1; j++) {
				monitor->watches[j] = monitor->watches[j + 1];
			}
			monitor->watch_count--;
			changed = true;
		}
	}

	return changed;
}

/* Validate a path and refresh it if it has been recreated */
bool monitor_sync(monitor_t *monitor, const char *path) {
	if (!monitor || !path) {
		return false;
	}

	struct stat st;
	bool path_exists = (stat(path, &st) == 0);
	bool list_modified = false;

	/* Find all watch_info entries for this exact path */
	for (int i = 0; i < monitor->watch_count; i++) {
		watch_info_t *info = monitor->watches[i];
		if (info && info->path && strcmp(info->path, path) == 0) {
			if (!path_exists) {
				/* Path does not exist - it was deleted */
				log_message(DEBUG, "Path deleted: %s. Removing watch.", path);

				/* If it was a recursive directory, remove all subdirectory watches */
				if (info->watch->type == WATCH_DIRECTORY && info->watch->recursive) {
					monitor_prune(monitor, path);
				}

				/* Remove this watch */
				watch_destroy(info);
				for (int j = i; j < monitor->watch_count - 1; j++) {
					monitor->watches[j] = monitor->watches[j + 1];
				}
				monitor->watch_count--;
				i--; /* Adjust index after removal */
				list_modified = true;

			} else if (info->inode != st.st_ino || info->device != st.st_dev) {
				/* Path exists but inode/device changed - it was recreated */
				log_message(DEBUG, "Path recreated: %s. Refreshing watch.", path);

				/* Close old file descriptor if not shared */
				if (!info->is_shared_fd && info->wd >= 0) {
					close(info->wd);
				}

				/* Open new file descriptor */
				int new_fd = open(path, O_RDONLY);
				if (new_fd == -1) {
					log_message(ERROR, "Failed to open recreated path %s: %s", path, strerror(errno));
					/* Treat as deleted for now */
					watch_destroy(info);
					for (int j = i; j < monitor->watch_count - 1; j++) {
						monitor->watches[j] = monitor->watches[j + 1];
					}
					monitor->watch_count--;
					i--;
					list_modified = true;
					continue;
				}

				info->wd = new_fd;
				info->inode = st.st_ino;
				info->device = st.st_dev;
				info->is_shared_fd = false; /* It's a new FD */

				/* Re-register with kqueue */
				monitor_kqueue(monitor, info);

				/* If it was a recursive directory, rescan subdirectories */
				if (info->watch->type == WATCH_DIRECTORY && info->watch->recursive) {
					log_message(DEBUG, "Re-scanning subdirectories for recreated path: %s", path);
					monitor_prune(monitor, path);
					monitor_tree(monitor, path, info->watch);
				}
				list_modified = true;

			} else {
				/* Path is valid and unchanged */
				info->last_validation = time(NULL);
			}
		}
	}

	return list_modified;
}

/* Stop the monitor by setting the running flag to false */
void monitor_stop(monitor_t *monitor) {
	if (monitor == NULL) {
		return;
	}

	monitor->running = false;
}
