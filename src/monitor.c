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

/* Free resources used by a watcher structure */
static void watcher_destroy(monitor_t *monitor, watcher_t *watcher) {
	if (watcher == NULL) {
		return;
	}

	/* Close the file descriptor if this is the last watcher using it */
	if (watcher->wd >= 0) {
		bool should_close = !watcher->shared_fd;
		
		if (watcher->shared_fd && monitor) {
			/* Count other watchers using this FD */
			int fd_users = 0;
			for (int i = 0; i < monitor->num_watches; i++) {
				watcher_t *other = monitor->watches[i];
				if (other && other != watcher && other->wd == watcher->wd) {
					fd_users++;
				}
			}
			should_close = (fd_users == 0);
		}
		
		if (should_close) {
			close(watcher->wd);
		}
	}

	free(watcher->path);
	free(watcher);
}

/* Initialize inode and device information for a watcher */
static bool watcher_stat(watcher_t *watcher) {
	struct stat info;
	if (fstat(watcher->wd, &info) == -1) {
		log_message(ERROR, "Failed to fstat file descriptor %d for %s: %s", watcher->wd, watcher->path, strerror(errno));
		return false;
	}

	watcher->inode = info.st_ino;
	watcher->device = info.st_dev;
	watcher->validated = time(NULL);
	return true;
}

/* Add a watcher to the monitor's array */
static bool watcher_add(monitor_t *monitor, watcher_t *watcher) {
	watcher_t **new_watches;

	new_watches = realloc(monitor->watches, (monitor->num_watches + 1) * sizeof(watcher_t *));
	if (new_watches == NULL) {
		log_message(ERROR, "Failed to allocate memory for watcher");
		return false;
	}

	monitor->watches = new_watches;
	monitor->watches[monitor->num_watches] = watcher;
	monitor->num_watches++;

	return true;
}

/* Find a watcher entry by path */
static watcher_t *watcher_find(monitor_t *monitor, const char *path) {
	for (int i = 0; i < monitor->num_watches; i++) {
		if (strcmp(monitor->watches[i]->path, path) == 0) {
			return monitor->watches[i];
		}
	}

	return NULL;
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
	monitor->num_watches = 0;
	monitor->running = false;
	monitor->reload = false;

	/* Store config file path for reloading */
	if (config->config_path != NULL) {
		monitor->config_path = strdup(config->config_path);
	}

	/* Initialize the deferred check queue */
	monitor->check_queue = queue_create(16); /* Initial capacity of 16 */

	/* Initialize state table */
	monitor->states = state_create(PATH_HASH_SIZE);
	if (!monitor->states) {
		log_message(ERROR, "Failed to create state table for monitor");
		queue_destroy(monitor->check_queue);
		free(monitor->config_path);
		free(monitor);
		return NULL;
	}

	/* Initialize delayed event queue */
	monitor->delayed_events = NULL;
	monitor->delayed_count = 0;
	monitor->delayed_capacity = 0;

	return monitor;
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
	for (int i = 0; i < monitor->num_watches; i++) {
		watcher_destroy(monitor, monitor->watches[i]);
	}

	free(monitor->watches);
	free(monitor->config_path);

	/* Clean up the check queue */
	queue_destroy(monitor->check_queue);

	/* Clean up delayed event queue */
	if (monitor->delayed_events) {
		for (int i = 0; i < monitor->delayed_count; i++) {
			free(monitor->delayed_events[i].event.path);
		}
		free(monitor->delayed_events);
	}

	/* Clean up state table */
	state_destroy(monitor->states);

	/* Destroy the configuration */
	config_destroy(monitor->config);

	free(monitor);
}

/* Set up kqueue monitoring for a file or directory */
static bool monitor_kq(monitor_t *monitor, watcher_t *watcher) {
	struct kevent changes[1];
	int flags = 0;

	/* Set up flags based on consolidated events */
	if (watcher->watch->filter & EVENT_STRUCTURE) {
		flags |= NOTE_WRITE | NOTE_EXTEND;
	}
	if (watcher->watch->filter & EVENT_METADATA) {
		flags |= NOTE_ATTRIB | NOTE_LINK;
	}
	if (watcher->watch->filter & EVENT_CONTENT) {
		flags |= NOTE_DELETE | NOTE_RENAME | NOTE_REVOKE | NOTE_WRITE;
	}

	/* Register for events */
	EV_SET(&changes[0], watcher->wd, EVFILT_VNODE, EV_ADD | EV_CLEAR, flags, 0, watcher);

	if (kevent(monitor->kq, changes, 1, NULL, 0, NULL) == -1) {
		log_message(ERROR, "Failed to register kqueue events for %s: %s", watcher->path, strerror(errno));
		return false;
	}

	return true;
}

/* Recursively add watches for a directory and its subdirectories */
bool monitor_tree(monitor_t *monitor, const char *dir_path, watch_t *watch) {
	DIR *dir;
	struct dirent *dirent;

	/* Proactively validate the path to handle re-creations before adding watches */
	monitor_sync(monitor, dir_path);

	/* Skip hidden directories unless hidden is true */
	if (!watch->hidden && path_hidden(dir_path)) {
		log_message(DEBUG, "Skipping hidden directory: %s", dir_path);
		return true; /* Not an error, just skipping */
	}

	/* Check if a watcher for this path and watch already exists */
	bool already_exists = false;
	for (int i = 0; i < monitor->num_watches; i++) {
		if (strcmp(monitor->watches[i]->path, dir_path) == 0 && monitor->watches[i]->watch == watch) {
			already_exists = true;
			break;
		}
	}

	if (!already_exists) {
		watcher_t *existing_watcher = watcher_find(monitor, dir_path);
		if (existing_watcher != NULL) {
			/* Reuse the existing file descriptor */
			int fd = existing_watcher->wd;
			watcher_t *watcher = calloc(1, sizeof(watcher_t));
			if (watcher == NULL) {
				log_message(ERROR, "Failed to allocate memory for watcher");
				return false;
			}

			watcher->wd = fd;
			watcher->path = strdup(dir_path);
			watcher->watch = watch;
			watcher->shared_fd = true;
			existing_watcher->shared_fd = true;

			if (!watcher_stat(watcher)) {
				watcher_destroy(monitor, watcher);
				return false;
			}

			if (!watcher_add(monitor, watcher)) {
				watcher_destroy(monitor, watcher);
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

			watcher_t *watcher = calloc(1, sizeof(watcher_t));
			if (watcher == NULL) {
				log_message(ERROR, "Failed to allocate memory for watcher");
				close(fd);
				return false;
			}

			watcher->wd = fd;
			watcher->path = strdup(dir_path);
			watcher->watch = watch;
			watcher->shared_fd = false;

			if (!watcher_stat(watcher)) {
				watcher_destroy(monitor, watcher);
				close(fd);
				return false;
			}

			if (!watcher_add(monitor, watcher)) {
				watcher_destroy(monitor, watcher);
				close(fd);
				return false;
			}

			if (!monitor_kq(monitor, watcher)) {
				return false;
			}
			log_message(DEBUG, "Added new watch for directory: %s", dir_path);

			/* Establish baseline state */
			state_get(monitor->states, dir_path, ENTITY_DIRECTORY, watch);
		}
	}

	dir = opendir(dir_path);
	if (dir == NULL) {
		log_message(ERROR, "Failed to open directory %s: %s", dir_path, strerror(errno));
		return false;
	}

	if (watch->recursive) {
		while ((dirent = readdir(dir)) != NULL) {
			char path[MAX_PATH_LEN];
			struct stat info;

			/* Skip . and .. */
			if (strcmp(dirent->d_name, ".") == 0 || strcmp(dirent->d_name, "..") == 0) {
				continue;
			}

			/* Skip hidden files/directories unless hidden is true */
			if (!watch->hidden && dirent->d_name[0] == '.') {
				log_message(DEBUG, "Skipping hidden file/directory: %s/%s", dir_path, dirent->d_name);
				continue;
			}

			snprintf(path, sizeof(path), "%s/%s", dir_path, dirent->d_name);

			if (stat(path, &info) == -1) {
				log_message(WARNING, "Failed to stat %s: %s", path, strerror(errno));
				continue;
			}

			if (S_ISDIR(info.st_mode)) {
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
bool monitor_add(monitor_t *monitor, watch_t *watch) {
	struct stat info;

	if (monitor == NULL || watch == NULL) {
		log_message(ERROR, "Invalid arguments to monitor_add_watch");
		return false;
	}

	/* Check if we already have a watch for this path, and reuse the file descriptor if we do */
	watcher_t *existing_watcher = watcher_find(monitor, watch->path);
	if (existing_watcher != NULL) {
		log_message(INFO, "Adding additional watch for %s (watch: %s)", watch->path, watch->name);

		/* Create a new watcher that reuses the file descriptor */
		watcher_t *watcher = calloc(1, sizeof(watcher_t));
		if (watcher == NULL) {
			log_message(ERROR, "Failed to allocate memory for watcher");
			return false;
		}

		/* Reuse the existing file descriptor */
		watcher->wd = existing_watcher->wd;
		watcher->path = strdup(watch->path);
		watcher->watch = watch;
		watcher->shared_fd = true; /* Mark that this FD is shared */

		if (!watcher_stat(watcher)) {
			watcher_destroy(monitor, watcher);
			return false;
		}

		if (!watcher_add(monitor, watcher)) {
			watcher_destroy(monitor, watcher);
			return false;
		}

		/* Update the existing watcher to also mark it as shared */
		existing_watcher->shared_fd = true;

		/* For directories with recursive monitoring, we still need to discover subdirectories */
		if (watch->target == WATCH_DIRECTORY && watch->recursive) {
			struct stat info;
			if (stat(watch->path, &info) == 0 && S_ISDIR(info.st_mode)) {
				monitor_tree(monitor, watch->path, watch); /* true = skip existing main dir */
			}
		}

		/* No need to add kqueue watch again since we're using the same FD */
		return true;
	}

	/* Get file/directory stats */
	if (stat(watch->path, &info) == -1) {
		log_message(ERROR, "Failed to stat %s: %s", watch->path, strerror(errno));
		return false;
	}

	/* Handle directories (possibly recursively) */
	if (S_ISDIR(info.st_mode)) {
		if (watch->target != WATCH_DIRECTORY) {
			log_message(WARNING, "%s is a directory but configured as a file", watch->path);
			watch->target = WATCH_DIRECTORY;
		}

		return monitor_tree(monitor, watch->path, watch); /* false = don't skip existing */
	}
	/* Handle regular files */
	else if (S_ISREG(info.st_mode)) {
		if (watch->target != WATCH_FILE) {
			log_message(WARNING, "%s is a file but configured as a directory", watch->path);
			watch->target = WATCH_FILE;
		}

		int fd = open(watch->path, O_RDONLY);
		if (fd == -1) {
			log_message(ERROR, "Failed to open %s: %s", watch->path, strerror(errno));
			return false;
		}

		watcher_t *watcher = calloc(1, sizeof(watcher_t));
		if (watcher == NULL) {
			log_message(ERROR, "Failed to allocate memory for watcher");
			close(fd);
			return false;
		}

		watcher->wd = fd;
		watcher->path = strdup(watch->path);
		watcher->watch = watch;
		watcher->shared_fd = false; /* Initially not shared */

		if (!watcher_stat(watcher)) {
			watcher_destroy(monitor, watcher);
			close(fd);
			return false;
		}

		if (!watcher_add(monitor, watcher)) {
			watcher_destroy(monitor, watcher);
			return false;
		}

		/* Establish baseline state */
		state_get(monitor->states, watcher->path, ENTITY_FILE, watch);

		return monitor_kq(monitor, watcher);
	}
	/* Unsupported file type */
	else {
		log_message(ERROR, "Unsupported file type for %s", watch->path);
		return false;
	}
}

/* Create a watch entry for the configuration file */
static watch_t *monitor_config(const char *config_file_path) {
	if (!config_file_path) return NULL;

	watch_t *config_watch = calloc(1, sizeof(watch_t));
	if (config_watch == NULL) {
		log_message(ERROR, "Failed to allocate memory for config file watch");
		return NULL;
	}

	config_watch->name = strdup("__config_file__");
	config_watch->path = strdup(config_file_path);
	config_watch->target = WATCH_FILE;
	config_watch->filter = EVENT_CONTENT;
	config_watch->command = strdup("__config_reload__");
	config_watch->log_output = false;
	config_watch->buffer_output = false;
	config_watch->recursive = false;
	config_watch->hidden = false;
	config_watch->environment = false;
	config_watch->complexity = 1.0;
	config_watch->processing_delay = 100;

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
	for (int i = 0; i < monitor->config->num_watches; i++) {
		if (!monitor_add(monitor, monitor->config->watches[i])) {
			log_message(WARNING, "Failed to add watch for %s, skipping", monitor->config->watches[i]->path);
		}
	}

	/* Check if we have at least one active watch */
	if (monitor->num_watches == 0) {
		log_message(ERROR, "No valid watches could be set up, aborting");
		return false;
	}

	/* Add config file watch for hot reload by adding it to the config structure */
	if (monitor->config_path != NULL) {
		watch_t *config_watch = monitor_config(monitor->config_path);
		if (config_watch) {
			/* Add to config structure so it gets managed properly */
			watch_t **new_watches = realloc(monitor->config->watches, (monitor->config->num_watches + 1) * sizeof(watch_t *));
			if (new_watches == NULL) {
				log_message(WARNING, "Failed to add config watch to config structure");
				free(config_watch->name);
				free(config_watch->path);
				free(config_watch->command);
				free(config_watch);
			} else {
				monitor->config->watches = new_watches;
				monitor->config->watches[monitor->config->num_watches] = config_watch;
				monitor->config->num_watches++;

				if (!monitor_add(monitor, config_watch)) {
					log_message(WARNING, "Failed to add config file watch for %s", monitor->config_path);
					/* Remove from config since it wasn't added to monitor */
					monitor->config->num_watches--;
				} else {
					log_message(DEBUG, "Added config file watch for %s", monitor->config_path);
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
	if (monitor->reload) {
		monitor->reload = false;
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
		
		/* Initialize sync request for collecting paths that need validation */
		sync_t sync;
		events_sync_init(&sync);
		
		/* Process events and collect sync requests */
		events_handle(monitor, events, nev, &after_kevent_time, &sync);
		
		/* Handle any sync requests */
		if (sync.paths_count > 0) {
			for (int i = 0; i < sync.paths_count; i++) {
				log_message(DEBUG, "Validating watch for path: %s", sync.paths[i]);
				monitor_sync(monitor, sync.paths[i]);
			}
		}
		
		/* Clean up sync request */
		events_sync_cleanup(&sync);
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
	events_delayed(monitor);

	/* Clean up expired command intents */
	intent_expire();

	return true; /* Continue monitoring */
}

/* Start the monitor and enter the main event loop */
bool monitor_start(monitor_t *monitor) {
	if (monitor == NULL) {
		log_message(ERROR, "Invalid monitor");
		return false;
	}

	monitor->running = true;

	log_message(NOTICE, "Starting file monitor with %d watches", monitor->num_watches);

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
	if (monitor == NULL || monitor->config_path == NULL) {
		log_message(ERROR, "Invalid monitor or missing configuration file for reload");
		return false;
	}

	log_message(INFO, "Reloading configuration from %s", monitor->config_path);
	log_message(DEBUG, "Current configuration has %d watches", monitor->num_watches);

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
	if (!config_parse(new_config, monitor->config_path)) {
		log_message(ERROR, "Failed to parse new config, keeping old one: %s", monitor->config_path);
		config_destroy(new_config);
		/* Re-validate the watch on the config file to detect subsequent changes */
		monitor_sync(monitor, monitor->config_path);
		return false;
	}

	/* Add config file watch to the new config so it gets re-added */
	if (monitor->config_path != NULL) {
		watch_t *config_watch = monitor_config(monitor->config_path);
		if (config_watch) {
			watch_t **new_entries = realloc(new_config->watches, (new_config->num_watches + 1) * sizeof(watch_t *));
			if (new_entries == NULL) {
				log_message(WARNING, "Failed to add config watch to new config structure");
				free(config_watch->name);
				free(config_watch->path);
				free(config_watch->command);
				free(config_watch);
			} else {
				new_config->watches = new_entries;
				new_config->watches[new_config->num_watches] = config_watch;
				new_config->num_watches++;
			}
		}
	}

	/* Reset the state management system */
	state_destroy(monitor->states);
	monitor->states = state_create(PATH_HASH_SIZE);
	if (!monitor->states) {
		log_message(ERROR, "Failed to recreate state table during reload");
		return false;
	}

	/* Clear deferred and delayed queues to prevent access to old states */
	queue_destroy(monitor->check_queue);
	monitor->check_queue = queue_create(16);

	/* Also clear delayed events queue that may reference old watches */
	if (monitor->delayed_events) {
		for (int i = 0; i < monitor->delayed_count; i++) {
			free(monitor->delayed_events[i].event.path);
		}
		free(monitor->delayed_events);
		monitor->delayed_events = NULL;
		monitor->delayed_count = 0;
		log_message(DEBUG, "Cleared %d delayed events during config reload", monitor->delayed_count);
		monitor->delayed_capacity = 0;
	}

	/* Save old watches to be destroyed later */
	watcher_t **stale_watches = monitor->watches;
	int stale_count = monitor->num_watches;

	/* Reset monitor's watch list to be populated with new watches */
	monitor->watches = NULL;
	monitor->num_watches = 0;

	/* Add watches from the new configuration (including the config file watch) */
	for (int i = 0; i < new_config->num_watches; i++) {
		if (!monitor_add(monitor, new_config->watches[i])) {
			log_message(WARNING, "Failed to add watch for %s", new_config->watches[i]->path);
		}
	}

	/* Destroy the old watches */
	for (int i = 0; i < stale_count; i++) {
		watcher_destroy(monitor, stale_watches[i]);
	}
	free(stale_watches);

	/* Replace old config with new one */
	config_destroy(old_config);
	monitor->config = new_config;

	/* After reloading, explicitly validate the config file watch to handle editor atomic saves */
	monitor_sync(monitor, monitor->config_path);

	log_message(INFO, "Configuration reload complete: %d active watches", monitor->num_watches);
	return true;
}

/* Remove all watches for subdirectories of a given parent path */
bool monitor_prune(monitor_t *monitor, const char *parent) {
	if (!monitor || !parent) {
		return false;
	}

	int parent_len = strlen(parent);
	bool changed = false;

	for (int i = monitor->num_watches - 1; i >= 0; i--) {
		watcher_t *watcher = monitor->watches[i];
		if (!watcher || !watcher->path) continue;

		/* Check if it's a subdirectory */
		if ((int) strlen(watcher->path) > parent_len &&
		    strncmp(watcher->path, parent, parent_len) == 0 &&
		    watcher->path[parent_len] == '/') {
			log_message(DEBUG, "Removing stale subdirectory watch: %s", watcher->path);

			/* Destroy the watcher (closes FD if not shared) */
			watcher_destroy(monitor, watcher);

			/* Remove from array by shifting */
			for (int j = i; j < monitor->num_watches - 1; j++) {
				monitor->watches[j] = monitor->watches[j + 1];
			}
			monitor->num_watches--;
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

	struct stat info;
	bool path_exists = (stat(path, &info) == 0);
	bool list_modified = false;

	/* Find all watcher entries for this exact path */
	for (int i = 0; i < monitor->num_watches; i++) {
		watcher_t *watcher = monitor->watches[i];
		if (watcher && watcher->path && strcmp(watcher->path, path) == 0) {
			if (!path_exists) {
				/* Path does not exist - it was deleted */
				log_message(DEBUG, "Path deleted: %s. Removing watch.", path);

				/* If it was a recursive directory, remove all subdirectory watches */
				if (watcher->watch->target == WATCH_DIRECTORY && watcher->watch->recursive) {
					monitor_prune(monitor, path);
				}

				/* Remove this watch */
				watcher_destroy(monitor, watcher);
				for (int j = i; j < monitor->num_watches - 1; j++) {
					monitor->watches[j] = monitor->watches[j + 1];
				}
				monitor->num_watches--;
				i--; /* Adjust index after removal */
				list_modified = true;

			} else if (watcher->inode != info.st_ino || watcher->device != info.st_dev) {
				/* Path exists but inode/device changed - it was recreated */
				log_message(DEBUG, "Path recreated: %s. Refreshing watch.", path);

				/* Close old file descriptor if not shared */
				if (!watcher->shared_fd && watcher->wd >= 0) {
					close(watcher->wd);
				}

				/* Open new file descriptor */
				int new_fd = open(path, O_RDONLY);
				if (new_fd == -1) {
					log_message(ERROR, "Failed to open recreated path %s: %s", path, strerror(errno));
					/* Treat as deleted for current_time */
					watcher_destroy(monitor, watcher);
					for (int j = i; j < monitor->num_watches - 1; j++) {
						monitor->watches[j] = monitor->watches[j + 1];
					}
					monitor->num_watches--;
					i--;
					list_modified = true;
					continue;
				}

				watcher->wd = new_fd;
				watcher->inode = info.st_ino;
				watcher->device = info.st_dev;
				watcher->shared_fd = false; /* It's a new FD */

				/* Re-register with kqueue */
				monitor_kq(monitor, watcher);

				/* If it was a recursive directory, rescan subdirectories */
				if (watcher->watch->target == WATCH_DIRECTORY && watcher->watch->recursive) {
					log_message(DEBUG, "Re-scanning subdirectories for recreated path: %s", path);
					monitor_prune(monitor, path);
					monitor_tree(monitor, path, watcher->watch);
				}
				list_modified = true;

			} else {
				/* Path is valid and unchanged */
				watcher->validated = time(NULL);
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
