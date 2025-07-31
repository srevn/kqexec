#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <fnmatch.h>
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
#include "pending.h"

/* Observer callback for watch deactivation */
static void monitor_on_pending_watch_deactivated(watchref_t ref, void *context) {
	monitor_t *monitor = (monitor_t *)context;
	if (!monitor || !monitor->pending) {
		return;
	}
	
	log_message(DEBUG, "Monitor observer: Watch ID %u (gen %u) deactivated, cleaning up pending entries", 
	           ref.watch_id, ref.generation);
	
	int entries_removed = 0;
	
	/* Scan pending entries for the deactivated watch (iterate backwards for safe removal) */
	for (int i = monitor->num_pending - 1; i >= 0; i--) {
		pending_t *pending = monitor->pending[i];
		if (pending && watchref_equal(pending->watchref, ref)) {
			log_message(DEBUG, "Removing orphaned pending entry for path: %s", 
			           pending->target_path ? pending->target_path : "<null>");
			
			/* Remove using the public pending_remove function for proper cleanup */
			pending_remove(monitor, i);
			entries_removed++;
		}
	}
	
	if (entries_removed > 0) {
		log_message(DEBUG, "Pending cleanup complete: removed %d orphaned entries", entries_removed);
	}
}

/* Free resources used by a watcher structure */
static void watcher_destroy(monitor_t *monitor, watcher_t *watcher, bool is_stale) {
	if (watcher == NULL) {
		return;
	}

	/* Close the file descriptor if this is the last watcher using it */
	if (watcher->wd >= 0) {
		bool should_close = !watcher->shared_fd;

		if (watcher->shared_fd && monitor) {
			/* Count other watchers using this FD */
			int fd_users = 0;
			watcher_t **list = is_stale ? monitor->watcher_graveyard.stale_watches : monitor->watches;
			int count = is_stale ? monitor->watcher_graveyard.num_stale : monitor->num_watches;

			for (int i = 0; i < count; i++) {
				watcher_t *other = list[i];
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
monitor_t *monitor_create(config_t *config, registry_t *registry) {
	monitor_t *monitor;

	if (config == NULL || registry == NULL) {
		log_message(ERROR, "Invalid configuration or registry for monitor");
		return NULL;
	}

	monitor = calloc(1, sizeof(monitor_t));
	if (monitor == NULL) {
		log_message(ERROR, "Failed to allocate memory for monitor");
		return NULL;
	}

	monitor->config = config;
	monitor->registry = registry; /* Take ownership of registry */
	monitor->kq = -1;
	monitor->watches = NULL;
	monitor->num_watches = 0;
	monitor->pending = NULL;
	monitor->num_pending = 0;
	monitor->running = false;
	monitor->reload = false;
    monitor->watcher_graveyard.stale_watches = NULL;
    monitor->watcher_graveyard.num_stale = 0;
    monitor->config_graveyard.old_config = NULL;

	/* Store config file path for reloading */
	if (config->config_path != NULL) {
		monitor->config_path = strdup(config->config_path);
	}

	/* Initialize the deferred check queue with registry observer */
	monitor->check_queue = queue_create(monitor->registry, 16); /* Initial capacity of 16 */

	/* Initialize state table */
	monitor->states = states_create(PATH_HASH_SIZE, monitor->registry);
	if (!monitor->states) {
		log_message(ERROR, "Failed to create state table for monitor");
		queue_destroy(monitor->check_queue);
		free(monitor->config_path);
		free(monitor);
		return NULL;
	}

	/* Initialize pending watch observer */
	monitor->pending_observer.on_watch_deactivated = monitor_on_pending_watch_deactivated;
	monitor->pending_observer.context = monitor;
	monitor->pending_observer.next = NULL;
	
	/* Register pending observer with the registry */
	if (monitor->registry && !register_observer(monitor->registry, &monitor->pending_observer)) {
		log_message(ERROR, "Failed to register pending observer with registry");
		states_destroy(monitor->states);
		queue_destroy(monitor->check_queue);
		free(monitor->config_path);
		free(monitor);
		return NULL;
	}

	/* Initialize delayed event queue */
	monitor->delayed_events = NULL;
	monitor->delayed_count = 0;
	monitor->delayed_capacity = 0;

	/* Initialize the special watch for intermediate glob directories */
	watch_t *glob_watch = calloc(1, sizeof(watch_t));
	if (!glob_watch) {
		log_message(ERROR, "Failed to allocate memory for glob watch");
		states_destroy(monitor->states);
		queue_destroy(monitor->check_queue);
		free(monitor->config_path);
		free(monitor);
		return NULL;
	}
	glob_watch->name = strdup("__glob_intermediate__");
	glob_watch->target = WATCH_DIRECTORY;
	glob_watch->filter = EVENT_STRUCTURE;
	glob_watch->command = NULL; /* No command execution */
	
	/* Initialize dynamic tracking fields (glob intermediate watch is not dynamic) */
	glob_watch->is_dynamic = false;
	glob_watch->source_pattern = NULL;
	
	/* Add glob watch to registry and store reference */
	monitor->glob_watchref = registry_add(monitor->registry, glob_watch);
	if (!watchref_valid(monitor->glob_watchref)) {
		log_message(ERROR, "Failed to add glob watch to registry");
		config_destroy_watch(glob_watch);
		states_destroy(monitor->states);
		queue_destroy(monitor->check_queue);
		free(monitor->config_path);
		free(monitor);
		return NULL;
	}

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
		watcher_destroy(monitor, monitor->watches[i], false);
		monitor->watches[i] = NULL; /* Prevent use-after-free in subsequent calls */
	}
    if (monitor->watcher_graveyard.stale_watches) {
        log_message(DEBUG, "Cleaning up %d stale watchers from graveyard during monitor destruction.", monitor->watcher_graveyard.num_stale);
        for (int i = 0; i < monitor->watcher_graveyard.num_stale; i++) {
            watcher_destroy(monitor, monitor->watcher_graveyard.stale_watches[i], true);
        }
        free(monitor->watcher_graveyard.stale_watches);
    }
    if (monitor->config_graveyard.old_config) {
        log_message(DEBUG, "Cleaning up old config from graveyard during monitor destruction.");
        config_destroy(monitor->config_graveyard.old_config);
    }

	free(monitor->watches);

	/* Unregister pending observer from registry */
	if (monitor->registry) {
		unregister_observer(monitor->registry, &monitor->pending_observer);
	}

	/* Clean up pending watches */
	pending_cleanup(monitor);

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
	states_destroy(monitor->states);

	/* Perform final garbage collection before destroying registry */
	if (monitor->registry) {
		registry_garbage(monitor->registry);
		log_message(DEBUG, "Performed final garbage collection during monitor destruction");
	}

	/* Destroy the configuration */
	config_destroy(monitor->config);

	/* Destroy the registry (monitor owns it) */
	if (monitor->registry) {
		registry_destroy(monitor->registry);
	}

	free(monitor);
}

/* Set up kqueue monitoring for a file or directory */
static bool monitor_kq(monitor_t *monitor, watcher_t *watcher) {
	struct kevent changes[1];
	int flags = 0;

	/* Consolidate event filters from ALL watches on this file descriptor */
	for (int i = 0; i < monitor->num_watches; i++) {
		if (monitor->watches[i]->wd == watcher->wd) {
			watch_t *shared_watch = registry_get(monitor->registry, monitor->watches[i]->watchref);
			if (shared_watch) {
				if (shared_watch->filter & EVENT_STRUCTURE) {
					flags |= NOTE_WRITE | NOTE_EXTEND;
				}
				if (shared_watch->filter & EVENT_METADATA) {
					flags |= NOTE_ATTRIB | NOTE_LINK;
				}
				if (shared_watch->filter & EVENT_CONTENT) {
					flags |= NOTE_DELETE | NOTE_RENAME | NOTE_REVOKE | NOTE_WRITE;
				}
			}
		}
	}

	/* Register for events */
	EV_SET(&changes[0], watcher->wd, EVFILT_VNODE, EV_ADD | EV_CLEAR, flags, 0, watcher);

	if (kevent(monitor->kq, changes, 1, NULL, 0, NULL) == -1) {
		log_message(ERROR, "Failed to register kqueue events for %s: %s", watcher->path, strerror(errno));
		return false;
	}

	return true;
}

/* Add a watch for a single path, creating or sharing file descriptors as needed */
bool monitor_path(monitor_t *monitor, const char *path, watchref_t watchref) {
	/* Clean up any stale watchers for this path first */
	monitor_sync(monitor, path);
	
	/* Check if a watcher for this path and watch config already exists to avoid duplicates */
	for (int i = 0; i < monitor->num_watches; i++) {
		if (strcmp(monitor->watches[i]->path, path) == 0 && watchref_equal(monitor->watches[i]->watchref, watchref)) {
			return true;
		}
	}

	watcher_t *shared_watcher = watcher_find(monitor, path);
	if (shared_watcher) {
		/* Path is already being watched, share the fd */
		log_message(DEBUG, "Path %s already watched, sharing file descriptor", path);
		watcher_t *watcher = calloc(1, sizeof(watcher_t));
		if (!watcher) {
			log_message(ERROR, "Failed to allocate memory for watcher for path %s", path);
			return false;
		}
		watcher->wd = shared_watcher->wd;
		watcher->path = strdup(path);
		watcher->watchref = watchref;
		watcher->shared_fd = true;
		shared_watcher->shared_fd = true;

		if (!watcher_stat(watcher)) {
			watcher_destroy(monitor, watcher, false);
			return false;
		}

		if (!watcher_add(monitor, watcher)) {
			watcher_destroy(monitor, watcher, false);
			return false;
		}

		/* Update kqueue with combined filters */
		return monitor_kq(monitor, watcher);
	} else {
		/* New path, create a new watcher and get a new fd */
		log_message(DEBUG, "Path %s is new, creating new watcher", path);
		int fd = open(path, O_RDONLY);
		if (fd == -1) {
			/* It's possible the file was deleted since the initial scan */
			log_message(WARNING, "Failed to open %s: %s", path, strerror(errno));
			return true; /* Not a fatal error, just skip this path */
		}

		watcher_t *watcher = calloc(1, sizeof(watcher_t));
		if (!watcher) {
			log_message(ERROR, "Failed to allocate memory for watcher for path %s", path);
			close(fd);
			return false;
		}
		watcher->wd = fd;
		watcher->path = strdup(path);
		watcher->watchref = watchref;
		watcher->shared_fd = false;

		if (!watcher_stat(watcher)) {
			watcher_destroy(monitor, watcher, false);
			return false;
		}

		if (!watcher_add(monitor, watcher)) {
			watcher_destroy(monitor, watcher, false);
			return false;
		}

		/* Establish baseline state */
		struct stat info;
		watch_t *watch = registry_get(monitor->registry, watchref);
		if (stat(path, &info) == 0 && watch) {
			kind_t kind = S_ISDIR(info.st_mode) ? ENTITY_DIRECTORY : ENTITY_FILE;
			states_get(monitor->states, path, kind, watchref, monitor->registry);
		}

		/* Add to kqueue */
		return monitor_kq(monitor, watcher);
	}
}

/* Recursively add watches for a directory and its subdirectories */
bool monitor_tree(monitor_t *monitor, const char *dir_path, watchref_t watchref) {
	watch_t *watch = registry_get(monitor->registry, watchref);
	if (!watch) {
		log_message(ERROR, "Invalid watch reference for directory tree scan");
		return false;
	}
	
	/* Skip hidden directories unless hidden is true */
	if (!watch->hidden && path_hidden(dir_path)) {
		log_message(DEBUG, "Skipping hidden directory: %s", dir_path);
		return true; /* Not an error, just skipping */
	}

	/* Add a watch for the directory itself */
	if (!monitor_path(monitor, dir_path, watchref)) {
		log_message(WARNING, "Failed to add watch for directory %s", dir_path);
		return false; /* If we can't watch the root, we shouldn't proceed */
	}

	/* If not recursive, we're done */
	if (!watch->recursive) {
		return true;
	}

	DIR *dir = opendir(dir_path);
	if (dir == NULL) {
		log_message(WARNING, "Failed to open directory %s: %s", dir_path, strerror(errno));
		return true; /* Not a fatal error, directory might have been deleted */
	}

	struct dirent *dirent;
	while ((dirent = readdir(dir)) != NULL) {
		/* Skip . and .. */
		if (strcmp(dirent->d_name, ".") == 0 || strcmp(dirent->d_name, "..") == 0) {
			continue;
		}

		char path[MAX_PATH_LEN];
		snprintf(path, sizeof(path), "%s/%s", dir_path, dirent->d_name);

		struct stat info;
		if (stat(path, &info) == -1) {
			log_message(WARNING, "Failed to stat %s: %s", path, strerror(errno));
			continue;
		}

		if (S_ISDIR(info.st_mode)) {
			/* Recursively watch subdirectory */
			monitor_tree(monitor, path, watchref);
		}
	}

	closedir(dir);
	return true;
}

/* Add a watch for a file or directory based on a watch reference */
bool monitor_add(monitor_t *monitor, watchref_t watchref, bool skip_pending) {
	watch_t *watch = registry_get(monitor->registry, watchref);
	if (monitor == NULL || !watch || watch->path == NULL) {
		log_message(ERROR, "Invalid arguments to monitor_add");
		return false;
	}

	/* Proactively validate the path to handle re-creations before adding watches */
	monitor_sync(monitor, watch->path);

	/* Get file/directory stats */
	struct stat info;
	if (stat(watch->path, &info) == -1) {
		if (errno == ENOENT && !skip_pending) {
			/* Path does not exist - add to pending watches for event-driven monitoring */
			log_message(DEBUG, "Path does not exist, adding to pending watches: %s", watch->path);
			if (pending_add(monitor, watch->path, watchref)) {
				/* Immediately process the parent to catch existing paths */
				pending_process(monitor, monitor->pending[monitor->num_pending - 1]->current_parent);
				return true;
			}
			return false;
		} else {
			/* Other stat error or skipping pending */
			log_message(WARNING, "Failed to stat %s: %s%s", watch->path, strerror(errno),
			           skip_pending ? " (skipping pending)" : ". It may have been deleted");
			return skip_pending ? false : true; /* Fail if skipping pending, else not fatal */
		}
	}

	/* Handle directories (possibly recursively) */
	if (S_ISDIR(info.st_mode)) {
		if (watch->target != WATCH_DIRECTORY) {
			log_message(WARNING, "%s is a directory but configured as a file", watch->path);
			watch->target = WATCH_DIRECTORY;
		}
		return monitor_tree(monitor, watch->path, watchref);
	}
	/* Handle regular files */
	else if (S_ISREG(info.st_mode)) {
		if (watch->target != WATCH_FILE) {
			log_message(WARNING, "%s is a file but configured as a directory", watch->path);
			watch->target = WATCH_FILE;
		}
		return monitor_path(monitor, watch->path, watchref);
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
	
	/* Initialize dynamic tracking fields (config watches are not dynamic) */
	config_watch->is_dynamic = false;
	config_watch->source_pattern = NULL;

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
		watchref_t watchref = config_get_watchref(monitor->config, i);
		if (watchref_valid(watchref)) {
			if (!monitor_add(monitor, watchref, false)) {
				watch_t *watch = config_get_watch(monitor->config, i, monitor->registry);
				log_message(WARNING, "Failed to add watch for %s, skipping", watch ? watch->path : "unknown");
			}
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
			if (config_add_watch(monitor->config, config_watch, monitor->registry)) {
				watchref_t config_watchref = config_get_watchref(monitor->config, monitor->config->num_watches - 1);
				if (!monitor_add(monitor, config_watchref, false)) {
					log_message(WARNING, "Failed to add config file watch for %s", monitor->config_path);
					/* Remove from config since it wasn't added to monitor */
					config_remove_watch(monitor->config, config_watchref, monitor->registry);
				} else {
					log_message(DEBUG, "Added config file watch for %s", monitor->config_path);
				}
			} else {
				log_message(WARNING, "Failed to add config watch to config structure");
				config_destroy_watch(config_watch);
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
	struct timespec kevent_time;
	clock_gettime(CLOCK_MONOTONIC, &kevent_time);

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
		events_handle(monitor, events, nev, &kevent_time, &sync);

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
	stability_process(monitor, &kevent_time);

	/* Process delayed events */
	events_delayed(monitor);

	/* Clean up retired watchers */
	monitor_watcher_cleanup(monitor);

	/* Clean up retired config */
	monitor_config_cleanup(monitor);

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

	/* Wait for any pending commands to finish before destroying state */
	command_cleanup(NULL);

	/* Close and recreate kqueue to invalidate all existing watchers and their udata pointers */
	if (monitor->kq >= 0) {
		close(monitor->kq);
	}
	monitor->kq = kqueue();
	if (monitor->kq == -1) {
		log_message(ERROR, "Failed to create new kqueue during reload: %s", strerror(errno));
		return false;
	}

	/* Save existing config to compare later */
	config_t *old_config = monitor->config;

	/* Create new configuration */
	config_t *new_config = config_create();
	if (!new_config) {
		log_message(ERROR, "Failed to create new configuration during reload");
		return false;
	}

	/* Create new registry for the reload */
	registry_t *new_registry = registry_create(0);
	if (!new_registry) {
		log_message(ERROR, "Failed to create new registry during reload");
		config_destroy(new_config);
		return false;
	}

	/* Copy daemon mode and log level from existing config */
	new_config->daemon_mode = old_config->daemon_mode;
	new_config->syslog_level = old_config->syslog_level;

	/* Parse configuration file */
	if (!config_parse(new_config, monitor->config_path, new_registry)) {
		log_message(ERROR, "Failed to parse new config, keeping old one: %s", monitor->config_path);
		config_destroy(new_config);
		registry_destroy(new_registry);
		/* Re-validate the watch on the config file to detect subsequent changes */
		monitor_sync(monitor, monitor->config_path);
		return false;
	}

	/* Preserve dynamic watches whose source patterns still exist in the new configuration */
	registry_t *old_registry = monitor->registry;
	for (int i = 0; i < old_config->num_watches; i++) {
		watch_t *old_watch = config_get_watch(old_config, i, old_registry);
		if (old_watch && old_watch->is_dynamic && old_watch->source_pattern) {
			/* Check if the source pattern exists in the new configuration */
			bool pattern_exists = false;
			for (int j = 0; j < new_config->num_watches; j++) {
				watch_t *new_watch = config_get_watch(new_config, j, new_registry);
				if (new_watch && !new_watch->is_dynamic && strcmp(new_watch->path, old_watch->source_pattern) == 0) {
					pattern_exists = true;
					break;
				}
			}

			if (pattern_exists) {
				/* Create a copy of the dynamic watch for the new config */
				watch_t *preserved_watch = config_clone_watch(old_watch);
				if (preserved_watch && config_add_watch(new_config, preserved_watch, new_registry)) {
					log_message(DEBUG, "Preserved dynamic watch: %s (from pattern: %s)", 
					           preserved_watch->path, preserved_watch->source_pattern);
				} else {
					log_message(WARNING, "Failed to preserve dynamic watch: %s", old_watch->path);
					if (preserved_watch) {
						config_destroy_watch(preserved_watch);
					}
				}
			}
		}
	}

	/* Replace old config and registry with new ones */
	monitor->config = new_config;
	monitor->registry = new_registry;

	/* Re-initialize the special watch for intermediate glob directories in the new registry */
	watch_t *glob_watch = calloc(1, sizeof(watch_t));
	if (!glob_watch) {
		log_message(ERROR, "Failed to allocate memory for glob watch during reload");
		config_destroy(new_config);
		return false;
	}
	glob_watch->name = strdup("__glob_intermediate__");
	glob_watch->target = WATCH_DIRECTORY;
	glob_watch->filter = EVENT_STRUCTURE;
	glob_watch->command = NULL;
	glob_watch->is_dynamic = false;
	glob_watch->source_pattern = NULL;
	
	monitor->glob_watchref = registry_add(monitor->registry, glob_watch);
	if (!watchref_valid(monitor->glob_watchref)) {
		log_message(ERROR, "Failed to add glob watch to registry during reload");
		config_destroy_watch(glob_watch);
		config_destroy(new_config);
		return false;
	}

	/* Add config file watch to the new config so it gets re-added */
	if (monitor->config_path != NULL) {
		watch_t *config_watch = monitor_config(monitor->config_path);
		if (config_watch) {
			if (!config_add_watch(new_config, config_watch, monitor->registry)) {
				log_message(WARNING, "Failed to add config watch to new config structure");
				config_destroy_watch(config_watch);
			}
		}
	}

	/* Reset the state management system */
	states_destroy(monitor->states);
	monitor->states = states_create(PATH_HASH_SIZE, monitor->registry);
	if (!monitor->states) {
		log_message(ERROR, "Failed to recreate state table during reload");
		return false;
	}

	/* Clear deferred and delayed queues to prevent access to old states */
	queue_destroy(monitor->check_queue);
	monitor->check_queue = queue_create(monitor->registry, 16);

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

	/* Clear pending watches that may reference old watches */
	pending_cleanup(monitor);


	/* Save old watches to be moved to the graveyard */
	watcher_t **stale_watches = monitor->watches;
	int stale_count = monitor->num_watches;

	/* Reset monitor's watch list to be populated with new watches */
	monitor->watches = NULL;
	monitor->num_watches = 0;

	/* Add watches from the new configuration (including the config file watch) */
	for (int i = 0; i < monitor->config->num_watches; i++) {
		watchref_t watchref = config_get_watchref(monitor->config, i);
		if (watchref_valid(watchref)) {
			watch_t *watch = config_get_watch(monitor->config, i, monitor->registry);
			log_message(DEBUG, "Reloading watch: %s (%s)", watch->name, watch->path);
			if (!monitor_add(monitor, watchref, false)) {
				log_message(WARNING, "Failed to add watch for %s", watch ? watch->path : "unknown");
			}
		}
	}

	/* Retire the old watchers to the graveyard */
    if (stale_count > 0) {
        if (monitor->watcher_graveyard.stale_watches) {
            /* If there's an old graveyard, clean it up now to make way for the new one */
            log_message(DEBUG, "Immediate cleanup of previous watcher graveyard to accommodate new one.");
            for (int i = 0; i < monitor->watcher_graveyard.num_stale; i++) {
                watcher_destroy(monitor, monitor->watcher_graveyard.stale_watches[i], true);
            }
            free(monitor->watcher_graveyard.stale_watches);
        }
        monitor->watcher_graveyard.stale_watches = stale_watches;
        monitor->watcher_graveyard.num_stale = stale_count;
        monitor->watcher_graveyard.retirement_time = time(NULL) + WATCHER_GRAVEYARD_SECONDS;
        log_message(DEBUG, "Retired %d watchers to graveyard. They will be cleaned up after %d seconds.", stale_count, WATCHER_GRAVEYARD_SECONDS);
    }

	/* Perform garbage collection and destroy old registry */
	if (old_registry) {
		registry_garbage(old_registry);
		registry_destroy(old_registry);
		log_message(DEBUG, "Performed garbage collection and destroyed old registry during reload");
	}

	/* Retire the old config to its graveyard */
    if (monitor->config_graveyard.old_config) {
        log_message(DEBUG, "Immediate cleanup of previous config graveyard to accommodate new one.");
        config_destroy(monitor->config_graveyard.old_config);
    }
    monitor->config_graveyard.old_config = old_config;
    monitor->config_graveyard.retirement_time = time(NULL) + WATCHER_GRAVEYARD_SECONDS;

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
			log_message(DEBUG, "Pruning stale subdirectory watch: %s", watcher->path);

			/* Destroy the watcher (closes FD if not shared) */
			watcher_destroy(monitor, watcher, false);

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

	/* Process all watchers monitoring this exact path */
	for (int i = 0; i < monitor->num_watches; i++) {
		watcher_t *watcher = monitor->watches[i];
		if (watcher && watcher->path && strcmp(watcher->path, path) == 0) {
			if (!path_exists) {
				/* Path deleted - clean up all related resources */
				log_message(DEBUG, "Path deleted: %s. Cleaning up watch resources.", path);
				
				/* Store watch config before watcher becomes invalid */
				watch_t *target_watch = registry_get(monitor->registry, watcher->watchref);

				/* Clear any pending deferred checks to prevent use-after-free */
				queue_remove(monitor->check_queue, path);

				/* Remove subdirectory watchers if this was a recursive directory */
				if (target_watch && target_watch->target == WATCH_DIRECTORY && target_watch->recursive) {
					monitor_prune(monitor, path);
				}

				/* Handle pending watches that might be affected by this deletion */
				pending_delete(monitor, path);

				/*  Remove dynamic watch from config to prevent resurrection during reload */
				if (target_watch && target_watch->is_dynamic) {
					config_remove_watch(monitor->config, watcher->watchref, monitor->registry);
				}

				/* Finally, remove the watcher for the parent path itself */
				for (int j = 0; j < monitor->num_watches; j++) {
					if (monitor->watches[j] == watcher) {
						watcher_destroy(monitor, monitor->watches[j], false);
						/* Shift remaining watchers */
						for (int k = j; k < monitor->num_watches - 1; k++) {
							monitor->watches[k] = monitor->watches[k + 1];
						}
						monitor->num_watches--;
						break;
					}
				}
				i--; /* Adjust loop index after removal */
				list_modified = true;
			} else if (watcher->inode != info.st_ino || watcher->device != info.st_dev) {
				/* Path exists but inode/device changed - it was recreated */
				log_message(DEBUG, "Path recreated: %s. Refreshing watch.", path);

				/* Close old file descriptor if not shared */
				if (!watcher->shared_fd && watcher->wd >= 0) {
					close(watcher->wd);
				}

				/* Attempt to open the recreated path */
				int new_fd = open(path, O_RDONLY);
				if (new_fd == -1) {
					log_message(ERROR, "Failed to open recreated path %s: %s", path, strerror(errno));
					/* Treat as deleted for current_time */
					watcher_destroy(monitor, watcher, false);
					for (int j = i; j < monitor->num_watches - 1; j++) {
						monitor->watches[j] = monitor->watches[j + 1];
					}
					monitor->num_watches--;
					i--;
					list_modified = true;
					continue;
				}

				/* Update watcher with new file info */
				watcher->wd = new_fd;
				watcher->inode = info.st_ino;
				watcher->device = info.st_dev;
				watcher->shared_fd = false;

				/* Re-register with kqueue */
				monitor_kq(monitor, watcher);

				/* If it was a recursive directory, rescan subdirectories */
				watch_t *watch = registry_get(monitor->registry, watcher->watchref);
				if (watch && watch->target == WATCH_DIRECTORY && watch->recursive) {
					log_message(DEBUG, "Re-scanning subdirectories for recreated path: %s", path);
					monitor_prune(monitor, path);
					monitor_tree(monitor, path, watcher->watchref);
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

void monitor_watcher_cleanup(monitor_t *monitor) {
    if (!monitor || !monitor->watcher_graveyard.stale_watches) {
        return;
    }

    time_t now = time(NULL);
    if (now >= monitor->watcher_graveyard.retirement_time) {
        log_message(DEBUG, "Cleaning up %d stale watchers from graveyard.", monitor->watcher_graveyard.num_stale);
        for (int i = 0; i < monitor->watcher_graveyard.num_stale; i++) {
            watcher_destroy(monitor, monitor->watcher_graveyard.stale_watches[i], true);
        }
        free(monitor->watcher_graveyard.stale_watches);
        monitor->watcher_graveyard.stale_watches = NULL;
        monitor->watcher_graveyard.num_stale = 0;
    }
}

void monitor_config_cleanup(monitor_t *monitor) {
    if (!monitor || !monitor->config_graveyard.old_config) {
        return;
    }

    time_t now = time(NULL);
    if (now >= monitor->config_graveyard.retirement_time) {
        log_message(DEBUG, "Cleaning up old config from graveyard.");
        config_destroy(monitor->config_graveyard.old_config);
        monitor->config_graveyard.old_config = NULL;
    }
}
