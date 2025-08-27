#include "monitor.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/event.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "command.h"
#include "control.h"
#include "events.h"
#include "logger.h"
#include "mapper.h"
#include "pending.h"
#include "queue.h"
#include "resource.h"
#include "stability.h"
#include "tracker.h"

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

/* Clean up internal resources of a watcher */
static void watcher_cleanup(monitor_t *monitor, watcher_t *watcher, bool is_stale) {
	if (watcher == NULL) return;

	/* Close the file descriptor if this is the last watcher using it */
	if (watcher->wd >= 0) {
		if (is_stale) {
			/* For stale watchers in the graveyard, mapper is unaware of them */
			bool should_close = true;
			if (monitor && monitor->graveyard.stale_watches) {
				int fd_users = 0;
				for (int i = 0; i < monitor->graveyard.num_stale; i++) {
					watcher_t *other = monitor->graveyard.stale_watches[i];
					if (other && other != watcher && other->wd == watcher->wd) {
						fd_users++;
					}
				}
				should_close = (fd_users == 0);
			}
			if (should_close) {
				close(watcher->wd);
			}
		} else {
			/* For active watchers use mapper */
			if (monitor && monitor->mapper && unmap_watcher(monitor->mapper, watcher->wd, watcher)) {
				close(watcher->wd);
			}
		}
	}

	free(watcher->path);
}

/* Free resources used by a watcher structure */
static void watcher_destroy(monitor_t *monitor, watcher_t *watcher, bool is_stale) {
	if (watcher == NULL) return;

	watcher_cleanup(monitor, watcher, is_stale);
	free(watcher);
}

/* Initialize inode and device information for a watcher */
static bool watcher_stat(watcher_t *watcher) {
	struct stat info;
	if (fstat(watcher->wd, &info) == -1) {
		log_message(ERROR, "Failed to fstat file descriptor %d for %s: %s", watcher->wd,
					watcher->path, strerror(errno));
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

	/* Add the watcher to the mapper for fast event lookup */
	if (monitor->mapper) {
		map_watcher(monitor->mapper, watcher->wd, watcher);
	}

	return true;
}

/* Find a watcher entry by path */
static watcher_t *watcher_find(monitor_t *monitor, const char *path) {
	if (!monitor || !path) return NULL;

	for (int i = 0; i < monitor->num_watches; i++) {
		if (monitor->watches[i] && monitor->watches[i]->path) {
			if (strcmp(monitor->watches[i]->path, path) == 0) {
				log_message(DEBUG, "Found existing watcher for path %s (fd=%d)",
							path, monitor->watches[i]->wd);
				return monitor->watches[i];
			}
		}
	}
	return NULL;
}

/* Observer callback for direct watcher cleanup when watches are deactivated */
static void monitor_deactivation(watchref_t watchref, void *context) {
	monitor_t *monitor = (monitor_t *) context;
	if (!monitor || !monitor->watches) return;

	log_message(DEBUG, "Watch (watch_id=%u, gen=%u) deactivated, cleaning up watcher resources",
				watchref.watch_id, watchref.generation);

	/* Get watch info before deactivation to check if it monitored file content */
	watch_t *watch = registry_get(monitor->registry, watchref);
	if (watch && ((watch->filter & EVENT_CONTENT) || watch->filter == EVENT_ALL) && watch->path) {
		/* Clean up file trackers associated with this watch */
		resource_t *resource = resource_get(monitor->resources, watch->path, ENTITY_DIRECTORY);
		if (resource && resource->trackers) {
			log_message(DEBUG, "Cleaning up file trackers for disabled watch: %s", watch->path);
			resource_lock(resource);
			tracker_purge(monitor, resource->trackers, watchref);
			resource_unlock(resource);
		}
	}

	/* Scan monitor watchers for the deactivated watch and move them to the graveyard */
	for (int i = monitor->num_watches - 1; i >= 0; i--) {
		watcher_t *watcher = monitor->watches[i];
		if (watcher && watchref_equal(watcher->watchref, watchref)) {
			log_message(DEBUG, "Retiring watcher for deactivated watch: %s (fd=%d)",
						watcher->path, watcher->wd);

			/* Remove from the mapper to prevent further events */
			unmap_watcher(monitor->mapper, watcher->wd, watcher);

			/* Add to graveyard */
			watcher_t **new_stale_watches = realloc(monitor->graveyard.stale_watches,
													(monitor->graveyard.num_stale + 1) * sizeof(watcher_t *));
			if (new_stale_watches) {
				monitor->graveyard.stale_watches = new_stale_watches;
				monitor->graveyard.stale_watches[monitor->graveyard.num_stale++] = watcher;
			} else {
				log_message(ERROR, "Failed to allocate memory for graveyard, leaking watcher");
			}

			/* Remove the watcher from the active list by shifting */
			for (int j = i; j < monitor->num_watches - 1; j++) {
				monitor->watches[j] = monitor->watches[j + 1];
			}
			monitor->num_watches--;
		}
	}

	/* Set retirement time to ensure graveyard is processed on the next poll */
	if (monitor->graveyard.num_stale > 0) {
		monitor->graveyard.retirement_time = time(NULL);
	}
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
	monitor->registry = registry;
	monitor->kq = -1;
	monitor->watches = NULL;
	monitor->num_watches = 0;
	monitor->pending = NULL;
	monitor->num_pending = 0;
	monitor->running = false;
	monitor->reload = false;

	monitor->graveyard.stale_watches = NULL;
	monitor->graveyard.num_stale = 0;
	monitor->graveyard.old_config = NULL;

	/* Store config file path for reloading */
	if (config->config_path != NULL) {
		monitor->config_path = strdup(config->config_path);
	}

	/* Initialize the mapper for fast event lookup */
	monitor->mapper = mapper_create(0);
	if (!monitor->mapper) {
		log_message(ERROR, "Failed to create mapper for monitor");
		free(monitor->config_path);
		free(monitor);
		return NULL;
	}

	/* Initialize the queued check queue with registry observer */
	monitor->check_queue = queue_create(monitor->registry, 16); /* Initial capacity of 16 */

	/* Initialize resource table */
	monitor->resources = resources_create(PATH_HASH_SIZE, monitor->registry);
	if (!monitor->resources) {
		log_message(ERROR, "Failed to create resource table for monitor");
		queue_destroy(monitor->check_queue);
		free(monitor->config_path);
		free(monitor);
		return NULL;
	}

	/* Initialize monitor watcher observer */
	monitor->monitor_observer.handle_deactivation = monitor_deactivation;
	monitor->monitor_observer.context = monitor;
	monitor->monitor_observer.next = NULL;

	/* Initialize pending watch observer */
	monitor->pending_observer.handle_deactivation = pending_deactivation;
	monitor->pending_observer.context = monitor;
	monitor->pending_observer.next = NULL;

	/* Register observers with the registry */
	if (!observer_register(monitor->registry, &monitor->monitor_observer)) {
		log_message(ERROR, "Failed to register monitor observer with registry");
		observer_unregister(monitor->registry, &monitor->pending_observer);
		resources_destroy(monitor->resources);
		queue_destroy(monitor->check_queue);
		free(monitor->config_path);
		free(monitor);
		return NULL;
	}

	if (!observer_register(monitor->registry, &monitor->pending_observer)) {
		log_message(ERROR, "Failed to register pending observer with registry");
		resources_destroy(monitor->resources);
		queue_destroy(monitor->check_queue);
		free(monitor->config_path);
		free(monitor);
		return NULL;
	}

	/* Initialize delayed event queue */
	monitor->delayed_events = NULL;
	monitor->delayed_count = 0;
	monitor->delayed_capacity = 0;

	/* Initialize control server */
	monitor->server = server_create(config->socket_path); /* Use configured socket path or default */
	if (!monitor->server) {
		log_message(WARNING, "Failed to create control server, continuing without socket control");
	}

	return monitor;
}

/* Destroy a monitor and free all associated resources */
void monitor_destroy(monitor_t *monitor) {
	if (monitor == NULL) return;

	/* Close kqueue */
	if (monitor->kq >= 0) {
		close(monitor->kq);
	}

	/* Free watches */
	for (int i = 0; i < monitor->num_watches; i++) {
		watcher_destroy(monitor, monitor->watches[i], false);
		monitor->watches[i] = NULL; /* Prevent use-after-free in subsequent calls */
	}
	if (monitor->graveyard.stale_watches) {
		log_message(DEBUG, "Cleaning up %d stale watchers from graveyard", monitor->graveyard.num_stale);
		for (int i = 0; i < monitor->graveyard.num_stale; i++) {
			watcher_cleanup(monitor, monitor->graveyard.stale_watches[i], true);
		}
		for (int i = 0; i < monitor->graveyard.num_stale; i++) {
			free(monitor->graveyard.stale_watches[i]);
		}
		free(monitor->graveyard.stale_watches);
	}
	if (monitor->graveyard.old_config) {
		log_message(DEBUG, "Cleaning up old config from graveyard during monitor destruction");
		config_destroy(monitor->graveyard.old_config);
	}

	free(monitor->watches);

	/* Unregister observers from registry */
	if (monitor->registry) {
		observer_unregister(monitor->registry, &monitor->monitor_observer);
		observer_unregister(monitor->registry, &monitor->pending_observer);
	}

	/* Clean up pending watches */
	pending_cleanup(monitor, monitor->registry);

	free(monitor->config_path);

	/* Clean up the check queue */
	queue_destroy(monitor->check_queue);

	/* Clean up the mapper */
	mapper_destroy(monitor->mapper);

	/* Clean up delayed event queue */
	if (monitor->delayed_events) {
		for (int i = 0; i < monitor->delayed_count; i++) {
			free(monitor->delayed_events[i].event.path);
		}
		free(monitor->delayed_events);
	}

	/* Clean up resource table */
	resources_destroy(monitor->resources);

	/* Clean up control server */
	if (monitor->server) {
		server_destroy(monitor->server);
	}

	/* Perform final garbage collection before destroying registry */
	if (monitor->registry) {
		registry_garbage(monitor->registry);
		log_message(DEBUG, "Performed final garbage collection during monitor destruction");
	}

	/* Destroy the configuration */
	config_destroy(monitor->config);

	/* Destroy the registry */
	if (monitor->registry) {
		registry_destroy(monitor->registry);
	}

	free(monitor);
}

/* Set up kqueue monitoring for a file or directory */
static bool monitor_kq(monitor_t *monitor, watcher_t *watcher) {
	struct kevent changes[1];
	int flags = 0;
	int shared_count = 0;
	target_t target_type = WATCH_UNKNOWN; /* Uninitialized */

	/* Consolidate event filters from enabled watches on this file descriptor */
	for (int i = 0; i < monitor->num_watches; i++) {
		if (monitor->watches[i]->wd != watcher->wd) continue;

		watch_t *shared_watch = registry_get(monitor->registry, monitor->watches[i]->watchref);
		if (!shared_watch) continue;

		/* Only process enabled watches */
		if (!shared_watch->enabled) continue;

		if (target_type == WATCH_UNKNOWN) target_type = shared_watch->target;

		shared_count++;

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

	/* Add base flags to ensure the kernel doesn't silently drop fundamental events */
	if (target_type == WATCH_FILE) flags |= NOTE_WRITE | NOTE_DELETE | NOTE_RENAME;
	else if (target_type == WATCH_DIRECTORY) flags |= NOTE_WRITE;

	if (shared_count > 1) {
		log_message(DEBUG, "Configuring kqueue for fd %d with %d shared watches, combined flags: 0x%x",
					watcher->wd, shared_count, flags);
	}

	/* Register for events */
	EV_SET(&changes[0], watcher->wd, EVFILT_VNODE, EV_ADD | EV_CLEAR, flags, 0, watcher);

	if (kevent(monitor->kq, changes, 1, NULL, 0, NULL) == -1) {
		log_message(ERROR, "Failed to register kqueue events for %s (fd=%d): %s", watcher->path,
					watcher->wd, strerror(errno));
		return false;
	}

	return true;
}

/* Add a watch for a single path, creating or sharing file descriptors as needed */
bool monitor_path(monitor_t *monitor, const char *path, watchref_t watchref) {
	if (!monitor || !path || !watchref_valid(watchref)) return false;

	/* Clean up any stale watchers for this path first */
	monitor_sync(monitor, path);

	/* Check if this exact combination already exists to avoid true duplicates */
	for (int i = 0; i < monitor->num_watches; i++) {
		if (strcmp(monitor->watches[i]->path, path) == 0 &&
			watchref_equal(monitor->watches[i]->watchref, watchref)) {
			return true;
		}
	}

	/* Always check for existing watchers by path to prioritize fd sharing */
	watcher_t *shared_watcher = watcher_find(monitor, path);
	if (shared_watcher) {
		/* Path is already being watched, share the fd */
		log_message(INFO, "Sharing file descriptor for path %s (watchref %u:%u with existing fd %d)",
					path, watchref.watch_id, watchref.generation, shared_watcher->wd);

		watcher_t *watcher = calloc(1, sizeof(watcher_t));
		if (!watcher) {
			log_message(ERROR, "Failed to allocate memory for shared watcher for path %s", path);
			return false;
		}

		watcher->wd = shared_watcher->wd;
		watcher->path = strdup(path);
		if (!watcher->path) {
			log_message(ERROR, "Failed to duplicate path for shared watcher: %s", path);
			free(watcher);
			return false;
		}

		watcher->watchref = watchref;
		watcher->shared_fd = true;
		shared_watcher->shared_fd = true;

		if (!watcher_stat(watcher)) {
			log_message(ERROR, "Failed to stat shared watcher for path %s", path);
			watcher_destroy(monitor, watcher, false);
			return false;
		}

		if (!watcher_add(monitor, watcher)) {
			log_message(ERROR, "Failed to add shared watcher for path %s", path);
			watcher_destroy(monitor, watcher, false);
			return false;
		}

		/* Update kqueue with combined filters from all watches on this fd */
		if (!monitor_kq(monitor, watcher)) {
			log_message(ERROR, "Failed to update kqueue for shared watcher: %s", path);
			return false;
		}

		/* For shared watchers, we still need to create a resource subscription */
		struct stat info;
		watch_t *watch = registry_get(monitor->registry, watchref);
		if (stat(path, &info) == 0 && watch) {
			kind_t kind = S_ISDIR(info.st_mode) ? ENTITY_DIRECTORY : ENTITY_FILE;
			resources_subscription(monitor->resources, monitor->registry, path, watchref, kind);
		}

		/* Shared watcher created successfully */
		return true;
	} else {
		/* New path, create a new watcher and get a new fd */
		int fd = open(path, O_RDONLY);
		if (fd == -1) {
			/* It's possible the file was deleted since the initial scan */
			log_message(WARNING, "Failed to open %s: %s", path, strerror(errno));
			return true; /* Not a fatal error, just skip this path */
		}

		watcher_t *watcher = calloc(1, sizeof(watcher_t));
		if (!watcher) {
			log_message(ERROR, "Failed to allocate memory for new watcher for path %s", path);
			close(fd);
			return false;
		}

		watcher->wd = fd;
		watcher->path = strdup(path);
		if (!watcher->path) {
			log_message(ERROR, "Failed to duplicate path for new watcher: %s", path);
			close(fd);
			free(watcher);
			return false;
		}

		watcher->watchref = watchref;
		watcher->shared_fd = false;

		if (!watcher_stat(watcher)) {
			log_message(ERROR, "Failed to stat new watcher for path %s", path);
			watcher_destroy(monitor, watcher, false);
			return false;
		}

		if (!watcher_add(monitor, watcher)) {
			log_message(ERROR, "Failed to add new watcher for path %s", path);
			watcher_destroy(monitor, watcher, false);
			return false;
		}

		/* Establish baseline state */
		struct stat info;
		watch_t *watch = registry_get(monitor->registry, watchref);
		if (stat(path, &info) == 0 && watch) {
			kind_t kind = S_ISDIR(info.st_mode) ? ENTITY_DIRECTORY : ENTITY_FILE;
			resources_subscription(monitor->resources, monitor->registry, path, watchref, kind);
		}

		/* Add to kqueue */
		if (!monitor_kq(monitor, watcher)) {
			log_message(ERROR, "Failed to setup kqueue for new watcher: %s", path);
			return false;
		}

		/* New watcher created successfully */
		return true;
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

	/* Skip excluded directories */
	if (exclude_match(watch, dir_path)) {
		log_message(DEBUG, "Skipping excluded directory: %s", dir_path);
		return true; /* Not an error, just skipping */
	}

	/* Add a watch for the directory itself */
	if (!monitor_path(monitor, dir_path, watchref)) {
		log_message(WARNING, "Failed to add watch for directory %s", dir_path);
		return false; /* If we can't watch the root, we shouldn't proceed */
	}

	/* Add file watches for content monitoring if requested */
	if ((watch->filter & EVENT_CONTENT) || watch->filter == EVENT_ALL) {
		/* Find the resource for this directory to scan for files */
		resource_t *resource = resource_get(monitor->resources, dir_path, ENTITY_DIRECTORY);
		if (resource) {
			resource_lock(resource);
			uint64_t config_hash = configuration_hash(watch);
			profile_t *profile = profile_get(resource, config_hash);
			if (profile) {
				tracker_scan(monitor, resource, watchref, watch);
			}
			resource_unlock(resource);
		}
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
		int path_len = snprintf(path, sizeof(path), "%s/%s", dir_path, dirent->d_name);

		/* Check for path truncation */
		if (path_len >= (int) sizeof(path)) {
			log_message(WARNING, "Path too long, skipping: %s/%s", dir_path, dirent->d_name);
			continue;
		}

		/* Skip excluded paths */
		if (exclude_match(watch, path)) {
			continue;
		}

		/* Skip hidden directories unless hidden is true */
		if (!watch->hidden && path_hidden(path)) {
			continue;
		}

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
	if (monitor == NULL || !watch || watch->path == NULL) return false;

	/* Check if watch is disabled */
	if (!watch->enabled) {
		log_message(INFO, "Watch '%s' is disabled, skipping setup", watch->name ? watch->name : "unknown");
		return true; /* Success but no monitoring */
	}

	/* Proactively validate the path to handle re-creations before adding watches */
	monitor_sync(monitor, watch->path);

	/* Get file/directory stats */
	struct stat info;
	if (stat(watch->path, &info) != 0) {
		/* Handle path not existing */
		if (errno == ENOENT && !skip_pending) {
			/* Path does not exist, add to pending watches for event-driven monitoring */
			log_message(DEBUG, "Path does not exist, adding to pending watches: %s", watch->path);
			if (!pending_add(monitor, watch->path, watchref)) {
				return false;
			}
			/* Immediately process the parent to catch existing paths */
			pending_process(monitor, monitor->pending[monitor->num_pending - 1]->current_parent);
			return true;
		}

		/* Other stat error or skipping pending */
		log_message(WARNING, "Failed to stat %s: %s%s", watch->path, strerror(errno),
					skip_pending ? " (skipping pending)" : ". It may have been deleted");
		return skip_pending ? false : true; /* Fail if skipping pending, else not fatal */
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
	if (S_ISREG(info.st_mode)) {
		if (watch->target != WATCH_FILE) {
			log_message(WARNING, "%s is a file but configured as a directory", watch->path);
			watch->target = WATCH_FILE;
		}
		return monitor_path(monitor, watch->path, watchref);
	}

	/* Unsupported file type */
	log_message(ERROR, "Unsupported file type for %s", watch->path);
	return false;
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
	config_watch->enabled = true;
	config_watch->command = strdup("__config_reload__");
	config_watch->log_output = false;
	config_watch->buffer_output = false;
	config_watch->recursive = false;
	config_watch->hidden = false;
	config_watch->environment = false;
	config_watch->complexity = 1.0;
	config_watch->batch_timeout = 0;
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
	if (monitor == NULL) return false;

	/* Create kqueue */
	monitor->kq = kqueue();
	if (monitor->kq == -1) {
		log_message(ERROR, "Failed to create kqueue: %s", strerror(errno));
		return false;
	}

	/* Add watches for each entry in the registry */
	uint32_t num_watches = 0;
	watchref_t *watchrefs = registry_active(monitor->registry, &num_watches);
	if (watchrefs) {
		for (uint32_t i = 0; i < num_watches; i++) {
			if (watchref_valid(watchrefs[i])) {
				if (!monitor_add(monitor, watchrefs[i], false)) {
					watch_t *watch = registry_get(monitor->registry, watchrefs[i]);
					log_message(WARNING, "Failed to add watch for %s, skipping",
								watch ? watch->path : "unknown");
				}
			}
		}
		free(watchrefs);
	}

	/* Check if we have at least one active watch */
	if (monitor->num_watches == 0) {
		log_message(ERROR, "No valid watches could be set up, aborting");
		return false;
	}

	/* Add config file watch for hot reload by adding it to the config structure */
	if (!monitor->config_path) return true;

	watch_t *config_watch = monitor_config(monitor->config_path);
	if (!config_watch) return true;

	/* Try to add to config structure */
	if (!watch_add(monitor->config, monitor->registry, config_watch)) {
		log_message(WARNING, "Failed to add config watch to config structure");
		watch_destroy(config_watch);
		return true;
	}

	/* Find the watchref that was just added */
	uint32_t num_active = 0;
	watchref_t *active_watchrefs = registry_active(monitor->registry, &num_active);
	if (!active_watchrefs || num_active == 0) {
		return true;
	}

	watchref_t config_watchref = WATCHREF_INVALID;
	for (uint32_t i = 0; i < num_active; i++) {
		watch_t *watch = registry_get(monitor->registry, active_watchrefs[i]);
		if (!watch || !watch->command || strcmp(watch->command, "__config_reload__") != 0) {
			continue;
		}
		config_watchref = active_watchrefs[i];
		break;
	}
	free(active_watchrefs);

	if (!watchref_valid(config_watchref)) {
		return true;
	}

	if (!monitor_add(monitor, config_watchref, false)) {
		log_message(WARNING, "Failed to add config file watch for %s", monitor->config_path);
		watch_remove(monitor->config, monitor->registry, config_watchref);
	} else {
		log_message(DEBUG, "Added config file watch for %s", monitor->config_path);
	}

	/* Start control server if available */
	if (monitor->server) {
		if (!server_start(monitor->server, monitor->kq)) {
			log_message(WARNING, "Failed to start control server, socket control will be unavailable");
		}
	}

	return true;
}

/* Process events from kqueue and handle commands */
bool monitor_poll(monitor_t *monitor) {
	struct kevent events[MAX_EVENTS];
	int new_event;
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

	/* Calculate timeout based on pending queued scans and delayed events */
	struct timespec now_monotonic;
	clock_gettime(CLOCK_MONOTONIC, &now_monotonic);

	p_timeout = timeout_calculate(monitor, &timeout, &now_monotonic);

	/* Wait for events */
	new_event = kevent(monitor->kq, NULL, 0, events, MAX_EVENTS, p_timeout);

	/* Get time after kevent returns */
	struct timespec kevent_time;
	clock_gettime(CLOCK_MONOTONIC, &kevent_time);

	/* Handle kevent result */
	if (new_event == -1) {
		if (errno == EINTR) {
			log_message(DEBUG, "kevent interrupted by signal, returning to main loop");
			return true; /* Return to main loop where running flag will be checked */
		}
		log_message(ERROR, "kevent error: %s", strerror(errno));
		return false; /* Stop monitoring on error */
	}

	/* Process new events */
	if (new_event > 0) {
		log_message(DEBUG, "Processing %d new kqueue events", new_event);

		/* Initialize validate request for collecting paths that need validation */
		validate_t validate;
		validate_init(&validate);

		/* Separate control events from file system events */
		struct kevent filesystem_event[MAX_EVENTS];
		int num_events = 0;

		for (int i = 0; i < new_event; i++) {
			/* Check if event is from control server socket */
			if (monitor->server && events[i].filter == EVFILT_READ &&
				events[i].ident == (uintptr_t) monitor->server->socket_fd) {
				control_accept(monitor->server, monitor->kq);
				continue;
			}

			/* Check if event is from a control client */
			if (monitor->server && control_event(monitor->server, &events[i])) {
				if (events[i].filter == EVFILT_READ) {
					control_handle(monitor, &events[i]);
				} else if (events[i].filter == EVFILT_WRITE) {
					control_write(monitor, &events[i]);
				}
				continue;
			}

			/* Add filesystem event for normal processing */
			filesystem_event[num_events++] = events[i];
		}

		/* Process filesystem events with existing handler */
		if (num_events > 0) {
			events_handle(monitor, filesystem_event, num_events, &kevent_time, &validate);
		}

		/* Handle any validate requests */
		if (validate.paths_count > 0) {
			for (int i = 0; i < validate.paths_count; i++) {
				log_message(DEBUG, "Validating watch for path: %s", validate.paths[i]);
				monitor_sync(monitor, validate.paths[i]);
			}
		}

		/* Clean up validate request */
		validate_cleanup(&validate);
	} else {
		/* new_event == 0 means timeout occurred */
		if (p_timeout) {
			log_message(DEBUG, "Timeout occurred after %ld.%09ld seconds, checking queued scans",
						p_timeout->tv_sec, p_timeout->tv_nsec);
		} else {
			log_message(DEBUG, "Timeout occurred, checking queued scans");
		}

		/* Check batch timeouts only on timeout */
		events_batch(monitor);
	}

	/* Check queued scans */
	stability_process(monitor, &kevent_time);

	/* Process delayed events */
	events_delayed(monitor);

	/* Clean up retired items from the graveyard */
	monitor_graveyard(monitor);

	/* Periodically clean up idle file watches to prevent resource leaks */
	if (!monitor->resources || !monitor->resources->buckets) {
		return true;
	}

	for (size_t i = 0; i < monitor->resources->bucket_count; i++) {
		resource_t *resource = monitor->resources->buckets[i];
		while (resource) {
			if (resource->trackers) {
				/* tracker_cleanup has its own internal timer to avoid running too often */
				resource_lock(resource);
				tracker_cleanup(monitor, resource->trackers);
				resource_unlock(resource);
			}
			resource = resource->next;
		}
	}

	return true; /* Continue monitoring */
}

/* Start the monitor and enter the main event loop */
bool monitor_start(monitor_t *monitor) {
	if (monitor == NULL) return false;

	monitor->running = true;

	int num_trackers = tracker_counter(monitor);
	if (num_trackers > 0) {
		log_message(NOTICE, "Starting monitor with %d watches, %d tracked files",
					monitor->num_watches, num_trackers);
	} else {
		log_message(NOTICE, "Starting monitor with %d watches", monitor->num_watches);
	}

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
	int current_trackers = tracker_counter(monitor);
	if (current_trackers > 0) {
		log_message(DEBUG, "Current configuration has %d watches, %d tracked files",
					monitor->num_watches, current_trackers);
	} else {
		log_message(DEBUG, "Current configuration has %d watches", monitor->num_watches);
	}

	/* Wait for any pending commands to finish before destroying state */
	command_cleanup(NULL);

	/* Create new kqueue first (don't close old one yet) */
	int new_kq = kqueue();
	if (new_kq == -1) {
		log_message(ERROR, "Failed to create new kqueue during reload: %s", strerror(errno));
		return false;
	}

	/* Save references to existing resources for potential rollback */
	config_t *old_config = monitor->config;
	registry_t *old_registry = monitor->registry;
	int old_kq = monitor->kq;

	/* Create new configuration */
	config_t *new_config = config_create();
	if (!new_config) {
		log_message(ERROR, "Failed to create new configuration during reload");
		close(new_kq);
		return false;
	}

	/* Create new registry for the reload */
	registry_t *new_registry = registry_create(0);
	if (!new_registry) {
		log_message(ERROR, "Failed to create new registry during reload");
		close(new_kq);
		config_destroy(new_config);
		return false;
	}

	/* Copy daemon mode, log level, and socket path from existing config */
	new_config->daemon_mode = old_config->daemon_mode;
	new_config->syslog_level = old_config->syslog_level;
	if (old_config->socket_path) {
		new_config->socket_path = strdup(old_config->socket_path);
		if (!new_config->socket_path) {
			log_message(ERROR, "Failed to allocate memory for socket path during reload");
			config_destroy(new_config);
			registry_destroy(new_registry);
			close(new_kq);
			return false;
		}
	}

	/* Parse configuration file */
	if (!config_parse(new_config, new_registry, monitor->config_path)) {
		log_message(ERROR, "Failed to parse new config, keeping old one: %s", monitor->config_path);
		close(new_kq);
		config_destroy(new_config);
		registry_destroy(new_registry);
		/* Re-validate the watch on the config file to detect subsequent changes */
		monitor_sync(monitor, monitor->config_path);
		return false;
	}

	/* Add config file watch to the new config */
	watch_t *config_watch = monitor_config(monitor->config_path);
	if (config_watch) {
		if (!watch_add(new_config, new_registry, config_watch)) {
			log_message(WARNING, "Failed to add config watch to new config structure");
			watch_destroy(config_watch);
		}
	}

	/* Create new resource management system */
	resources_t *new_resources = resources_create(PATH_HASH_SIZE, new_registry);
	if (!new_resources) {
		log_message(ERROR, "Failed to create new resource table during reload");
		close(new_kq);
		config_destroy(new_config);
		registry_destroy(new_registry);
		return false;
	}

	/* Create new queues */
	queue_t *new_check_queue = queue_create(new_registry, 16);
	if (!new_check_queue) {
		log_message(ERROR, "Failed to create new check queue during reload");
		resources_destroy(new_resources);
		close(new_kq);
		config_destroy(new_config);
		registry_destroy(new_registry);
		return false;
	}

	/* Create new mapper */
	mapper_t *new_mapper = mapper_create(0);
	if (!new_mapper) {
		log_message(ERROR, "Failed to create new mapper during reload");
		queue_destroy(new_check_queue);
		resources_destroy(new_resources);
		close(new_kq);
		config_destroy(new_config);
		registry_destroy(new_registry);
		return false;
	}

	/* Handle control server recreation during reload */
	server_t *old_server = monitor->server;
	server_t *new_server = NULL;

	/* Switch to new kqueue first */
	monitor->kq = new_kq;

	/* Stop old server first to free up the socket */
	if (old_server) {
		server_stop(old_server);
		server_destroy(old_server);
		monitor->server = NULL;
	}

	/* Create and start new control server */
	new_server = server_create(new_config->socket_path);

	if (new_server) {
		if (server_start(new_server, new_kq)) {
			monitor->server = new_server;
			log_message(DEBUG, "Control server successfully recreated during reload");
		} else {
			log_message(ERROR, "Failed to start new control server during reload");
			server_destroy(new_server);
			monitor->server = NULL;
		}
	} else {
		log_message(ERROR, "Failed to create new control server during reload");
		monitor->server = NULL;
	}

	/* Switch configuration first */
	monitor->config = new_config;

	/* Switch resource management */
	resources_t *old_resources = monitor->resources;
	monitor->resources = new_resources;

	/* Switch check queue */
	queue_t *old_check_queue = monitor->check_queue;
	monitor->check_queue = new_check_queue;

	/* Switch mapper */
	mapper_t *old_mapper = monitor->mapper;
	monitor->mapper = new_mapper;

	/* Clear delayed events queue that may reference old watches */
	int cleared_count = 0;
	if (monitor->delayed_events) {
		cleared_count = monitor->delayed_count;
		for (int i = 0; i < monitor->delayed_count; i++) {
			free(monitor->delayed_events[i].event.path);
		}
		free(monitor->delayed_events);
		monitor->delayed_events = NULL;
		monitor->delayed_count = 0;
		monitor->delayed_capacity = 0;
	}

	/* Clear pending watches that may reference old watches */
	pending_cleanup(monitor, old_registry);

	/* Save old watches to be moved to the graveyard */
	watcher_t **stale_watches = monitor->watches;
	int stale_count = monitor->num_watches;

	/* Reset monitor's watch list to be populated with new watches */
	monitor->watches = NULL;
	monitor->num_watches = 0;

	/* Switch to the new registry before adding watches */
	monitor->registry = new_registry;

	/* Add watches from the new configuration (including the config file watch) */
	uint32_t new_num_watches = 0;
	watchref_t *new_watchrefs = registry_active(monitor->registry, &new_num_watches);
	if (new_watchrefs) {
		for (uint32_t i = 0; i < new_num_watches; i++) {
			if (watchref_valid(new_watchrefs[i])) {
				watch_t *watch = registry_get(monitor->registry, new_watchrefs[i]);
				log_message(DEBUG, "Reloading watch: %s (%s)", watch ? watch->name : "unknown",
							watch ? watch->path : "unknown");
				if (!monitor_add(monitor, new_watchrefs[i], false)) {
					log_message(WARNING, "Failed to add watch for %s", watch ? watch->path : "unknown");
				}
			}
		}
		free(new_watchrefs);
	}

	/* Close old kqueue (now that new one is active) */
	if (old_kq >= 0) {
		close(old_kq);
	}

	/* Cleanup old resources */
	resources_destroy(old_resources);
	queue_destroy(old_check_queue);
	mapper_destroy(old_mapper);

	/* Retire the old watchers and config to the graveyard */
	if (stale_count > 0 || old_config) {
		if (monitor->graveyard.stale_watches || monitor->graveyard.old_config) {
			/* If there's an old graveyard, clean it up now to make way for the new one */
			log_message(DEBUG, "Immediate cleanup of previous graveyard to accommodate new one");
			monitor_graveyard(monitor);
		}
		monitor->graveyard.stale_watches = stale_watches;
		monitor->graveyard.num_stale = stale_count;
		monitor->graveyard.old_config = old_config;
		monitor->graveyard.retirement_time = time(NULL) + GRAVEYARD_SECONDS;
		log_message(DEBUG, "Retired %d watchers and old config to graveyard", stale_count);
	}

	/* Perform garbage collection and destroy old registry */
	if (old_registry) {
		registry_garbage(old_registry);
		registry_destroy(old_registry);
		log_message(DEBUG, "Performed garbage collection and destroyed old registry during reload");
	}

	/* Log successful atomic reload */
	if (cleared_count > 0) {
		log_message(DEBUG, "Cleared %d delayed events during config reload", cleared_count);
	}

	/* After reloading, explicitly validate the config file watch to handle editor atomic saves */
	monitor_sync(monitor, monitor->config_path);

	int reload_trackers = tracker_counter(monitor);
	if (reload_trackers > 0) {
		log_message(INFO, "Configuration reload complete: %d watches, %d tracked files",
					monitor->num_watches, reload_trackers);
	} else {
		log_message(INFO, "Configuration reload complete: %d watches", monitor->num_watches);
	}
	return true;
}

/* Remove all watches for subdirectories of a given parent path */
bool monitor_prune(monitor_t *monitor, const char *parent) {
	if (!monitor || !parent) return false;

	int parent_len = strlen(parent);
	bool changed = false;

	for (int i = monitor->num_watches - 1; i >= 0; i--) {
		watcher_t *watcher = monitor->watches[i];
		if (!watcher || !watcher->path) continue;

		/* Check if it's a subdirectory */
		if ((int) strlen(watcher->path) > parent_len && strncmp(watcher->path, parent, parent_len) == 0 &&
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

/* Clean up stale items in the graveyard */
void monitor_graveyard(monitor_t *monitor) {
	if (!monitor || (!monitor->graveyard.stale_watches && !monitor->graveyard.old_config)) return;

	time_t now = time(NULL);
	if (now >= monitor->graveyard.retirement_time) {
		if (monitor->graveyard.stale_watches) {
			log_message(DEBUG, "Cleaning up %d stale watchers from graveyard", monitor->graveyard.num_stale);
			for (int i = 0; i < monitor->graveyard.num_stale; i++) {
				watcher_cleanup(monitor, monitor->graveyard.stale_watches[i], true);
			}
			for (int i = 0; i < monitor->graveyard.num_stale; i++) {
				free(monitor->graveyard.stale_watches[i]);
			}
			free(monitor->graveyard.stale_watches);
			monitor->graveyard.stale_watches = NULL;
			monitor->graveyard.num_stale = 0;
		}

		if (monitor->graveyard.old_config) {
			log_message(DEBUG, "Cleaning up old config from graveyard");
			config_destroy(monitor->graveyard.old_config);
			monitor->graveyard.old_config = NULL;
		}
	}
}

/* Validate a path and refresh it if it has been recreated */
bool monitor_sync(monitor_t *monitor, const char *path) {
	if (!monitor || !path) return false;

	struct stat info;
	bool path_exists = (stat(path, &info) == 0);
	bool list_modified = false;

	if (!path_exists) {
		/* Path does not exist, clean up only if it was being watched */
		if (!watcher_find(monitor, path)) {
			return false;
		}

		log_message(DEBUG, "Path deleted: %s, cleaning up watch resources", path);

		/* Clean up associated file watches from the resource's trackers */
		resource_t *resource = resource_get(monitor->resources, path, ENTITY_UNKNOWN);
		if (resource && resource->trackers) {
			log_message(DEBUG, "Cleaning up file watches for deleted directory: %s", path);
			resource_lock(resource);
			directory_cleanup(monitor, resource->trackers, path);
			resource_unlock(resource);
		}

		/* Handle pending watches that might be affected by this deletion */
		pending_delete(monitor, path);

		/* Iterate and clean up any remaining watchers for this specific path */
		for (int i = monitor->num_watches - 1; i >= 0; i--) {
			watcher_t *watcher = monitor->watches[i];
			if (!watcher || !watcher->path || strcmp(watcher->path, path) != 0) continue;

			/* Store watch config before watcher becomes invalid */
			watch_t *target_watch = registry_get(monitor->registry, watcher->watchref);
			watchref_t target_watchref = watcher->watchref;

			/* Clear any pending queued checks to prevent use-after-free */
			queue_remove(monitor->check_queue, path);

			/* Remove subdirectory watchers if this was a recursive directory */
			if (target_watch && target_watch->target == WATCH_DIRECTORY && target_watch->recursive) {
				if (monitor_prune(monitor, path)) {
					i = monitor->num_watches;
					list_modified = true;
					continue;
				}
			}

			/* Remove dynamic watch from config to prevent resurrection during reload */
			if (target_watch && target_watch->is_dynamic) {
				watch_remove(monitor->config, monitor->registry, watcher->watchref);
				i = monitor->num_watches;
				list_modified = true;
				continue;
			}

			/* Remove the watcher - destroy it and shift array elements */
			watcher_destroy(monitor, watcher, false);
			for (int j = i; j < monitor->num_watches - 1; j++) {
				monitor->watches[j] = monitor->watches[j + 1];
			}
			monitor->num_watches--;
			list_modified = true;

			/* Re-establish pending watches based on target type */
			if (!target_watch) continue;

			if (target_watch->target == WATCH_FILE) {
				log_message(DEBUG, "Re-establishing pending watch for deleted file: %s", path);
				monitor_add(monitor, target_watchref, false);
			} else if (target_watch->target == WATCH_DIRECTORY) {
				if (target_watch->is_dynamic) {
					log_message(DEBUG, "Dynamic directory watch for '%s' deleted, not be re-establishing", path);
				} else {
					log_message(DEBUG, "Re-establishing pending watch for deleted directory: %s", path);
					monitor_add(monitor, target_watchref, false);
				}
			}
		}

		return list_modified;
	}

	/* Path exists, check for recreation */
	for (int i = monitor->num_watches - 1; i >= 0; i--) {
		watcher_t *watcher = monitor->watches[i];
		if (!watcher || !watcher->path || strcmp(watcher->path, path) != 0) continue;

		/* Check if path was recreated (inode/device changed) */
		if (watcher->inode != info.st_ino || watcher->device != info.st_dev) {
			log_message(DEBUG, "Path recreated: %s, refreshing watch", path);

			/* Close old file descriptor if not shared */
			if (!watcher->shared_fd && watcher->wd >= 0) {
				close(watcher->wd);
			}

			/* Attempt to open the recreated path */
			int new_fd = open(path, O_RDONLY);
			if (new_fd == -1) {
				log_message(ERROR, "Failed to open recreated path %s: %s", path, strerror(errno));
				/* Treat as deleted - destroy watcher and shift array */
				watcher_destroy(monitor, watcher, false);
				for (int j = i; j < monitor->num_watches - 1; j++) {
					monitor->watches[j] = monitor->watches[j + 1];
				}
				monitor->num_watches--;
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
				i = monitor->num_watches;
				list_modified = true;
				continue;
			}
			list_modified = true;
		} else {
			/* Path is valid and unchanged */
			watcher->validated = time(NULL);
		}
	}

	return list_modified;
}

/* Stop the monitor by setting the running flag to false */
void monitor_stop(monitor_t *monitor) {
	if (monitor == NULL) return;

	monitor->running = false;
}

/* Activate a watch dynamically */
bool monitor_activate(monitor_t *monitor, watchref_t watchref) {
	if (!monitor || !watchref_valid(watchref)) return false;

	watch_t *watch = registry_get(monitor->registry, watchref);

	/* If watch is already active and enabled, nothing to do */
	if (watch && watch->enabled) {
		log_message(DEBUG, "Watch '%s' is already active and enabled", watch->name);
		return true;
	}

	/* Watch might be inactive, try to transition it */
	if (!watch) {
		pthread_rwlock_wrlock(&monitor->registry->lock);
		bool was_inactive = false;

		/* Defensive validation: bounds check, generation check, and state check */
		if (watchref.watch_id < monitor->registry->capacity &&
			monitor->registry->generations[watchref.watch_id] == watchref.generation &&
			monitor->registry->states[watchref.watch_id] == WATCH_STATE_INACTIVE) {

			monitor->registry->states[watchref.watch_id] = WATCH_STATE_ACTIVE;
			monitor->registry->count++;
			was_inactive = true;

			log_message(DEBUG, "Transitioned watch (watch_id=%u, gen=%u) from INACTIVE to ACTIVE",
						watchref.watch_id, watchref.generation);
		}
		pthread_rwlock_unlock(&monitor->registry->lock);

		/* Invalid reference, neither inactive nor active */
		if (!was_inactive) {
			log_message(WARNING, "Cannot activate watch, invalid reference (watch_id=%u, gen=%u)",
						watchref.watch_id, watchref.generation);
			return false;
		}

		/* Get the watch again now that it's active */
		watch = registry_get(monitor->registry, watchref);
		if (!watch) {
			log_message(ERROR, "Watch reference became invalid after state transition");
			return false;
		}
	}

	/* Valid and active watch that is currently disabled */
	watch->enabled = true;

	/* Use the existing monitor_add function to set up monitoring */
	if (!monitor_add(monitor, watchref, false)) {
		log_message(ERROR, "Failed to set up monitoring for watch %s", watch->name ? watch->name : "unknown");
		/* Rollback enabled flag on failure */
		watch->enabled = false;
		return false;
	}

	log_message(INFO, "Watch %s activated successfully", watch->name ? watch->name : "unknown");
	return true;
}

/* Disable a watch dynamically (preserves for re-enabling) */
bool monitor_disable(monitor_t *monitor, watchref_t watchref) {
	if (!monitor || !watchref_valid(watchref)) return false;

	/* Get the watch from the registry */
	watch_t *watch = registry_get(monitor->registry, watchref);
	if (!watch) {
		log_message(WARNING, "Cannot disable watch, reference not found in registry");
		return false;
	}

	/* Set the watch as disabled */
	watch->enabled = false;

	/* Clean up file trackers if this watch monitors file content */
	if (((watch->filter & EVENT_CONTENT) || watch->filter == EVENT_ALL) && watch->path) {
		resource_t *resource = resource_get(monitor->resources, watch->path, ENTITY_DIRECTORY);
		if (resource && resource->trackers) {
			log_message(DEBUG, "Cleaning up file trackers for disabled watch: %s", watch->path);
			resource_lock(resource);
			tracker_purge(monitor, resource->trackers, watchref);
			resource_unlock(resource);
		}
	}

	/* Clean up directory watchers associated with this watch */
	for (int i = monitor->num_watches - 1; i >= 0; i--) {
		watcher_t *watcher = monitor->watches[i];
		if (watcher && watchref_equal(watcher->watchref, watchref)) {
			log_message(DEBUG, "Removing watcher for disabled watch: %s (fd=%d)",
						watcher->path, watcher->wd);

			/* Remove the watcher from the array and destroy it */
			watcher_destroy(monitor, watcher, false);

			/* Shift remaining watchers down */
			for (int j = i; j < monitor->num_watches - 1; j++) {
				monitor->watches[j] = monitor->watches[j + 1];
			}
			monitor->num_watches--;
		}
	}

	log_message(INFO, "Watch %s disabled successfully", watch->name ? watch->name : "unknown");
	return true;
}
