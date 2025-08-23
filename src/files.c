#include "files.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config.h"
#include "logger.h"
#include "monitor.h"
#include "registry.h"
#include "resource.h"

/* Create file watch registry */
fregistry_t *fregistry_create(size_t bucket_count) {
	if (bucket_count == 0) bucket_count = 256;

	fregistry_t *registry = calloc(1, sizeof(fregistry_t));
	if (!registry) {
		log_message(ERROR, "Failed to allocate file watch registry");
		return NULL;
	}

	registry->buckets = calloc(bucket_count, sizeof(fwatcher_t *));
	if (!registry->buckets) {
		log_message(ERROR, "Failed to allocate file watch registry buckets");
		free(registry);
		return NULL;
	}

	/* Initialize FD mapping with reasonable initial size */
	registry->fd_map_size = 1024;
	registry->fd_map = calloc(registry->fd_map_size, sizeof(fwatcher_t *));
	if (!registry->fd_map) {
		log_message(ERROR, "Failed to allocate file watch fd map");
		free(registry->buckets);
		free(registry);
		return NULL;
	}

	registry->bucket_count = bucket_count;
	registry->total_count = 0;
	registry->last_cleanup = time(NULL);

	log_message(DEBUG, "Created file watch registry with %zu buckets and %d fd slots",
				bucket_count, registry->fd_map_size);
	return registry;
}

/* Destroy file watch registry */
void fregistry_destroy(fregistry_t *registry) {
	if (!registry) return;

	for (size_t i = 0; i < registry->bucket_count; i++) {
		fwatcher_t *watcher = registry->buckets[i];
		while (watcher) {
			fwatcher_t *next = watcher->next;

			if (watcher->fd >= 0) {
				close(watcher->fd);
			}
			free(watcher->path);
			free(watcher);

			watcher = next;
		}
	}

	free(registry->buckets);
	free(registry->fd_map);
	free(registry);

	log_message(DEBUG, "Destroyed file watch registry");
}

/* Hash function for file paths */
unsigned int files_hash(const char *path, size_t bucket_count) {
	if (!path || bucket_count == 0) return 0;

	unsigned int hash = 5381;
	const char *c = path;
	while (*c) {
		hash = ((hash << 5) + hash) + *c++;
	}
	return hash % bucket_count;
}

/* Find file watcher by path */
fwatcher_t *files_find(fregistry_t *registry, const char *file_path) {
	if (!registry || !file_path) return NULL;

	unsigned int bucket = files_hash(file_path, registry->bucket_count);
	fwatcher_t *watcher = registry->buckets[bucket];

	while (watcher) {
		if (strcmp(watcher->path, file_path) == 0) {
			return watcher;
		}
		watcher = watcher->next;
	}

	return NULL;
}

/* Find file watcher by file descriptor */
fwatcher_t *files_find_by_fd(fregistry_t *registry, int fd) {
	if (!registry || fd < 0 || fd >= registry->fd_map_size) {
		return NULL;
	}

	return registry->fd_map[fd];
}

/* Validate file watcher structure */
bool fwatcher_valid(const fwatcher_t *watcher) {
	return watcher && watcher->magic == FWATCHER_MAGIC;
}

/* Check if a file should be monitored based on watch configuration */
bool files_monitor(const watch_t *watch, const char *file_path) {
	if (!watch || !file_path) return false;

	/* Check if content events are requested */
	if (!(watch->filter & EVENT_CONTENT)) return false;

	/* Check exclusion patterns */
	if (config_exclude_match(watch, file_path)) return false;

	/* Check hidden file policy */
	if (!watch->hidden) {
		const char *basename = strrchr(file_path, '/');
		basename = basename ? basename + 1 : file_path;
		if (basename[0] == '.') return false;
	}

	return true;
}

/* Register file watcher with kqueue using one-shot */
bool files_register(monitor_t *monitor, fwatcher_t *fwatcher) {
	if (!monitor || !fwatcher || fwatcher->num_watchrefs == 0) return false;

	/* Consolidate event filters from ALL watches on this file */
	u_int fflags = 0;
	for (int i = 0; i < fwatcher->num_watchrefs; i++) {
		watch_t *watch = registry_get(monitor->registry, fwatcher->watchrefs[i]);
		if (!watch) continue;

		if (watch->filter & EVENT_CONTENT) {
			fflags |= NOTE_DELETE | NOTE_WRITE | NOTE_RENAME | NOTE_REVOKE;
		}
		if (watch->filter & EVENT_METADATA) {
			fflags |= NOTE_ATTRIB | NOTE_LINK;
		}
	}

	/* Use EV_ONESHOT to automatically remove the watch after the first event */
	struct kevent change;
	EV_SET(&change, fwatcher->fd, EVFILT_VNODE, EV_ADD | EV_ONESHOT, fflags, 0, fwatcher);

	if (kevent(monitor->kq, &change, 1, NULL, 0, NULL) == -1) {
		log_message(ERROR, "Failed to register file watch for %s: %s",
					fwatcher->path, strerror(errno));
		return false;
	}

	fwatcher->state = FILES_ACTIVE;
	log_message(DEBUG, "Registered one-shot file watch for %s (fd %d)",
				fwatcher->path, fwatcher->fd);

	return true;
}

/* Re-register file watcher after one-shot event */
bool files_reregister(monitor_t *monitor, fwatcher_t *fwatcher) {
	if (!monitor || !fwatcher) return false;

	/* Validate the file still exists and hasn't changed */
	struct stat info;
	if (fstat(fwatcher->fd, &info) == -1) {
		log_message(DEBUG, "File descriptor invalid for %s, removing watch", fwatcher->path);
		return false;
	}

	/* Check if file identity changed */
	if (info.st_ino != fwatcher->inode || info.st_dev != fwatcher->device) {
		log_message(DEBUG, "File identity changed for %s, removing watch", fwatcher->path);
		return false;
	}

	/* Re-register with kqueue */
	if (!files_register(monitor, fwatcher)) {
		return false;
	}

	log_message(DEBUG, "Re-registered file watch for %s", fwatcher->path);
	return true;
}

/* Add new file watcher */
bool files_add(monitor_t *monitor, resource_t *resource, const char *file_path, watchref_t watchref) {
	if (!monitor || !resource || !resource->fregistry || !file_path) return false;

	fregistry_t *registry = resource->fregistry;

	/* Check if already monitoring this file */
	fwatcher_t *watcher = files_find(registry, file_path);
	if (watcher) {
		/* File is already watched, just add our watchref to it */
		for (int i = 0; i < watcher->num_watchrefs; i++) {
			if (watchref_equal(watcher->watchrefs[i], watchref)) {
				return true; /* Already associated with this watch */
			}
		}

		/* Add new watchref to the existing fwatcher */
		if (watcher->num_watchrefs >= watcher->cap_watchrefs) {
			int new_cap = watcher->cap_watchrefs == 0 ? 2 : watcher->cap_watchrefs * 2;
			watchref_t *new_refs = realloc(watcher->watchrefs, new_cap * sizeof(watchref_t));
			if (!new_refs) {
				log_message(ERROR, "Failed to realloc watchrefs for %s", file_path);
				return false;
			}
			watcher->watchrefs = new_refs;
			watcher->cap_watchrefs = new_cap;
		}
		watcher->watchrefs[watcher->num_watchrefs++] = watchref;
		log_message(DEBUG, "Associated new watch with existing file watch for %s", file_path);
		return true;
	}

	/* Check if we've hit the per-directory limit */
	if (registry->total_count >= MAX_FILES_PER_DIR) {
		log_message(WARNING, "File watch limit reached, not adding watch for %s", file_path);
		return false;
	}

	/* Open file for monitoring */
	int fd = open(file_path, O_RDONLY);
	if (fd == -1) {
		if (errno != ENOENT) {
			log_message(WARNING, "Failed to open file for watching %s: %s",
						file_path, strerror(errno));
		}
		return false;
	}

	/* Ensure fd_map is large enough to hold the new file descriptor */
	if (fd >= registry->fd_map_size) {
		int new_size = fd + 256; /* Grow by a margin to avoid frequent reallocs */
		fwatcher_t **new_map = realloc(registry->fd_map, new_size * sizeof(fwatcher_t *));
		if (!new_map) {
			log_message(ERROR, "Failed to resize fd_map to %d. Cannot add watch for %s", new_size, file_path);
			close(fd);
			return false;
		}
		/* Zero out the newly allocated portion of the map */
		memset(new_map + registry->fd_map_size, 0, (new_size - registry->fd_map_size) * sizeof(fwatcher_t *));
		registry->fd_map = new_map;
		registry->fd_map_size = new_size;
		log_message(DEBUG, "Resized file watch fd_map to %d", new_size);
	}

	/* Get file identity */
	struct stat info;
	if (fstat(fd, &info) == -1) {
		log_message(WARNING, "Failed to stat file %s: %s", file_path, strerror(errno));
		close(fd);
		return false;
	}

	/* Only monitor regular files */
	if (!S_ISREG(info.st_mode)) {
		close(fd);
		return false;
	}

	/* Create file watcher */
	fwatcher_t *new_watcher = calloc(1, sizeof(fwatcher_t));
	if (!new_watcher) {
		log_message(ERROR, "Failed to allocate file watcher for %s", file_path);
		close(fd);
		return false;
	}

	new_watcher->path = strdup(file_path);
	if (!new_watcher->path) {
		log_message(ERROR, "Failed to duplicate path for file watcher: %s", file_path);
		free(new_watcher);
		close(fd);
		return false;
	}

	new_watcher->magic = FWATCHER_MAGIC;
	new_watcher->fd = fd;
	new_watcher->state = FILES_ACTIVE;
	new_watcher->last_event = time(NULL);
	new_watcher->created = time(NULL);
	new_watcher->inode = info.st_ino;
	new_watcher->device = info.st_dev;

	new_watcher->watchrefs = calloc(2, sizeof(watchref_t));
	if (!new_watcher->watchrefs) {
		log_message(ERROR, "Failed to allocate watchrefs for %s", file_path);
		free(new_watcher->path);
		free(new_watcher);
		close(fd);
		return false;
	}
	new_watcher->watchrefs[0] = watchref;
	new_watcher->num_watchrefs = 1;
	new_watcher->cap_watchrefs = 2;

	/* Register with kqueue */
	if (!files_register(monitor, new_watcher)) {
		free(new_watcher->path);
		free(new_watcher);
		close(fd);
		return false;
	}

	/* Add to registry */
	unsigned int bucket = files_hash(file_path, registry->bucket_count);
	new_watcher->next = registry->buckets[bucket];
	registry->buckets[bucket] = new_watcher;

	/* Add to fd mapping if fd is in range */
	if (fd >= 0 && fd < registry->fd_map_size) {
		registry->fd_map[fd] = new_watcher;
	} else {
		log_message(WARNING, "File descriptor %d out of range for registry fd map (size: %d)",
					fd, registry->fd_map_size);
	}

	registry->total_count++;

	log_message(DEBUG, "Added file watch for %s (fd: %d, total: %d)",
				file_path, fd, registry->total_count);
	return true;
}


/* Handle file watch events */
bool files_handle(monitor_t *monitor, fwatcher_t *watcher, struct kevent *event, struct timespec *time) {
	if (!monitor || !watcher || !event || !time) return false;

	/* Validate the watcher */
	if (!fwatcher_valid(watcher)) {
		log_message(ERROR, "Invalid file watcher in event handling");
		return false;
	}

	/* Check if file should still be monitored (exclude patterns may have changed) */
	/* A file should continue being monitored if at least one watch still wants it */
	bool still_wanted = false;
	for (int i = 0; i < watcher->num_watchrefs; i++) {
		watch_t *watch = registry_get(monitor->registry, watcher->watchrefs[i]);
		if (watch && files_monitor(watch, watcher->path)) {
			still_wanted = true;
			break;
		}
	}
	
	if (!still_wanted) {
		log_message(DEBUG, "File %s is now excluded by all watches, removing from monitoring", watcher->path);
		watcher->state = FILES_PENDING_CLEANUP;
		return false; /* Don't process excluded file events */
	}

	/* Update last event time */
	watcher->last_event = time->tv_sec;

	/* Mark as needing re-registration since this was a one-shot event */
	watcher->state = FILES_ONESHOT_FIRED;

	log_message(DEBUG, "File watch event for %s (flags: 0x%x)", watcher->path, event->fflags);

	return true;
}

/* Scan directory for files to monitor */
bool files_scan(monitor_t *monitor, resource_t *resource, watchref_t watchref, const watch_t *watch) {
	if (!monitor || !resource || !watch) return false;

	const char *dir_path = resource->path;

	/* Only scan if file content monitoring is enabled */
	if (!(watch->filter & EVENT_CONTENT)) return true;

	DIR *dir = opendir(dir_path);
	if (!dir) {
		log_message(WARNING, "Failed to open directory for file scan %s: %s",
					dir_path, strerror(errno));
		return false;
	}

	struct dirent *entry;
	int added_count = 0;

	while ((entry = readdir(dir)) != NULL) {
		/* Skip . and .. */
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
			continue;
		}

		char file_path[1024];
		int path_len = snprintf(file_path, sizeof(file_path), "%s/%s", dir_path, entry->d_name);

		if (path_len >= (int) sizeof(file_path)) {
			log_message(WARNING, "Path too long, skipping: %s/%s", dir_path, entry->d_name);
			continue;
		}

		/* Check if this file should be monitored */
		if (!files_monitor(watch, file_path)) {
			continue;
		}

		/* Check if it's a regular file */
		struct stat info;
		if (stat(file_path, &info) == -1) {
			continue;
		}

		if (S_ISREG(info.st_mode)) {
			if (files_add(monitor, resource, file_path, watchref)) {
				added_count++;
			}
		}
	}

	closedir(dir);

	if (added_count > 0) {
		log_message(DEBUG, "Added %d file watches in directory %s", added_count, dir_path);
	}

	return true;
}

/* Clean up idle file watches */
void files_cleanup(fregistry_t *registry) {
	if (!registry) return;

	time_t now = time(NULL);

	/* Only cleanup periodically */
	if (now - registry->last_cleanup < FILES_CLEANUP_INTERVAL) {
		return;
	}

	int removed_count = 0;

	for (size_t i = 0; i < registry->bucket_count; i++) {
		fwatcher_t *watcher = registry->buckets[i];
		fwatcher_t *prev = NULL;

		while (watcher) {
			fwatcher_t *next = watcher->next;
			bool should_remove = false;

			/* Remove idle watches */
			if (now - watcher->last_event > FILES_IDLE_TIMEOUT) {
				should_remove = true;
			}

			/* Remove watches marked for cleanup */
			if (watcher->state == FILES_PENDING_CLEANUP) {
				should_remove = true;
			}

			if (should_remove) {
				/* Remove from list */
				if (prev) {
					prev->next = next;
				} else {
					registry->buckets[i] = next;
				}

				/* Remove from fd mapping */
				if (watcher->fd >= 0 && watcher->fd < registry->fd_map_size) {
					registry->fd_map[watcher->fd] = NULL;
				}

				/* Close and free */
				if (watcher->fd >= 0) {
					close(watcher->fd);
				}
				free(watcher->path);
				free(watcher);

				registry->total_count--;
				removed_count++;
			} else {
				/* Watcher will be re-registered after stability */
				prev = watcher;
			}

			watcher = next;
		}
	}

	registry->last_cleanup = now;

	if (removed_count > 0) {
		log_message(DEBUG, "Cleaned up %d idle file watches (total: %d)",
					removed_count, registry->total_count);
	}
}

/* Clean up file watches in a specific directory */
void directory_cleanup(fregistry_t *registry, const char *dir_path) {
	if (!registry || !dir_path) return;

	size_t dir_len = strlen(dir_path);
	int removed_count = 0;

	for (size_t i = 0; i < registry->bucket_count; i++) {
		fwatcher_t *watcher = registry->buckets[i];
		fwatcher_t *prev = NULL;

		while (watcher) {
			fwatcher_t *next = watcher->next;

			/* Check if this file is within the directory */
			if (strncmp(watcher->path, dir_path, dir_len) == 0 &&
				(watcher->path[dir_len] == '/' || watcher->path[dir_len] == '\0')) {

				/* Remove from list */
				if (prev) {
					prev->next = next;
				} else {
					registry->buckets[i] = next;
				}

				/* Remove from fd mapping */
				if (watcher->fd >= 0 && watcher->fd < registry->fd_map_size) {
					registry->fd_map[watcher->fd] = NULL;
				}

				/* Close and free */
				if (watcher->fd >= 0) {
					close(watcher->fd);
				}
				free(watcher->path);
				free(watcher);

				registry->total_count--;
				removed_count++;
			} else {
				prev = watcher;
			}

			watcher = next;
		}
	}

	if (removed_count > 0) {
		log_message(DEBUG, "Removed %d file watches from directory %s", removed_count, dir_path);
	}
}

/* Re-register fired file watches for a directory after stability */
void directory_reregister(monitor_t *monitor, fregistry_t *registry, const char *dir_path) {
	if (!monitor || !registry || !dir_path) return;

	size_t dir_len = strlen(dir_path);
	int reregistered_count = 0;

	for (size_t i = 0; i < registry->bucket_count; i++) {
		fwatcher_t *watcher = registry->buckets[i];

		while (watcher) {
			/* Check if this file is within the directory and needs re-registration */
			if (strncmp(watcher->path, dir_path, dir_len) == 0 &&
				(watcher->path[dir_len] == '/' || watcher->path[dir_len] == '\0') &&
				watcher->state == FILES_ONESHOT_FIRED) {

				/* Re-register with kqueue */
				if (files_reregister(monitor, watcher)) {
					watcher->state = FILES_ACTIVE;
					reregistered_count++;
				} else {
					/* If re-registration fails, mark for cleanup */
					watcher->state = FILES_PENDING_CLEANUP;
				}
			}

			watcher = watcher->next;
		}
	}

	if (reregistered_count > 0) {
		log_message(DEBUG, "Re-registered %d file watches for stable directory %s",
					reregistered_count, dir_path);
	}
}
