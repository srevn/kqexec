#include "tracker.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config.h"
#include "logger.h"
#include "mapper.h"
#include "monitor.h"
#include "registry.h"
#include "resource.h"

/* Create file tracker registry */
trackers_t *trackers_create(size_t bucket_count) {
	if (bucket_count == 0) bucket_count = 256;

	trackers_t *registry = calloc(1, sizeof(trackers_t));
	if (!registry) {
		log_message(ERROR, "Failed to allocate file tracker registry");
		return NULL;
	}

	registry->buckets = calloc(bucket_count, sizeof(tracker_t *));
	if (!registry->buckets) {
		log_message(ERROR, "Failed to allocate file tracker registry buckets");
		free(registry);
		return NULL;
	}

	registry->bucket_count = bucket_count;
	registry->total_count = 0;
	registry->last_cleanup = time(NULL);

	log_message(DEBUG, "Created file tracker registry with %zu buckets", bucket_count);
	return registry;
}

/* Destroy file tracker registry and all its resources */
void trackers_destroy(trackers_t *registry) {
	if (!registry) return;

	for (size_t bucket_index = 0; bucket_index < registry->bucket_count; bucket_index++) {
		tracker_t *current_tracker = registry->buckets[bucket_index];
		while (current_tracker) {
			tracker_t *next_tracker = current_tracker->next;

			if (current_tracker->fd >= 0) {
				close(current_tracker->fd);
			}
			free(current_tracker->path);
			free(current_tracker->watchrefs);
			free(current_tracker);

			current_tracker = next_tracker;
		}
	}

	free(registry->buckets);
	free(registry);
}

/* Hash function for file paths */
unsigned int tracker_hash(const char *path, size_t bucket_count) {
	if (!path || bucket_count == 0) return 0;

	unsigned int hash = 5381;
	const char *c = path;
	while (*c) {
		hash = ((hash << 5) + hash) + *c++;
	}
	return hash % bucket_count;
}

/* Find file tracker by path */
tracker_t *tracker_find(trackers_t *registry, const char *file_path) {
	if (!registry || !file_path) return NULL;

	unsigned int bucket = tracker_hash(file_path, registry->bucket_count);
	tracker_t *tracker = registry->buckets[bucket];

	while (tracker) {
		if (strcmp(tracker->path, file_path) == 0) {
			return tracker;
		}
		tracker = tracker->next;
	}

	return NULL;
}

/* Remove a tracker from the registry hash table */
static bool tracker_remove(monitor_t *monitor, trackers_t *registry, tracker_t *target_tracker) {
	if (!registry || !target_tracker || !target_tracker->path) return false;

	unsigned int bucket = tracker_hash(target_tracker->path, registry->bucket_count);
	tracker_t *tracker = registry->buckets[bucket];
	tracker_t *previous_tracker = NULL;

	while (tracker) {
		if (tracker == target_tracker) {
			/* Remove from list */
			if (previous_tracker) {
				previous_tracker->next = tracker->next;
			} else {
				registry->buckets[bucket] = tracker->next;
			}

			/* Remove from fd mapping */
			if (tracker->fd >= 0) {
				mapper_remove_tracker(monitor->mapper, tracker->fd);
				close(tracker->fd);
			}

			/* Free memory */
			free(tracker->path);
			free(tracker->watchrefs);
			free(tracker);

			registry->total_count--;

			log_message(DEBUG, "Removed stale file tracker from registry (total: %d)",
						registry->total_count);
			return true;
		}
		previous_tracker = tracker;
		tracker = tracker->next;
	}

	return false;
}

/* Validate file tracker structure */
bool tracker_valid(const tracker_t *tracker) {
	return tracker && tracker->magic == TRACKER_MAGIC;
}

/* Check if a file should be monitored based on watch configuration */
bool tracker_monitor(const watch_t *watch, const char *file_path) {
	if (!watch || !file_path) return false;

	/* Check if content events are requested */
	if (!((watch->filter & EVENT_CONTENT) || watch->filter == EVENT_ALL)) return false;

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

/* Register file tracker with kqueue using one-shot */
bool tracker_register(monitor_t *monitor, tracker_t *tracker) {
	if (!monitor || !tracker || tracker->num_watchrefs == 0) return false;

	/* Consolidate event filters from all watches on this file */
	u_int fflags = 0;
	for (int watchref_index = 0; watchref_index < tracker->num_watchrefs; watchref_index++) {
		watch_t *watch = registry_get(monitor->registry, tracker->watchrefs[watchref_index]);
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
	EV_SET(&change, tracker->fd, EVFILT_VNODE, EV_ADD | EV_ONESHOT, fflags, 0, tracker);

	if (kevent(monitor->kq, &change, 1, NULL, 0, NULL) == -1) {
		log_message(ERROR, "Failed to register file tracker for %s: %s",
					tracker->path, strerror(errno));
		return false;
	}

	tracker->tracker_state = TRACKER_ACTIVE;
	log_message(DEBUG, "Registered one-shot file tracker for %s (fd %d)",
				tracker->path, tracker->fd);

	return true;
}

/* Re-register file tracker after one-shot event */
bool tracker_reregister(monitor_t *monitor, tracker_t *tracker) {
	if (!monitor || !tracker) return false;

	/* Validate the file still exists and hasn't changed */
	struct stat info;
	if (fstat(tracker->fd, &info) == -1) {
		log_message(DEBUG, "File descriptor invalid for %s, removing watch", tracker->path);
		return false;
	}

	/* Check if file identity changed */
	if (info.st_ino != tracker->inode || info.st_dev != tracker->device) {
		log_message(DEBUG, "File identity changed for %s, removing watch", tracker->path);
		return false;
	}

	/* Re-register with kqueue */
	if (!tracker_register(monitor, tracker)) {
		return false;
	}

	log_message(DEBUG, "Re-registered file tracker for %s", tracker->path);
	return true;
}

/* Add new file tracker */
bool tracker_add(monitor_t *monitor, resource_t *resource, const char *file_path, watchref_t watchref) {
	if (!monitor || !resource || !resource->trackers || !file_path) return false;

	trackers_t *registry = resource->trackers;

	/* Check if already monitoring this file */
	tracker_t *tracker = tracker_find(registry, file_path);
	if (tracker) {
		/* Validate that the existing tracker is still valid for the current file */
		struct stat current_file_info;
		if (stat(file_path, &current_file_info) == -1) {
			if (errno != ENOENT) {
				log_message(WARNING, "Failed to stat file %s: %s", file_path, strerror(errno));
			}
			/* File doesn't exist, remove stale tracker */
			tracker_remove(monitor, registry, tracker);
			return false;
		}

		/* Check if the file identity has changed */
		if (tracker->inode != current_file_info.st_ino || tracker->device != current_file_info.st_dev) {
			log_message(DEBUG, "File %s was atomically replaced (inode %llu->%llu)", file_path,
						tracker->inode, current_file_info.st_ino);
			tracker_remove(monitor, registry, tracker);
			/* Continue to create a new tracker for the new file */
		} else {
			/* File is still the same, check if already associated with this watch */
			for (int watchref_index = 0; watchref_index < tracker->num_watchrefs; watchref_index++) {
				if (watchref_equal(tracker->watchrefs[watchref_index], watchref)) {
					return true; /* Already associated with this watch */
				}
			}

			/* Add new watchref to the existing tracker */
			if (tracker->num_watchrefs >= tracker->watchrefs_capacity) {
				int new_cap = tracker->watchrefs_capacity == 0 ? 2 : tracker->watchrefs_capacity * 2;
				watchref_t *new_refs = realloc(tracker->watchrefs, new_cap * sizeof(watchref_t));
				if (!new_refs) {
					log_message(ERROR, "Failed to realloc watchrefs for %s", file_path);
					return false;
				}
				tracker->watchrefs = new_refs;
				tracker->watchrefs_capacity = new_cap;
			}
			tracker->watchrefs[tracker->num_watchrefs++] = watchref;

			/* Re-register with kqueue to update event filters based on all watchrefs */
			if (!tracker_reregister(monitor, tracker)) {
				log_message(ERROR, "Failed to re-register kqueue watch for %s", file_path);
				/* Rollback the watchref addition */
				tracker->num_watchrefs--;
				return false;
			}

			log_message(DEBUG, "Associated new watch with existing file tracker for %s", file_path);
			return true;
		}
	}

	/* Check if we've hit the per-directory limit */
	if (registry->total_count >= MAX_TRACKER_PER_DIR) {
		log_message(WARNING, "File tracker limit reached, not adding tracker for %s", file_path);
		return false;
	}

	/* Open file for monitoring */
	int fd = open(file_path, O_RDONLY);
	if (fd == -1) {
		if (errno != ENOENT) {
			log_message(WARNING, "Failed to open file for tracking %s: %s",
						file_path, strerror(errno));
		}
		return false;
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

	/* Create file tracker */
	tracker_t *new_tracker = calloc(1, sizeof(tracker_t));
	if (!new_tracker) {
		log_message(ERROR, "Failed to allocate file tracker for %s", file_path);
		close(fd);
		return false;
	}

	new_tracker->path = strdup(file_path);
	if (!new_tracker->path) {
		log_message(ERROR, "Failed to duplicate path for file tracker: %s", file_path);
		free(new_tracker);
		close(fd);
		return false;
	}

	new_tracker->magic = TRACKER_MAGIC;
	new_tracker->fd = fd;
	new_tracker->tracker_state = TRACKER_ACTIVE;
	new_tracker->last_event = time(NULL);
	new_tracker->created = time(NULL);
	new_tracker->inode = info.st_ino;
	new_tracker->device = info.st_dev;

	new_tracker->watchrefs = calloc(2, sizeof(watchref_t));
	if (!new_tracker->watchrefs) {
		log_message(ERROR, "Failed to allocate watchrefs for %s", file_path);
		free(new_tracker->path);
		free(new_tracker);
		close(fd);
		return false;
	}
	new_tracker->watchrefs[0] = watchref;
	new_tracker->num_watchrefs = 1;
	new_tracker->watchrefs_capacity = 2;

	/* Register with kqueue */
	if (!tracker_register(monitor, new_tracker)) {
		free(new_tracker->path);
		free(new_tracker);
		close(fd);
		return false;
	}

	/* Add to registry */
	unsigned int bucket = tracker_hash(file_path, registry->bucket_count);
	new_tracker->next = registry->buckets[bucket];
	registry->buckets[bucket] = new_tracker;

	/* Add to the central mapper */
	if (!mapper_add_tracker(monitor->mapper, fd, new_tracker)) {
		log_message(WARNING, "Failed to add tracker for %s (fd: %d) to mapper", file_path, fd);
		/* Cleanup logic might be needed here if this fails */
	}

	registry->total_count++;

	log_message(DEBUG, "Added file tracker for %s (fd: %d, total: %d)",
				file_path, fd, registry->total_count);
	return true;
}

/* Handle file tracker events */
bool tracker_handle(monitor_t *monitor, tracker_t *tracker, struct kevent *event, struct timespec *time) {
	if (!monitor || !tracker || !event || !time) return false;

	/* Validate the tracker */
	if (!tracker_valid(tracker)) {
		log_message(ERROR, "Invalid file tracker in event handling");
		return false;
	}

	char *parent_path = strdup(tracker->path);
	if (!parent_path) {
		log_message(ERROR, "Failed to duplicate path for locking in tracker_handle");
		return false;
	}
	char *last_slash = strrchr(parent_path, '/');
	if (last_slash && last_slash != parent_path) {
		*last_slash = '\0';
	} else if (last_slash) {
		*(last_slash + 1) = '\0';
	} else {
		free(parent_path);
		log_message(ERROR, "Could not determine parent path for tracker %s", tracker->path);
		return false;
	}

	resource_t *resource = resource_get(monitor->resources, parent_path, ENTITY_DIRECTORY);
	free(parent_path);

	if (!resource) {
		log_message(WARNING, "Could not find parent resource for tracker %s, marking for cleanup", tracker->path);
		tracker->tracker_state = TRACKER_PENDING_CLEANUP;
		return false;
	}

	resource_lock(resource);

	/* Check if file should still be monitored */
	bool still_wanted = false;
	for (int watchref_index = 0; watchref_index < tracker->num_watchrefs; watchref_index++) {
		watch_t *watch = registry_get(monitor->registry, tracker->watchrefs[watchref_index]);
		if (watch && tracker_monitor(watch, tracker->path)) {
			still_wanted = true;
			break;
		}
	}

	if (!still_wanted) {
		log_message(DEBUG, "File %s is now excluded by all watches, removing from monitoring", tracker->path);
		tracker->tracker_state = TRACKER_PENDING_CLEANUP;
		resource_unlock(resource);
		return false; /* Don't process excluded file events */
	}

	/* Update last event time */
	tracker->last_event = time->tv_sec;

	/* Mark as needing re-registration since this was a one-shot event */
	tracker->tracker_state = TRACKER_ONESHOT_FIRED;

	log_message(DEBUG, "File tracker event for %s (flags: 0x%x)", tracker->path, event->fflags);

	resource_unlock(resource);

	return true;
}

/* Scan directory for files to monitor */
bool tracker_scan(monitor_t *monitor, resource_t *resource, watchref_t watchref, const watch_t *watch) {
	if (!monitor || !resource || !watch) return false;

	const char *dir_path = resource->path;

	/* Only scan if file content monitoring is enabled */
	if (!((watch->filter & EVENT_CONTENT) || watch->filter == EVENT_ALL)) return true;

	DIR *dir = opendir(dir_path);
	if (!dir) {
		log_message(WARNING, "Failed to open directory for file scan %s: %s",
					dir_path, strerror(errno));
		return false;
	}

	struct dirent *dirent;
	int added_count = 0;

	while ((dirent = readdir(dir)) != NULL) {
		/* Skip . and .. */
		if (strcmp(dirent->d_name, ".") == 0 || strcmp(dirent->d_name, "..") == 0) {
			continue;
		}

		char file_path[1024];
		int path_len = snprintf(file_path, sizeof(file_path), "%s/%s", dir_path, dirent->d_name);

		if (path_len >= (int) sizeof(file_path)) {
			log_message(WARNING, "Path too long, skipping: %s/%s", dir_path, dirent->d_name);
			continue;
		}

		/* Check if this file should be monitored */
		if (!tracker_monitor(watch, file_path)) {
			continue;
		}

		/* Check if it's a regular file */
		struct stat info;
		if (stat(file_path, &info) == -1) {
			continue;
		}

		if (S_ISREG(info.st_mode)) {
			if (tracker_add(monitor, resource, file_path, watchref)) {
				added_count++;
			}
		}
	}

	closedir(dir);

	if (added_count > 0) {
		log_message(DEBUG, "Added %d file trackers in directory %s", added_count, dir_path);
	}

	return true;
}

/* Clean up idle file trackers */
void tracker_cleanup(monitor_t *monitor, trackers_t *registry) {
	if (!registry) return;

	time_t now = time(NULL);

	/* Only cleanup periodically */
	if (now - registry->last_cleanup < TRACKER_CLEANUP_INTERVAL) {
		return;
	}

	int removed_count = 0;

	for (size_t bucket_index = 0; bucket_index < registry->bucket_count; bucket_index++) {
		tracker_t *tracker = registry->buckets[bucket_index];
		tracker_t *previous_tracker = NULL;

		while (tracker) {
			tracker_t *next_tracker = tracker->next;
			bool should_remove = false;

			/* Do not clean up trackers that are pending re-registration */
			if (tracker->tracker_state == TRACKER_ONESHOT_FIRED) {
				previous_tracker = tracker;
				tracker = next_tracker;
				continue;
			}

			/* Remove idle trackers */
			if (now - tracker->last_event > TRACKER_IDLE_TIMEOUT) {
				should_remove = true;
			}

			/* Remove trackers marked for cleanup */
			if (tracker->tracker_state == TRACKER_PENDING_CLEANUP) {
				should_remove = true;
			}

			if (should_remove) {
				/* Remove from list */
				if (previous_tracker) {
					previous_tracker->next = next_tracker;
				} else {
					registry->buckets[bucket_index] = next_tracker;
				}

				/* Remove from fd mapping */
				if (tracker->fd >= 0) {
					mapper_remove_tracker(monitor->mapper, tracker->fd);
					close(tracker->fd);
				}

				/* Free memory */
				free(tracker->path);
				free(tracker->watchrefs);
				free(tracker);

				registry->total_count--;
				removed_count++;
			} else {
				/* tracker will be re-registered after stability */
				previous_tracker = tracker;
			}

			tracker = next_tracker;
		}
	}

	registry->last_cleanup = now;

	if (removed_count > 0) {
		log_message(DEBUG, "Cleaned up %d idle file trackers (total: %d)",
					removed_count, registry->total_count);
	}
}

/* Clean up file trackers in a specific directory */
void directory_cleanup(monitor_t *monitor, trackers_t *registry, const char *dir_path) {
	if (!registry || !dir_path) return;

	int removed_count = 0;

	for (size_t bucket_index = 0; bucket_index < registry->bucket_count; bucket_index++) {
		tracker_t *tracker = registry->buckets[bucket_index];
		tracker_t *previous_tracker = NULL;

		while (tracker) {
			tracker_t *next_tracker = tracker->next;

			/* Remove from list */
			if (previous_tracker) {
				previous_tracker->next = next_tracker;
			} else {
				registry->buckets[bucket_index] = next_tracker;
			}

			/* Remove from fd mapping */
			if (tracker->fd >= 0) {
				mapper_remove_tracker(monitor->mapper, tracker->fd);
				close(tracker->fd);
			}

			/* Free memory */
			free(tracker->path);
			free(tracker->watchrefs);
			free(tracker);

			registry->total_count--;
			removed_count++;

			tracker = next_tracker;
		}
	}

	if (removed_count > 0) {
		log_message(DEBUG, "Removed %d file trackers from directory %s", removed_count, dir_path);
	}
}

/* Re-register fired file trackers for a directory after stability */
void directory_reregister(monitor_t *monitor, resource_t *resource) {
	if (!monitor || !resource || !resource->trackers) return;

	resource_lock(resource);

	trackers_t *registry = resource->trackers;
	const char *dir_path = resource->path;
	int reregistered_count = 0;

	for (size_t bucket_index = 0; bucket_index < registry->bucket_count; bucket_index++) {
		tracker_t *tracker = registry->buckets[bucket_index];

		while (tracker) {
			/* Check if this file needs re-registration */
			if (tracker->tracker_state == TRACKER_ONESHOT_FIRED) {
				/* Re-register with kqueue */
				if (tracker_reregister(monitor, tracker)) {
					tracker->tracker_state = TRACKER_ACTIVE;
					reregistered_count++;
				} else {
					/* If re-registration fails, mark for cleanup */
					tracker->tracker_state = TRACKER_PENDING_CLEANUP;
				}
			}

			tracker = tracker->next;
		}
	}

	if (reregistered_count > 0) {
		log_message(DEBUG, "Re-registered %d file trackers for stable directory %s",
					reregistered_count, dir_path);
	}

	resource_unlock(resource);
}

/* Get total tracked files across all resources */
int tracker_counter(monitor_t *monitor) {
	int total = 0;
	if (monitor->resources && monitor->resources->buckets) {
		for (size_t i = 0; i < monitor->resources->bucket_count; i++) {
			resource_t *resource = monitor->resources->buckets[i];
			while (resource) {
				if (resource->trackers) {
					total += resource->trackers->total_count;
				}
				resource = resource->next;
			}
		}
	}
	return total;
}
