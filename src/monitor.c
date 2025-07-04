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
#include "logger.h"

/* Maximum number of events to process at once */
#define MAX_EVENTS 64

/* Maximum path length */
#define MAX_PATH_LEN 1024

/* Define max allowed failures before giving up */
#define MAX_FAILED_CHECKS 3

/* Global monitor instance for integration with states.c */
monitor_t *g_current_monitor = NULL;

/* Add a watch to a queue entry */
static bool check_queue_add_watch(deferred_check_t *entry, watch_entry_t *watch) {
	if (!entry || !watch) {
		log_message(LOG_LEVEL_ERR, "Invalid parameters for check_queue_add_watch");
		return false;
	}
	
	/* Check if this watch is already in the array */
	for (int i = 0; i < entry->watch_count; i++) {
		if (entry->watches && entry->watches[i] == watch) {
			return true; /* Already present */
		}
	}
	
	/* Ensure capacity */
	if (entry->watch_count >= entry->watch_capacity) {
		int new_capacity = entry->watch_capacity == 0 ? 4 : entry->watch_capacity * 2;
		watch_entry_t **new_watches = realloc(entry->watches, 
											new_capacity * sizeof(watch_entry_t *));
		if (!new_watches) {
			log_message(LOG_LEVEL_ERR, "Failed to resize watches array in queue entry");
			return false;
		}
		entry->watches = new_watches;
		entry->watch_capacity = new_capacity;
		
		/* Zero out new memory */
		if (entry->watch_count < new_capacity) {
			memset(&entry->watches[entry->watch_count], 0, 
				  (new_capacity - entry->watch_count) * sizeof(watch_entry_t *));
		}
	}
	
	/* Add the new watch */
	entry->watches[entry->watch_count++] = watch;
	return true;
}

/* Cleanup the priority queue */
static void check_queue_cleanup(monitor_t *monitor) {
	if (!monitor || !monitor->check_queue) return;
	
	/* Free path strings and watch arrays */
	for (int i = 0; i < monitor->check_queue_size; i++) {
		if (monitor->check_queue[i].path) {
			free(monitor->check_queue[i].path);
			monitor->check_queue[i].path = NULL;
		}
		if (monitor->check_queue[i].watches) {
			free(monitor->check_queue[i].watches);
			monitor->check_queue[i].watches = NULL;
		}
		
		/* Clear the struct to prevent double-free issues */
		memset(&monitor->check_queue[i], 0, sizeof(deferred_check_t));
	}
	
	free(monitor->check_queue);
	monitor->check_queue = NULL;
	monitor->check_queue_size = 0;
	monitor->check_queue_capacity = 0;
	
	log_message(LOG_LEVEL_DEBUG, "Cleaned up deferred check queue");
}

/* Initialize the priority queue */
static void check_queue_init(monitor_t *monitor, int initial_capacity) {
	if (!monitor) {
		return;
	}
	
	if (initial_capacity < 8) initial_capacity = 8;
	
	/* Make sure we're starting with a clean state */
	if (monitor->check_queue) {
		check_queue_cleanup(monitor);
	}
	
	monitor->check_queue = NULL;
	monitor->check_queue_size = 0;
	monitor->check_queue_capacity = 0;
	
	/* Allocate memory for the queue and zero it out */
	monitor->check_queue = calloc(initial_capacity, sizeof(deferred_check_t));
	if (!monitor->check_queue) {
		log_message(LOG_LEVEL_ERR, "Failed to allocate memory for deferred check queue");
	} else {
		monitor->check_queue_capacity = initial_capacity;
		log_message(LOG_LEVEL_DEBUG, "Initialized deferred check queue with capacity %d", initial_capacity);
	}
}

/* Compare two timespec values for priority queue ordering */
static int check_queue_compare(struct timespec *a, struct timespec *b) {
	if (!a || !b) return 0; /* Handle NULL pointers */
	
	if (a->tv_sec < b->tv_sec) return -1;
	if (a->tv_sec > b->tv_sec) return 1;
	if (a->tv_nsec < b->tv_nsec) return -1;
	if (a->tv_nsec > b->tv_nsec) return 1;
	return 0;
}

/* Restore heap property upward */
static void check_queue_heapify_up(deferred_check_t *queue, int index) {
	if (!queue || index <= 0) return;
	
	int parent = (index - 1) / 2;
	
	/* Ensure both queue entries have valid paths to avoid crash */
	if (!queue[index].path || !queue[parent].path) {
		log_message(LOG_LEVEL_WARNING, "Heapify up encountered invalid path at index %d or parent %d", 
				  index, parent);
		return;
	}
	
	if (check_queue_compare(&queue[index].next_check, 
						  &queue[parent].next_check) < 0) {
		/* Swap with parent using a temporary copy */
		deferred_check_t temp;
		memcpy(&temp, &queue[index], sizeof(deferred_check_t));
		memcpy(&queue[index], &queue[parent], sizeof(deferred_check_t));
		memcpy(&queue[parent], &temp, sizeof(deferred_check_t));
		
		/* Recursively heapify up */
		check_queue_heapify_up(queue, parent);
	}
}

/* Restore heap property downward */
static void check_queue_heapify_down(deferred_check_t *queue, int size, int index) {
	if (!queue || index < 0 || size <= 0 || index >= size) {
		return;
	}
	
	int smallest = index;
	int left = 2 * index + 1;
	int right = 2 * index + 2;
	
	/* First validate that the current entry has a valid path */
	if (!queue[index].path) {
		log_message(LOG_LEVEL_WARNING, "Heapify down encountered NULL path at index %d", index);
		return;
	}
	
	/* Check left child with validation */
	if (left < size) {
		if (!queue[left].path) {
			log_message(LOG_LEVEL_WARNING, "Left child at index %d has NULL path", left);
		} else if (check_queue_compare(&queue[left].next_check, 
									 &queue[smallest].next_check) < 0) {
			smallest = left;
		}
	}
	
	/* Check right child with validation */
	if (right < size) {
		if (!queue[right].path) {
			log_message(LOG_LEVEL_WARNING, "Right child at index %d has NULL path", right);
		} else if (check_queue_compare(&queue[right].next_check, 
									  &queue[smallest].next_check) < 0) {
			smallest = right;
		}
	}
	
	if (smallest != index) {
		/* Swap with smallest child using a temporary copy to properly preserve pointers */
		deferred_check_t temp;
		memcpy(&temp, &queue[index], sizeof(deferred_check_t));
		memcpy(&queue[index], &queue[smallest], sizeof(deferred_check_t));
		memcpy(&queue[smallest], &temp, sizeof(deferred_check_t));
		
		/* Recursively heapify down */
		check_queue_heapify_down(queue, size, smallest);
	}
}

/* Find a queue entry by path */
static int check_queue_find_by_path(monitor_t *monitor, const char *path) {
	if (!monitor->check_queue) {
		return -1;
	}
	
	/* Special case for handling NULL paths */
	if (!path) {
		for (int i = 0; i < monitor->check_queue_size; i++) {
			if (!monitor->check_queue[i].path) {
				return i;  /* Found a NULL path entry */
			}
		}
		return -1;  /* No NULL path entries */
	}
	
	/* Normal case - search for a matching path */
	for (int i = 0; i < monitor->check_queue_size; i++) {
		/* Skip entries with NULL paths */
		if (!monitor->check_queue[i].path) {
			continue;
		}
		
		if (strcmp(monitor->check_queue[i].path, path) == 0) {
			return i;
		}
	}
	return -1; /* Not found */
}

/* Add or update an entry in the queue */
static void check_queue_add_or_update(monitor_t *monitor, const char *path, 
								   watch_entry_t *watch, struct timespec next_check) {
	if (!monitor->check_queue || !path || !watch) {
		log_message(LOG_LEVEL_WARNING, "Invalid parameters for check_queue_add_or_update");
		return;
	}
	
	/* Check if entry already exists for this path (regardless of watch) */
	int index = check_queue_find_by_path(monitor, path);
	
	if (index >= 0) {
		/* Entry exists - update it */
		deferred_check_t *entry = &monitor->check_queue[index];
		
		/* Add this watch if not already present */
		if (!check_queue_add_watch(entry, watch)) {
			log_message(LOG_LEVEL_WARNING, 
					  "Failed to add watch to existing queue entry for %s", path);
		}
		
		/* Update check time - only if the new time is earlier */
		if (check_queue_compare(&next_check, &entry->next_check) < 0) {
			entry->next_check = next_check;
			
			/* Restore heap property by trying both up and down heapify */
			check_queue_heapify_up(monitor->check_queue, index);
			check_queue_heapify_down(monitor->check_queue, 
								   monitor->check_queue_size, index);
								   
			log_message(LOG_LEVEL_DEBUG, 
					  "Updated check time for %s (earlier time: %ld.%09ld)",
					  path, (long)next_check.tv_sec, next_check.tv_nsec);
		}
		return;
	}
	
	/* Entry not found, add new one */
	
	/* Ensure capacity */
	if (monitor->check_queue_size >= monitor->check_queue_capacity) {
		int new_capacity = monitor->check_queue_capacity * 2;
		deferred_check_t *new_queue = realloc(monitor->check_queue, 
											new_capacity * sizeof(deferred_check_t));
		if (!new_queue) {
			log_message(LOG_LEVEL_ERR, "Failed to resize deferred check queue");
			return;
		}
		monitor->check_queue = new_queue;
		monitor->check_queue_capacity = new_capacity;
		
		/* Zero out new memory */
		memset(&monitor->check_queue[monitor->check_queue_capacity], 0, 
			  (new_capacity - monitor->check_queue_capacity) * sizeof(deferred_check_t));
		
		monitor->check_queue_capacity = new_capacity;
	}
	
	/* Add new entry */
	int new_index = monitor->check_queue_size;
	
	/* Initialize the new entry */
	char *path_copy = strdup(path);
	if (!path_copy) {
		log_message(LOG_LEVEL_ERR, "Failed to duplicate path for queue entry");
		return;
	}
	
	/* Clear the new entry first to avoid garbage data */
	memset(&monitor->check_queue[new_index], 0, sizeof(deferred_check_t));
	
	monitor->check_queue[new_index].path = path_copy;
	monitor->check_queue[new_index].next_check = next_check;
	monitor->check_queue[new_index].watches = NULL;
	monitor->check_queue[new_index].watch_count = 0;
	monitor->check_queue[new_index].watch_capacity = 0;
	
	/* Add the watch */
	if (!check_queue_add_watch(&monitor->check_queue[new_index], watch)) {
		log_message(LOG_LEVEL_ERR, "Failed to add watch to new queue entry");
		free(monitor->check_queue[new_index].path);
		monitor->check_queue[new_index].path = NULL;
		return;
	}
	
	monitor->check_queue_size++;
	
	/* Restore heap property */
	check_queue_heapify_up(monitor->check_queue, new_index);
	
	log_message(LOG_LEVEL_DEBUG, 
			  "Added new deferred check for %s (next check at %ld.%09ld)",
			  path, (long)next_check.tv_sec, next_check.tv_nsec);
}

/* Remove an entry from the queue */
static void check_queue_remove(monitor_t *monitor, const char *path) {
	if (!monitor->check_queue || monitor->check_queue_size <= 0) return;
	
	int index;
	
	/* Special case for empty path - handle corrupted queue entry removal */
	if (!path || path[0] == '\0') {
		/* Find first entry with NULL path */
		for (index = 0; index < monitor->check_queue_size; index++) {
			if (!monitor->check_queue[index].path) {
				log_message(LOG_LEVEL_WARNING, "Removing corrupted queue entry at index %d", index);
				break;
			}
		}
		if (index >= monitor->check_queue_size) {
			/* No corrupted entries found */
			return;
		}
	} else {
		/* Normal case - find by path */
		index = check_queue_find_by_path(monitor, path);
		if (index < 0) return; /* Not found */
	}
	
	/* Store a copy of the path for logging if available */
	char path_copy[PATH_MAX] = "<corrupted>";
	if (monitor->check_queue[index].path) {
		strncpy(path_copy, monitor->check_queue[index].path, PATH_MAX - 1);
		path_copy[PATH_MAX - 1] = '\0';
	}
	
	/* Free resources */
	if (monitor->check_queue[index].path) {
		free(monitor->check_queue[index].path);
		monitor->check_queue[index].path = NULL;
	}
	
	if (monitor->check_queue[index].watches) {
		free(monitor->check_queue[index].watches);
		monitor->check_queue[index].watches = NULL;
	}
	
	/* Replace with the last element and restore heap property */
	monitor->check_queue_size--;
	if (index < monitor->check_queue_size) {
		/* Move the last element to the removed position */
		memcpy(&monitor->check_queue[index], 
			   &monitor->check_queue[monitor->check_queue_size], 
			   sizeof(deferred_check_t));
		
		/* Clear the last element which was just moved */
		memset(&monitor->check_queue[monitor->check_queue_size], 0, sizeof(deferred_check_t));
		
		/* Restore heap property for the moved element */
		check_queue_heapify_down(monitor->check_queue, monitor->check_queue_size, index);
	} else {
		/* Removed the last element, just clear it */
		memset(&monitor->check_queue[index], 0, sizeof(deferred_check_t));
	}
	
	log_message(LOG_LEVEL_DEBUG, "Removed deferred check for %s", path_copy);
}

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
	monitor->reload_requested = false;

	/* Store config file path for reloading */
	if (config->config_file != NULL) {
		monitor->config_file = strdup(config->config_file);
	}
	
	/* Initialize the deferred check queue */
	check_queue_init(monitor, 16); /* Initial capacity of 16 */
	
	/* Initialize delayed event queue */
	monitor->delayed_events = NULL;
	monitor->delayed_event_count = 0;
	monitor->delayed_event_capacity = 0;
	
	/* Set global monitor instance */
	g_current_monitor = monitor;

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
	free(monitor->config_file);

	/* Clean up the check queue */
	check_queue_cleanup(monitor);
	
	/* Clean up delayed event queue */
	if (monitor->delayed_events) {
		for (int i = 0; i < monitor->delayed_event_count; i++) {
			free(monitor->delayed_events[i].event.path);
		}
		free(monitor->delayed_events);
	}
	
	/* Clear global monitor reference if it's this monitor */
	if (g_current_monitor == monitor) {
		g_current_monitor = NULL;
	}
	
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
static bool monitor_add_dir_recursive(monitor_t *monitor, const char *dir_path, watch_entry_t *watch) {
	DIR *dir;
	struct dirent *entry;

	/* Skip hidden directories unless hidden is true */
	if (!watch->hidden && is_hidden_path(dir_path)) {
		log_message(LOG_LEVEL_DEBUG, "Skipping hidden directory: %s", dir_path);
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
		watch_info_t *existing_info = monitor_find_watch_info_by_path(monitor, dir_path);
		if (existing_info != NULL) {
			/* Reuse the existing file descriptor */
			int fd = existing_info->wd;
			watch_info_t *info = calloc(1, sizeof(watch_info_t));
			if (info == NULL) {
				log_message(LOG_LEVEL_ERR, "Failed to allocate memory for watch info");
				return false;
			}
			
			info->wd = fd;
			info->path = strdup(dir_path);
			info->watch = watch;
			info->is_shared_fd = true;
			existing_info->is_shared_fd = true;
			if (!monitor_add_watch_info(monitor, info)) {
				watch_info_destroy(info);
				return false;
			}
			
			log_message(LOG_LEVEL_DEBUG, "Added additional watch for directory: %s (with shared FD)", dir_path);
		} else {
			/* Create a new watch with a new file descriptor */
			int fd = open(dir_path, O_RDONLY);
			if (fd == -1) {
				log_message(LOG_LEVEL_ERR, "Failed to open %s: %s", dir_path, strerror(errno));
				return false;
			}
			
			watch_info_t *info = calloc(1, sizeof(watch_info_t));
			if (info == NULL) {
				log_message(LOG_LEVEL_ERR, "Failed to allocate memory for watch info");
				close(fd);
				return false;
			}
			
			info->wd = fd;
			info->path = strdup(dir_path);
			info->watch = watch;
			info->is_shared_fd = false;
			if (!monitor_add_watch_info(monitor, info)) {
				watch_info_destroy(info);
				close(fd);
				return false;
			}
			
			if (!monitor_add_kqueue_watch(monitor, info)) {
				/* The watch_info is already in the monitor's list, so it will be cleaned up on monitor_destroy */
				return false;
			}
			log_message(LOG_LEVEL_DEBUG, "Added new watch for directory: %s", dir_path);
		}
	}

	dir = opendir(dir_path);
	if (dir == NULL) {
		log_message(LOG_LEVEL_ERR, "Failed to open directory %s: %s", dir_path, strerror(errno));
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
				log_message(LOG_LEVEL_DEBUG, "Skipping hidden file/directory: %s/%s", dir_path, entry->d_name);
				continue;
			}
			
			snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);
			
			if (stat(path, &st) == -1) {
				log_message(LOG_LEVEL_WARNING, "Failed to stat %s: %s", path, strerror(errno));
				continue;
			}
			
			if (S_ISDIR(st.st_mode)) {
				/* Recursively add subdirectory */
				if (!monitor_add_dir_recursive(monitor, path, watch)) {
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
		
		/* For directories with recursive monitoring, we still need to discover subdirectories */
		if (watch->type == WATCH_DIRECTORY && watch->recursive) {
			struct stat st;
			if (stat(watch->path, &st) == 0 && S_ISDIR(st.st_mode)) {
				monitor_add_dir_recursive(monitor, watch->path, watch); /* true = skip existing main dir */
			}
		}
		
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
		
		return monitor_add_dir_recursive(monitor, watch->path, watch);  /* false = don't skip existing */
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
	
	/* Add config file watch for hot reload by adding it to the config structure */
	if (monitor->config_file != NULL) {
		watch_entry_t *config_watch = calloc(1, sizeof(watch_entry_t));
		if (config_watch == NULL) {
			log_message(LOG_LEVEL_ERR, "Failed to allocate memory for config file watch");
			return false;
		}
		
		config_watch->name = strdup("__config_file__");
		config_watch->path = strdup(monitor->config_file);
		config_watch->type = WATCH_FILE;
		config_watch->events = EVENT_MODIFY;
		config_watch->command = strdup("__config_reload__");
		config_watch->log_output = false;
		config_watch->recursive = false;
		config_watch->hidden = false;
		
		/* Add to config structure so it gets managed properly */
		watch_entry_t **new_watches = realloc(monitor->config->watches, (monitor->config->watch_count + 1) * sizeof(watch_entry_t *));
		if (new_watches == NULL) {
			log_message(LOG_LEVEL_WARNING, "Failed to add config watch to config structure");
			free(config_watch->name);
			free(config_watch->path);
			free(config_watch->command);
			free(config_watch);
		} else {
			monitor->config->watches = new_watches;
			monitor->config->watches[monitor->config->watch_count] = config_watch;
			monitor->config->watch_count++;
			
			if (!monitor_add_watch(monitor, config_watch)) {
				log_message(LOG_LEVEL_WARNING, "Failed to add config file watch for %s", monitor->config_file);
				/* Remove from config since it wasn't added to monitor */
				monitor->config->watch_count--;
			} else {
				log_message(LOG_LEVEL_DEBUG, "Added config file watch for %s", monitor->config_file);
			}
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

/* Function to schedule a deferred directory check */
void schedule_deferred_check(monitor_t *monitor, entity_state_t *state) {
	if (!monitor || !state) {
		log_message(LOG_LEVEL_WARNING, "Cannot schedule deferred check - invalid monitor or state");
		return;
	}
	
	if (!state->path || !state->watch) {
		log_message(LOG_LEVEL_WARNING, "Cannot schedule deferred check - state has null path or watch");
		return;
	}
	
	/* Find the root state for this entity */
	entity_state_t *root_state = find_root_state(state);
	if (!root_state) {
		/* If no root found, use the provided state if it's a directory */
		if (state->type == ENTITY_DIRECTORY) {
			root_state = state;
		} else {
			log_message(LOG_LEVEL_WARNING, 
					  "Cannot schedule check for %s - no root state found", state->path);
			return;
		}
	}
	
	/* Force root state to be active */
	root_state->activity_in_progress = true;
	
	/* Initialize reference stats if needed - CRITICAL for empty directories */
	if (!root_state->reference_stats_initialized) {
		root_state->stable_reference_stats = root_state->dir_stats;
		root_state->reference_stats_initialized = true;
		log_message(LOG_LEVEL_DEBUG, 
				  "Initialized reference stats for %s: files=%d, dirs=%d, depth=%d",
				  root_state->path, root_state->dir_stats.file_count, 
				  root_state->dir_stats.dir_count, root_state->dir_stats.depth);
	}
	
	/* Calculate check time based on quiet period */
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	
	/* Fix: Ensure we don't use a timestamp in the past */
	if (root_state->last_activity_in_tree.tv_sec < now.tv_sec - 10) {
		log_message(LOG_LEVEL_WARNING, 
				  "Last activity timestamp for %s is too old, using current time",
				  root_state->path);
		root_state->last_activity_in_tree = now;
	}
	
	long required_quiet_period_ms = get_required_quiet_period(root_state);
	
	struct timespec next_check;
	next_check.tv_sec = root_state->last_activity_in_tree.tv_sec + (required_quiet_period_ms / 1000);
	next_check.tv_nsec = root_state->last_activity_in_tree.tv_nsec + 
						((required_quiet_period_ms % 1000) * 1000000);
	
	/* Normalize nsec */
	if (next_check.tv_nsec >= 1000000000) {
		next_check.tv_sec++;
		next_check.tv_nsec -= 1000000000;
	}
	
	/* Add to queue */
	check_queue_add_or_update(monitor, root_state->path, root_state->watch, next_check);
	
	/* For the synchronization to work correctly, also perform a synchronize_activity_states call */
	synchronize_activity_states(root_state->path, root_state);
	
	log_message(LOG_LEVEL_DEBUG, 
			  "Scheduled deferred check for %s: in %ld ms (directory with %d files, %d dirs)",
			  root_state->path, required_quiet_period_ms,
			  root_state->dir_stats.file_count, root_state->dir_stats.dir_count);
}

/* Process deferred directory scans after quiet periods */
static void process_deferred_dir_scans(monitor_t *monitor, struct timespec *current_time) {
	int commands_attempted = 0;
	int commands_executed = 0;
	bool new_directories_found = false;
	int total_active_dirs = monitor->check_queue_size;
	
	/* Nothing to process if queue is empty */
	if (!monitor || !monitor->check_queue || monitor->check_queue_size == 0) {
		return;
	}
	
	/* Count active directories for summary */
	for (int i = 0; i < monitor->check_queue_size; i++) {
		if (monitor->check_queue[i].path) {
			total_active_dirs++;
		}
	}
	
	/* Validate the top entry before processing */
	if (!monitor->check_queue[0].path) {
		log_message(LOG_LEVEL_WARNING, "Corrupted entry at top of queue, removing");
		check_queue_remove(monitor, NULL);
		return;
	}
	
	/* Get the top entry (earliest scheduled check) */
	deferred_check_t *entry = &monitor->check_queue[0];
	
	/* Check if it's time to process this entry */
	if (current_time->tv_sec < entry->next_check.tv_sec ||
		(current_time->tv_sec == entry->next_check.tv_sec && 
		 current_time->tv_nsec < entry->next_check.tv_nsec)) {
		/* Not yet time for this check */
		long remaining_ms = (entry->next_check.tv_sec - current_time->tv_sec) * 1000 +
						   (entry->next_check.tv_nsec - current_time->tv_nsec) / 1000000;
		
		/* Only log if significant time remains to avoid log spam */
		if (remaining_ms > 50) {
			log_message(LOG_LEVEL_DEBUG, "Path %s: %ld ms remaining of scheduled quiet period",
					  entry->path, remaining_ms);
		}
		return;
	}
	
	log_message(LOG_LEVEL_DEBUG, "Processing deferred check for %s with %d watches", 
			  entry->path, entry->watch_count);
	
	/* Get the primary watch (first in the list) */
	watch_entry_t *primary_watch = entry->watch_count > 0 ? entry->watches[0] : NULL;
	if (!primary_watch) {
		log_message(LOG_LEVEL_WARNING, "Deferred check for %s has no watches, removing", entry->path);
		check_queue_remove(monitor, entry->path);
		return;
	}
	
	/* Get the root entity state using the primary watch */
	entity_state_t *root_state = get_entity_state(entry->path, ENTITY_DIRECTORY, primary_watch);
	if (!root_state) {
		log_message(LOG_LEVEL_WARNING, "Cannot find state for %s, removing from queue", entry->path);
		check_queue_remove(monitor, entry->path);
		return;
	}
	
	/* If the entity is no longer active, just remove from queue */
	if (!root_state->activity_in_progress) {
		log_message(LOG_LEVEL_DEBUG, "Directory %s no longer active, removing from queue", entry->path);
		check_queue_remove(monitor, entry->path);
		return;
	}
	
	/* Verify if the quiet period has truly elapsed */
	long elapsed_ms = (current_time->tv_sec - root_state->last_activity_in_tree.tv_sec) * 1000 +
					 (current_time->tv_nsec - root_state->last_activity_in_tree.tv_nsec) / 1000000;
	long required_quiet_period_ms = get_required_quiet_period(root_state);
	
	/* Detailed log showing state of this directory check */
	log_message(LOG_LEVEL_DEBUG, 
			  "Path %s: %ld ms elapsed of %ld ms quiet period, direct_entries=%d+%d, recursive_entries=%d+%d, depth=%d, adjusted wait: %ld ms",
			  entry->path, elapsed_ms, required_quiet_period_ms, 
			  root_state->dir_stats.file_count, root_state->dir_stats.dir_count,
			  root_state->dir_stats.recursive_file_count, root_state->dir_stats.recursive_dir_count,
			  root_state->dir_stats.depth, 
			  required_quiet_period_ms - elapsed_ms < 0 ? 0 : required_quiet_period_ms - elapsed_ms);
	
	/* Check if quiet period has truly elapsed based on most recent activity */
	bool quiet_period_has_elapsed = is_quiet_period_elapsed(root_state, current_time);
	
	if (!quiet_period_has_elapsed) {
		/* Quiet period not yet elapsed, reschedule */
		log_message(LOG_LEVEL_DEBUG, "Quiet period not yet elapsed for %s (watch: %s), continuing to monitor",
				  root_state->path, primary_watch->name);
		
		/* Update next check time based on latest activity */
		struct timespec next_check;
		next_check.tv_sec = root_state->last_activity_in_tree.tv_sec + (required_quiet_period_ms / 1000);
		next_check.tv_nsec = root_state->last_activity_in_tree.tv_nsec + 
						   ((required_quiet_period_ms % 1000) * 1000000);
		
		/* Normalize timestamp */
		if (next_check.tv_nsec >= 1000000000) {
			next_check.tv_sec++;
			next_check.tv_nsec -= 1000000000;
		}
		
		/* Update the entry in place */
		entry->next_check = next_check;
		
		/* Restore heap property */
		check_queue_heapify_down(monitor->check_queue, monitor->check_queue_size, 0);
		
		/* Log processing summary */
		log_message(LOG_LEVEL_DEBUG,
				  "Deferred processing summary: directories=%d, active=%d, commands_attempted=%d, executed=%d, new_dirs_found=%s",
				  total_active_dirs, total_active_dirs, commands_attempted, commands_executed, 
				  new_directories_found ? "yes" : "no");
		
		return;
	}
	
	log_message(LOG_LEVEL_DEBUG, "Quiet period elapsed for %s, performing stability verification", entry->path);
	
	/* For recursive watches, scan for new directories */
	int prev_watch_count = monitor->watch_count;
	for (int i = 0; i < entry->watch_count; i++) {
		if (entry->watches[i]->recursive) {
			monitor_add_dir_recursive(monitor, entry->path, entry->watches[i]);
		}
	}
	
	/* Check if new directories were found */
	if (monitor->watch_count > prev_watch_count) {
		log_message(LOG_LEVEL_DEBUG, "Found %d new directories during scan, deferring command execution",
				  monitor->watch_count - prev_watch_count);
		new_directories_found = true;
		
		/* Synchronize state after adding watches but before rescheduling */
		synchronize_activity_states(root_state->path, root_state);
		
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
		check_queue_heapify_down(monitor->check_queue, monitor->check_queue_size, 0);
		
		/* Log processing summary */
		log_message(LOG_LEVEL_DEBUG,
				  "Deferred processing summary: directories=%d, active=%d, commands_attempted=%d, executed=%d, new_dirs_found=%s",
				  total_active_dirs, total_active_dirs, commands_attempted, commands_executed, 
				  new_directories_found ? "yes" : "no");
		
		return;
	}
	
	/* Perform recursive stability verification */
	dir_stats_t current_stats;
	bool scan_completed = verify_directory_stability(entry->path, &current_stats, 0);
	
	/* Ensure comprehensive stats for accurate cumulative changes */
	dir_stats_t comprehensive_stats;
	if (gather_basic_directory_stats(entry->path, &comprehensive_stats, 0)) {
		current_stats = comprehensive_stats;
	}
	
	/* Update root state with latest stats, even if not stable */
	if (scan_completed || current_stats.recursive_file_count > 0 || current_stats.recursive_dir_count > 0) {
		/* Check if current scan has more complete recursive stats */
		if (current_stats.recursive_file_count > root_state->dir_stats.recursive_file_count ||
			current_stats.recursive_dir_count > root_state->dir_stats.recursive_dir_count ||
			current_stats.max_depth > root_state->dir_stats.max_depth) {
			
			log_message(LOG_LEVEL_DEBUG, 
					  "Updating %s with more comprehensive recursive stats: files=%d, dirs=%d, max_depth=%d",
					  root_state->path, current_stats.recursive_file_count, 
					  current_stats.recursive_dir_count, current_stats.max_depth);
			
			/* Store comprehensive recursive stats */
			root_state->dir_stats.recursive_file_count = current_stats.recursive_file_count;
			root_state->dir_stats.recursive_dir_count = current_stats.recursive_dir_count;
			root_state->dir_stats.max_depth = current_stats.max_depth;
			root_state->dir_stats.recursive_total_size = current_stats.recursive_total_size;
		}
	}
	
	/* Handle scan failure */
	if (!scan_completed) {
		/* Check if the directory still exists */
		struct stat st;
		bool exists = (stat(entry->path, &st) == 0 && S_ISDIR(st.st_mode));
		
		if (!exists) {
			/* Increment failed checks counter */
			root_state->failed_checks++;
			
			log_message(LOG_LEVEL_DEBUG, "Directory %s not found (attempt %d/%d)",
					  entry->path, root_state->failed_checks, MAX_FAILED_CHECKS);
			
			/* After multiple consecutive failures, consider it permanently deleted */
			if (root_state->failed_checks >= MAX_FAILED_CHECKS) {
				log_message(LOG_LEVEL_INFO, "Directory %s confirmed deleted after %d failed checks, cleaning up",
					  entry->path, root_state->failed_checks);
				
				/* Mark as not active for all watches */
				root_state->activity_in_progress = false;
				root_state->exists = false;
				synchronize_activity_states(entry->path, root_state);
				
				/* Remove from queue */
				check_queue_remove(monitor, entry->path);
				return;
			}
			
			/* Reschedule with a longer timeout for the next check */
			struct timespec next_check;
			next_check.tv_sec = current_time->tv_sec + 2; /* 2 seconds */
			next_check.tv_nsec = current_time->tv_nsec;
			
			/* Update entry */
			entry->next_check = next_check;
			check_queue_heapify_down(monitor->check_queue, monitor->check_queue_size, 0);
			return;
		} else {
			/* Directory exists but scan failed for some other reason */
			root_state->failed_checks = 0;  /* Reset counter */
		}
	} else {
		/* Reset failed check counter on successful scan */
		root_state->failed_checks = 0;
	}
	
	/* Store direct stats from scan (even if unstable) */
	root_state->dir_stats.file_count = current_stats.file_count;
	root_state->dir_stats.dir_count = current_stats.dir_count;
	root_state->dir_stats.depth = current_stats.depth;
	root_state->dir_stats.total_size = current_stats.total_size;
	
	/* Track if previous stats exist for comparison */
	bool has_prev_stats = (root_state->prev_stats.file_count > 0 || 
						 root_state->prev_stats.dir_count > 0);
	
	/* Log scan results with detailed stats */
	log_message(LOG_LEVEL_DEBUG, 
			  "Stability check #%d for %s: files=%d, dirs=%d, size=%.2f MB, recursive_files=%d, recursive_dirs=%d, max_depth=%d, stable=%s",
			  root_state->stability_check_count + 1, entry->path, 
			  current_stats.file_count, current_stats.dir_count, current_stats.total_size / (1024.0 * 1024.0),
			  current_stats.recursive_file_count, current_stats.recursive_dir_count, 
			  current_stats.max_depth, scan_completed ? "yes" : "no");
	
	/* Determine stability based on scan result and comparison */
	bool is_stable = scan_completed;  /* Initially use scan result */
	
	/* Only compare with previous stats if we have a previous scan */
	if (scan_completed && has_prev_stats) {
		bool counts_stable = compare_dir_stats(&root_state->prev_stats, &current_stats);
		if (!counts_stable) {
			log_message(LOG_LEVEL_DEBUG, "Directory unstable: file/dir count changed from %d/%d to %d/%d",
					  root_state->prev_stats.file_count, root_state->prev_stats.dir_count, 
					  current_stats.file_count, current_stats.dir_count);
			is_stable = false;
		}
	}
	
	/* Save previous stats temporarily to calculate change */
	dir_stats_t temp_prev_stats = root_state->prev_stats;
	
	/* Update current stats in state */
	root_state->dir_stats = current_stats;
	
	/* Calculate cumulative changes using previous stats */
	root_state->prev_stats = temp_prev_stats;
	update_cumulative_changes(root_state);
	
	/* After calculation, set previous stats to current for next cycle */
	root_state->prev_stats = current_stats;
	
	/* Synchronize updated stats with other watches */
	synchronize_activity_states(entry->path, root_state);
	
	if (!is_stable) {
		/* Directory is unstable - reset counter and reschedule */
		root_state->stability_check_count = 0;
		
		/* Update activity timestamp */
		root_state->last_activity_in_tree = *current_time;
		synchronize_activity_states(entry->path, root_state);
		
		log_message(LOG_LEVEL_DEBUG, "Directory %s is still unstable, continuing to monitor", entry->path);
		
		/* Calculate adaptive quiet period for rescheduling */
		long adaptive_period_ms = get_required_quiet_period(root_state);
		
		/* For unstable directories, schedule with more urgency */
		struct timespec next_check;
		next_check.tv_sec = current_time->tv_sec + (adaptive_period_ms / 1000);
		next_check.tv_nsec = current_time->tv_nsec + ((adaptive_period_ms % 1000) * 1000000);
		
		/* Normalize timestamp */
		if (next_check.tv_nsec >= 1000000000) {
			next_check.tv_sec++;
			next_check.tv_nsec -= 1000000000;
		}
		
		/* Update entry in queue */
		entry->next_check = next_check;
		check_queue_heapify_down(monitor->check_queue, monitor->check_queue_size, 0);
		
		/* Log processing summary */
		log_message(LOG_LEVEL_DEBUG,
				  "Deferred processing summary: directories=%d, active=%d, commands_attempted=%d, executed=%d, new_dirs_found=%s",
				  total_active_dirs, total_active_dirs, commands_attempted, commands_executed, 
				  new_directories_found ? "yes" : "no");
		
		return;
	}
	
	/* Directory is stable - determine if enough checks have been completed */
	root_state->stability_check_count++;
	
	/* Calculate required checks based on complexity factors */
	int required_checks;
	int total_entries = current_stats.recursive_file_count + current_stats.recursive_dir_count;
	int tree_depth = current_stats.max_depth > 0 ? current_stats.max_depth : current_stats.depth;
	
	/* Use cumulative changes for adapting stability requirements */
	int abs_file_change = abs(root_state->cumulative_file_change);
	int abs_dir_change = abs(root_state->cumulative_dir_change);
	int abs_depth_change = abs(root_state->cumulative_depth_change);
	int abs_change = abs_file_change + abs_dir_change;
	
	/* Determine required checks based on change magnitude and complexity */
	if (abs_change <= 1 && abs_depth_change == 0) {
		required_checks = 1;
		if (tree_depth >= 5 || total_entries > 1000) required_checks = 2;
	} 
	else if (abs_change <= 5 && abs_depth_change == 0) {
		required_checks = 2;
	}
	else if (abs_depth_change > 0) {
		required_checks = 2;
		if (abs_depth_change > 1) required_checks = 3;
	}
	else if (abs_change < 20) {
		required_checks = 2;
		if (tree_depth >= 4 || total_entries > 500) required_checks = 3;
	}
	else {
		required_checks = 3;
		if (tree_depth >= 5 || total_entries > 1000) required_checks = 4;
	}
	
	/* Consider previous stability for check reduction */
	if (root_state->stability_lost && required_checks > 1) {
		required_checks--;
		log_message(LOG_LEVEL_DEBUG, "Adjusting required checks due to previous stability: %d", required_checks);
	}
	
	/* Ensure at least one check is required */
	if (required_checks < 1) required_checks = 1;
	
	log_message(LOG_LEVEL_DEBUG, 
			  "Directory stability check for %s: %d/%d checks based on cumulative changes (%+d files, %+d dirs, %+d depth) in dir with %d entries, depth %d",
			  root_state->path, root_state->stability_check_count, required_checks, 
			  root_state->cumulative_file_change, root_state->cumulative_dir_change, 
			  root_state->cumulative_depth_change, total_entries, tree_depth);
	
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
		check_queue_heapify_down(monitor->check_queue, monitor->check_queue_size, 0);
		
		/* Log processing summary */
		log_message(LOG_LEVEL_DEBUG,
				  "Deferred processing summary: directories=%d, active=%d, commands_attempted=%d, executed=%d, new_dirs_found=%s",
				  total_active_dirs, total_active_dirs, commands_attempted, commands_executed, 
				  new_directories_found ? "yes" : "no");
		
		return;
	}
	
	/* Directory is stable with sufficient consecutive checks - execute commands */
	commands_attempted++;
	log_message(LOG_LEVEL_INFO, 
			  "Directory %s stability confirmed (%d/%d checks), proceeding to command execution",
			  root_state->path, root_state->stability_check_count, required_checks);
	
	/* Reset activity flag and stability counter */
	root_state->activity_in_progress = false;
	root_state->stability_check_count = 0;
	
	/* Propagate status to all related states */
	synchronize_activity_states(root_state->path, root_state);
	
	/* Create synthetic event */
	file_event_t synthetic_event = {
		.path = entry->path,
		.type = EVENT_CONTENT,
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
			log_message(LOG_LEVEL_WARNING, "Unable to get state for %s with watch %s during command execution", 
					  entry->path, watch->name);
			continue;
		}
		
		/* Reset activity flag */
		watch_state->activity_in_progress = false;
		watch_state->stability_check_count = 0;
		
		/* Execute command */
		log_message(LOG_LEVEL_INFO, "Executing deferred command for %s (watch: %s)",
				  entry->path, watch->name);
		
		if (command_execute(watch, &synthetic_event)) {
			commands_executed++;
			
			/* Update stable reference stats after successful execution */
			watch_state->stable_reference_stats = watch_state->dir_stats;
			watch_state->reference_stats_initialized = true;
			
			/* Reset all tracking after successful command */
			watch_state->cumulative_file_change = 0;
			watch_state->cumulative_dir_change = 0;
			watch_state->cumulative_depth_change = 0;
			watch_state->stability_lost = false;
			
			/* Reset state change flags */
			watch_state->content_changed = false;
			watch_state->metadata_changed = false;
			watch_state->structure_changed = false;
			
			/* Update last command time */
			watch_state->last_command_time = current_time->tv_sec;
			
			log_message(LOG_LEVEL_DEBUG, 
					  "Reset change tracking for %s (watch: %s) after successful command execution",
					  entry->path, watch->name);
		} else {
			log_message(LOG_LEVEL_WARNING, "Command execution failed for %s (watch: %s)",
					  entry->path, watch->name);
		}
	}
	
	/* Remove entry from queue after processing all watches */
	check_queue_remove(monitor, entry->path);
	
	/* Log final processing summary */
	log_message(LOG_LEVEL_DEBUG,
			  "Deferred processing summary: directories=%d, active=%d, commands_attempted=%d, executed=%d, new_dirs_found=%s",
			  total_active_dirs, total_active_dirs - 1, /* -1 because we're removing one */
			  commands_attempted, commands_executed, 
			  new_directories_found ? "yes" : "no");
}

/* Calculate timeout for the next delayed event */
static int get_next_delayed_event_timeout(monitor_t *monitor, struct timespec *now) {
	if (!monitor || !monitor->delayed_events || monitor->delayed_event_count == 0) {
		return -1; /* No timeout needed */
	}
	
	struct timespec earliest = monitor->delayed_events[0].process_time;
	for (int i = 1; i < monitor->delayed_event_count; i++) {
		if (monitor->delayed_events[i].process_time.tv_sec < earliest.tv_sec ||
			(monitor->delayed_events[i].process_time.tv_sec == earliest.tv_sec &&
			 monitor->delayed_events[i].process_time.tv_nsec < earliest.tv_nsec)) {
			earliest = monitor->delayed_events[i].process_time;
		}
	}
	
	/* Calculate timeout in milliseconds */
	long timeout_ms = (earliest.tv_sec - now->tv_sec) * 1000 +
					 (earliest.tv_nsec - now->tv_nsec) / 1000000;
	
	return timeout_ms > 0 ? (int)timeout_ms : 0;
}

/* Process events from kqueue and handle commands */
bool monitor_process_events(monitor_t *monitor) {
	struct kevent events[MAX_EVENTS];
	int nev;
	struct timespec timeout, *p_timeout;
	
	/* Check for reload request */
	if (monitor->reload_requested) {
		monitor->reload_requested = false;
		if (!monitor_reload(monitor)) {
			log_message(LOG_LEVEL_ERR, "Failed to reload configuration, continuing with existing config");
		}
	}
	
    if (!monitor || monitor->kq < 0) {
        log_message(LOG_LEVEL_ERR, "Invalid monitor state");
        return false;
    }
    
    /* Calculate timeout based on pending deferred scans and delayed events */
    memset(&timeout, 0, sizeof(timeout));
    p_timeout = NULL;
    
    struct timespec now_monotonic;
    clock_gettime(CLOCK_MONOTONIC, &now_monotonic);
    
    /* Get timeout for delayed events */
    int delayed_timeout_ms = get_next_delayed_event_timeout(monitor, &now_monotonic);
    
    /* Check if we have any pending deferred checks */
    if (monitor->check_queue_size > 0 && monitor->check_queue) {
        /* Debug output for the queue status */
        if (monitor->check_queue[0].path) {
            log_message(LOG_LEVEL_DEBUG, "Deferred queue status: %d entries, next check for path %s", 
                      monitor->check_queue_size, monitor->check_queue[0].path);
        }
        
        /* Get the earliest check time (top of min-heap) */
        struct timespec next_check = monitor->check_queue[0].next_check;
        
        /* Calculate relative timeout */
        if (now_monotonic.tv_sec < next_check.tv_sec ||
            (now_monotonic.tv_sec == next_check.tv_sec && 
             now_monotonic.tv_nsec < next_check.tv_nsec)) {
            
            /* Time until next check */
            timeout.tv_sec = next_check.tv_sec - now_monotonic.tv_sec;
			if (next_check.tv_nsec >= now_monotonic.tv_nsec) {
				timeout.tv_nsec = next_check.tv_nsec - now_monotonic.tv_nsec;
			} else {
				timeout.tv_sec--;
				timeout.tv_nsec = 1000000000 + next_check.tv_nsec - now_monotonic.tv_nsec;
			}
            
            /* Ensure sane values */
            if (timeout.tv_sec < 0) {
                timeout.tv_sec = 0;
                timeout.tv_nsec = 50000000; /* 50ms minimum */
            } else if (timeout.tv_sec == 0 && timeout.tv_nsec < 10000000) {
                timeout.tv_nsec = 50000000; /* 50ms minimum */
            }
            
            p_timeout = &timeout;
			
        } else {
            /* Check time already passed, use minimal timeout */
            timeout.tv_sec = 0;
            timeout.tv_nsec = 10000000; /* 10ms */
            p_timeout = &timeout;
            log_message(LOG_LEVEL_DEBUG, "Deferred check overdue, using minimal timeout");
        }
    } else if (delayed_timeout_ms >= 0) {
        /* No deferred checks, but we have delayed events */
        timeout.tv_sec = delayed_timeout_ms / 1000;
        timeout.tv_nsec = (delayed_timeout_ms % 1000) * 1000000;
        p_timeout = &timeout;
        log_message(LOG_LEVEL_DEBUG, "No deferred checks, timeout for delayed events: %d ms", delayed_timeout_ms);
    } else {
        log_message(LOG_LEVEL_DEBUG, "No pending directory activity or delayed events, waiting indefinitely");
        p_timeout = NULL;
    }
    
    /* If we have both deferred checks and delayed events, use the shorter timeout */
    if (p_timeout && delayed_timeout_ms >= 0) {
        long current_timeout_ms = timeout.tv_sec * 1000 + timeout.tv_nsec / 1000000;
        if (delayed_timeout_ms < current_timeout_ms) {
            timeout.tv_sec = delayed_timeout_ms / 1000;
            timeout.tv_nsec = (delayed_timeout_ms % 1000) * 1000000;
            log_message(LOG_LEVEL_DEBUG, "Using shorter delayed event timeout: %d ms", delayed_timeout_ms);
        }
    }

    /* Wait for events */
    nev = kevent(monitor->kq, NULL, 0, events, MAX_EVENTS, p_timeout);

    /* Get time after kevent returns */
	struct timespec after_kevent_time;
	clock_gettime(CLOCK_MONOTONIC, &after_kevent_time);

    /* Handle kevent result */
	if (nev == -1) {
		if (errno == EINTR) {
			log_message(LOG_LEVEL_DEBUG, "kevent interrupted by signal, returning to main loop");
			return true; /* Return to main loop where running flag will be checked */
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
					
					/* Check if this watch has a processing delay configured */
					if (info->watch->processing_delay > 0) {
						/* Schedule the event for delayed processing */
						schedule_delayed_event(monitor, info->watch, &event, entity_type);
					} else {
						/* Process the event immediately */
						process_event(info->watch, &event, entity_type);
					}
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
					
					log_message(LOG_LEVEL_DEBUG, "Re-opened %s after DELETE/REVOKE (new descriptor: %d)", 
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
		if (p_timeout) {
			log_message(LOG_LEVEL_DEBUG, "Timeout occurred after %ld.%09ld seconds, checking deferred scans", 
					  p_timeout->tv_sec, p_timeout->tv_nsec);
		} else {
			log_message(LOG_LEVEL_DEBUG, "Timeout occurred, checking deferred scans");
		}
	}

	/* Check deferred scans */
	process_deferred_dir_scans(monitor, &after_kevent_time);
	
	/* Process delayed events */
	process_delayed_events(monitor);
	
	/* Clean up expired command intents */
	command_intent_cleanup_expired();

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

/* Request a configuration reload */
void monitor_request_reload(monitor_t *monitor) {
	if (monitor != NULL) {
		monitor->reload_requested = true;
		log_message(LOG_LEVEL_INFO, "Configuration reload requested");
	}
}

/* Process a reload request */
bool monitor_reload(monitor_t *monitor) {
	if (monitor == NULL || monitor->config_file == NULL) {
		log_message(LOG_LEVEL_ERR, "Invalid monitor or missing configuration file for reload");
		return false;
	}
	
	log_message(LOG_LEVEL_INFO, "Reloading configuration from %s", monitor->config_file);
	log_message(LOG_LEVEL_DEBUG, "Current configuration has %d watches", monitor->watch_count);
	
	/* Save existing config to compare later */
	config_t *old_config = monitor->config;
	
	/* Create new configuration */
	config_t *new_config = config_create();
	if (new_config == NULL) {
		log_message(LOG_LEVEL_ERR, "Failed to create new configuration during reload");
		return false;
	}
	
	/* Copy daemon mode and log level from existing config */
	new_config->daemon_mode = old_config->daemon_mode;
	new_config->syslog_level = old_config->syslog_level;
	
	/* Parse configuration file */
	if (!config_parse_file(new_config, monitor->config_file)) {
		log_message(LOG_LEVEL_ERR, "Failed to parse configuration file during reload: %s", monitor->config_file);
		config_destroy(new_config);
		return false;
	}
	
	log_message(LOG_LEVEL_DEBUG, "Found %d watch entries in new configuration", new_config->watch_count);

    /* Create and add the new config file watch entry to the new_config */
    watch_entry_t *new_config_watch_entry = calloc(1, sizeof(watch_entry_t));
    if (!new_config_watch_entry) {
        log_message(LOG_LEVEL_ERR, "Failed to allocate memory for new config watch entry");
        config_destroy(new_config);
        return false;
    }
    new_config_watch_entry->name = strdup("__config_file__");
    new_config_watch_entry->path = strdup(monitor->config_file);
    new_config_watch_entry->type = WATCH_FILE;
    new_config_watch_entry->events = EVENT_MODIFY;
    new_config_watch_entry->command = strdup("__config_reload__");

    watch_entry_t **temp_watches = realloc(new_config->watches, (new_config->watch_count + 1) * sizeof(watch_entry_t *));
    if (!temp_watches) {
        log_message(LOG_LEVEL_ERR, "Failed to realloc watches for new config entry");
        free(new_config_watch_entry->name);
        free(new_config_watch_entry->path);
        free(new_config_watch_entry->command);
        free(new_config_watch_entry);
        config_destroy(new_config);
        return false;
    }
    new_config->watches = temp_watches;
    new_config->watches[new_config->watch_count] = new_config_watch_entry;
    new_config->watch_count++;

	/* Allocate space for the list of watches that will be kept */
	watch_info_t **retained_watches = calloc(monitor->watch_count + new_config->watch_count, sizeof(watch_info_t *));
	int retained_count = 0;
	if (!retained_watches) {
		log_message(LOG_LEVEL_ERR, "Failed to allocate memory for retained watches array");
		config_destroy(new_config);
		return false;
	}

	/* Track which new watches have been processed */
	bool *new_watch_processed = calloc(new_config->watch_count, sizeof(bool));
	if (!new_watch_processed) {
		log_message(LOG_LEVEL_ERR, "Failed to allocate memory for watch processing tracker");
		free(retained_watches);
		config_destroy(new_config);
		return false;
	}

	/* Pass 1: First, find the old config file watch_info, retain it, and point it to the new entry */
	for (int i = 0; i < monitor->watch_count; i++) {
		if (monitor->watches[i] && monitor->watches[i]->watch && strcmp(monitor->watches[i]->watch->name, "__config_file__") == 0) {
			monitor->watches[i]->watch = new_config_watch_entry; /* Point to the new entry */
			retained_watches[retained_count++] = monitor->watches[i];
			monitor->watches[i] = NULL; /* Mark as retained */
			log_message(LOG_LEVEL_DEBUG, "Preserving and updating config file watch");
			break;
		}
	}

	/* Find user-defined watches that are identical in both old and new configs */
	for (int i = 0; i < new_config->watch_count; i++) {
		if (new_config->watches[i] == new_config_watch_entry) continue;
		
		watch_entry_t *new_watch = new_config->watches[i];
		for (int j = 0; j < old_config->watch_count; j++) {
			watch_entry_t *old_watch = old_config->watches[j];
			if (old_watch == NULL || strcmp(old_watch->name, "__config_file__") == 0) continue;
			
			/* Check for identity */
			if (strcmp(new_watch->path, old_watch->path) == 0 &&
				strcmp(new_watch->name, old_watch->name) == 0 &&
				new_watch->type == old_watch->type &&
				new_watch->events == old_watch->events &&
				new_watch->recursive == old_watch->recursive &&
				new_watch->hidden == old_watch->hidden &&
				strcmp(new_watch->command, old_watch->command) == 0) {
				
				log_message(LOG_LEVEL_DEBUG, "Watch unchanged: %s (watch: %s)", new_watch->path, new_watch->name);
				new_watch_processed[i] = true;
				
				/* Retain all watch_info structs associated with this old_watch definition */
				for (int k = 0; k < monitor->watch_count; k++) {
					if (monitor->watches[k] && monitor->watches[k]->watch == old_watch) {
						monitor->watches[k]->watch = new_watch;
						retained_watches[retained_count++] = monitor->watches[k];
						monitor->watches[k] = NULL;
					}
				}
				
				log_message(LOG_LEVEL_DEBUG, "Skipping entity state update for unchanged watch: %s", new_watch->name);
				
				old_config->watches[j] = NULL;
				break;
			}
		}
	}

	/* Clear deferred processing queue to prevent access to freed entity states */
	log_message(LOG_LEVEL_DEBUG, "Clearing deferred processing queue during config reload");
	check_queue_cleanup(monitor);
	check_queue_init(monitor, 16);
	
	/* Also clear delayed events queue that may reference old watches */
	if (monitor->delayed_events) {
		for (int i = 0; i < monitor->delayed_event_count; i++) {
			if (monitor->delayed_events[i].event.path) {
				free(monitor->delayed_events[i].event.path);
				monitor->delayed_events[i].event.path = NULL;
			}
		}
		monitor->delayed_event_count = 0;
		log_message(LOG_LEVEL_DEBUG, "Cleared %d delayed events during config reload", monitor->delayed_event_count);
	}
	
	/* Clean up orphaned entity states before destroying old watches */
	cleanup_orphaned_entity_states(old_config);

	/* Pass 2: Destroy old and modified watches */
	for (int i = 0; i < monitor->watch_count; i++) {
		if (monitor->watches[i]) {
			log_message(LOG_LEVEL_DEBUG, "Removing watch for %s (watch: %s)",
						monitor->watches[i]->path, monitor->watches[i]->watch ? monitor->watches[i]->watch->name : "<unknown>");
			watch_info_destroy(monitor->watches[i]);
		}
	}
	free(monitor->watches);

	/* Pass 3: Add new and modified watches */
	monitor->watches = retained_watches;
	monitor->watch_count = retained_count;

	for (int i = 0; i < new_config->watch_count; i++) {
        if (new_config->watches[i] == new_config_watch_entry) continue;
		if (!new_watch_processed[i]) {
			watch_entry_t *watch_to_add = new_config->watches[i];
			log_message(LOG_LEVEL_DEBUG, "Watch added or modified: %s (watch: %s)", watch_to_add->path, watch_to_add->name);
			if (!monitor_add_watch(monitor, watch_to_add)) {
				log_message(LOG_LEVEL_ERR, "Failed to add new/modified watch for %s", watch_to_add->path);
			}
		}
	}
	
	/* Finalization */
	free(new_watch_processed);
	config_destroy(old_config);
	monitor->config = new_config;

	log_message(LOG_LEVEL_INFO, "Configuration reload complete: %d active watches", monitor->watch_count);
	return true;
}

/* Schedule an event for delayed processing */
void schedule_delayed_event(monitor_t *monitor, watch_entry_t *watch, file_event_t *event, entity_type_t entity_type) {
	if (!monitor || !watch || !event || watch->processing_delay <= 0) {
		return;
	}
	
	/* Expand delayed events array if needed */
	if (monitor->delayed_event_count >= monitor->delayed_event_capacity) {
		int new_capacity = monitor->delayed_event_capacity == 0 ? 16 : monitor->delayed_event_capacity * 2;
		delayed_event_t *new_events = realloc(monitor->delayed_events, new_capacity * sizeof(delayed_event_t));
		if (!new_events) {
			log_message(LOG_LEVEL_ERR, "Failed to allocate memory for delayed events");
			return;
		}
		monitor->delayed_events = new_events;
		monitor->delayed_event_capacity = new_capacity;
	}
	
	/* Calculate process time */
	struct timespec process_time;
	clock_gettime(CLOCK_MONOTONIC, &process_time);
	process_time.tv_sec += watch->processing_delay / 1000;
	process_time.tv_nsec += (watch->processing_delay % 1000) * 1000000;
	
	/* Normalize nsec */
	if (process_time.tv_nsec >= 1000000000) {
		process_time.tv_sec++;
		process_time.tv_nsec -= 1000000000;
	}
	
	/* Store the delayed event */
	delayed_event_t *delayed = &monitor->delayed_events[monitor->delayed_event_count++];
	delayed->event.path = strdup(event->path);
	delayed->event.type = event->type;
	delayed->event.time = event->time;
	delayed->event.wall_time = event->wall_time;
	delayed->event.user_id = event->user_id;
	delayed->watch = watch;
	delayed->entity_type = entity_type;
	delayed->process_time = process_time;
	
	log_message(LOG_LEVEL_DEBUG, "Scheduled delayed event for %s (watch: %s) in %d ms", 
			  event->path, watch->name, watch->processing_delay);
}

/* Process delayed events that are ready */
void process_delayed_events(monitor_t *monitor) {
	if (!monitor || !monitor->delayed_events || monitor->delayed_event_count == 0) {
		return;
	}
	
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	
	int processed = 0;
	for (int i = 0; i < monitor->delayed_event_count; i++) {
		delayed_event_t *delayed = &monitor->delayed_events[i];
		
		/* Check if this event is ready to process */
		if (now.tv_sec > delayed->process_time.tv_sec ||
			(now.tv_sec == delayed->process_time.tv_sec && now.tv_nsec >= delayed->process_time.tv_nsec)) {
			
			log_message(LOG_LEVEL_DEBUG, "Processing delayed event for %s (watch: %s)", 
					  delayed->event.path, delayed->watch->name);
			
			/* Process the event */
			process_event(delayed->watch, &delayed->event, delayed->entity_type);
			
			/* Free the path string */
			free(delayed->event.path);
			
			/* Mark as processed */
			processed++;
			
			/* Move the last event to this position to avoid gaps */
			if (i < monitor->delayed_event_count - 1) {
				monitor->delayed_events[i] = monitor->delayed_events[monitor->delayed_event_count - 1];
				i--; /* Reprocess this position */
			}
			monitor->delayed_event_count--;
		}
	}
	
	if (processed > 0) {
		log_message(LOG_LEVEL_DEBUG, "Processed %d delayed events", processed);
	}
}

/* Stop the monitor by setting the running flag to false */
void monitor_stop(monitor_t *monitor) {
	if (monitor == NULL) {
		return;
	}
	
	monitor->running = false;
}
