#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
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

/* Watched file/directory information */
typedef struct {
	int wd;                 /* Watch descriptor (file descriptor) */
	char *path;             /* Full path */
	watch_entry_t *watch;   /* Associated watch entry */
} watch_info_t;

/* Monitor structure */
struct monitor {
	int kq;                 /* Kqueue descriptor */
	config_t *config;       /* Configuration */
	watch_info_t **watches; /* Array of watch information */
	int watch_count;        /* Number of watches */
	bool running;           /* Monitor running flag */
};

/* Create a new monitor */
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

/* Free watched info */
static void watch_info_destroy(watch_info_t *info) {
	if (info == NULL) {
		return;
	}
	
	if (info->wd >= 0) {
		close(info->wd);
	}
	
	free(info->path);
	free(info);
}

/* Destroy a monitor */
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

/* Add a watch info to the monitor */
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

/* Find a watch info by path */
static watch_info_t *monitor_find_watch_info_by_path(monitor_t *monitor, const char *path) {
	for (int i = 0; i < monitor->watch_count; i++) {
		if (strcmp(monitor->watches[i]->path, path) == 0) {
			return monitor->watches[i];
		}
	}
	
	return NULL;
}

/* Find a watch info by watch descriptor */
static watch_info_t *monitor_find_watch_info_by_wd(monitor_t *monitor, int wd) {
	for (int i = 0; i < monitor->watch_count; i++) {
		if (monitor->watches[i]->wd == wd) {
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

/* Helper function to check if a path is hidden */
static bool is_hidden_path(const char *path) {
	/* Get the basename from the path */
	const char *basename = strrchr(path, '/');
	if (basename) {
		basename++; /* Skip the slash */
	} else {
		basename = path; /* No slash, use the whole path */
	}

	/* Check if the basename starts with a dot (hidden) */
	return basename[0] == '.';
}

/* Check if a path is contained within a watch path */
static bool is_path_in_watch(const char *path, const char *watch_path) {
	size_t watch_len = strlen(watch_path);
	
	/* Check if the path starts with the watch path */
	if (strncmp(path, watch_path, watch_len) == 0) {
		/* Make sure it's a complete match or the watch path is followed by a slash */
		if (path[watch_len] == '\0' || path[watch_len] == '/') {
			return true;
		}
	}
	
	return false;
}

/* Recursively add watches for a directory */
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
	
	/* First, add a watch for the directory itself, unless we're skipping existing and it's already monitored */
	if (!skip_existing || monitor_find_watch_info_by_path(monitor, dir_path) == NULL) {
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
		
		if (!monitor_add_watch_info(monitor, info)) {
			watch_info_destroy(info);
			closedir(dir);
			return false;
		}
		
		if (!monitor_add_kqueue_watch(monitor, info)) {
			closedir(dir);
			return false;
		}
		
		if (!skip_existing) {
			log_message(LOG_LEVEL_DEBUG, "Added watch for %s", dir_path);
		} else {
			log_message(LOG_LEVEL_DEBUG, "Added new directory to monitoring: %s", dir_path);
		}
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
			
			/* Skip if we're ignoring existing paths and this one is already monitored */
			if (skip_existing && monitor_find_watch_info_by_path(monitor, path) != NULL) {
				continue;
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

/* Add a watch for a file or directory */
bool monitor_add_watch(monitor_t *monitor, watch_entry_t *watch) {
	struct stat st;
	
	if (monitor == NULL || watch == NULL) {
		log_message(LOG_LEVEL_ERR, "Invalid arguments to monitor_add_watch");
		return false;
	}
	
	/* Check if we already have a watch for this path */
	if (monitor_find_watch_info_by_path(monitor, watch->path) != NULL) {
		log_message(LOG_LEVEL_WARNING, "Already watching %s", watch->path);
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
		
		return monitor_add_dir_recursive(monitor, watch->path, watch, false);  // false = don't skip existing
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

/* Set up the monitor */
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

/* Convert kqueue flags to event types */
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
static void process_deferred_dir_scans(monitor_t *monitor) {
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	
	/* Tracking variables for debugging */
	int total_dir_watches = 0;
	int watches_with_activity = 0;
	int commands_executed = 0;
	
	/* Process watches in order - this allows us to execute commands in a predictable order */
	for (int i = 0; i < monitor->config->watch_count; i++) {
		watch_entry_t *watch = monitor->config->watches[i];
		
		/* Skip non-directory watches */
		if (watch->type != WATCH_DIRECTORY) {
			continue;
		}
		
		total_dir_watches++;
		
		/* Get the entity state for this directory */
		entity_state_t *state = get_entity_state(watch->path, ENTITY_DIRECTORY, watch);
		if (!state) {
			log_message(LOG_LEVEL_WARNING, "Failed to get entity state for %s (watch: %s)", 
					  watch->path, watch->name);
			continue;
		}
		
		/* Log the state we found */
		log_message(LOG_LEVEL_DEBUG, 
				  "Checking deferred watch %s: path=%s, in_progress=%s", 
				  watch->name, watch->path, 
				  state->activity_in_progress ? "true" : "false");
		
		/* Check if this directory has deferred activity */
		if (state->activity_in_progress) {
			watches_with_activity++;
			
			/* Check if quiet period has elapsed */
			if (is_quiet_period_elapsed(state, &now)) {
				log_message(LOG_LEVEL_INFO, 
						  "Quiet period elapsed for %s (watch: %s), processing deferred events", 
						  watch->path, watch->name);
				
				/* Mark activity as complete */
				state->activity_in_progress = false;
				
				/* For recursive directories, scan for new entries */
				if (watch->recursive) {
					log_message(LOG_LEVEL_DEBUG, "Scanning directory %s for new entries", watch->path);
					monitor_add_dir_recursive(monitor, watch->path, watch, true);  /* true = skip existing */
				}
				
				/* Create synthetic event for command execution */
				file_event_t synthetic_event = {
					.path = state->path,
					.type = EVENT_CONTENT,  /* Directory content change */
					.time = state->last_update,
					.wall_time = state->wall_time,
					.user_id = getuid()
				};
				
				/* Execute command */
				log_message(LOG_LEVEL_INFO, "Executing deferred command for %s (watch: %s) after quiet period", 
						  watch->path, watch->name);
				
				if (command_execute(watch, &synthetic_event)) {
					commands_executed++;
					log_message(LOG_LEVEL_INFO, "Command execution successful");
				} else {
					log_message(LOG_LEVEL_WARNING, "Command execution failed");
				}
				
				/* Reset state flags after execution */
				state->content_changed = false;
				state->metadata_changed = false;
				state->structure_changed = false;
			} else {
				log_message(LOG_LEVEL_DEBUG, "Quiet period not yet elapsed for %s (watch: %s)", 
						  watch->path, watch->name);
			}
		}
	}
	
	/* Log summary of deferred processing */
	if (watches_with_activity > 0 || commands_executed > 0) {
		log_message(LOG_LEVEL_DEBUG, 
				  "Deferred processing summary: total_dir_watches=%d, with_activity=%d, commands_executed=%d",
				  total_dir_watches, watches_with_activity, commands_executed);
	}
}

/* Process events from kqueue */
bool monitor_process_events(monitor_t *monitor) {
	struct kevent events[MAX_EVENTS];
	int nev;
	struct timespec timeout;
	
	if (monitor == NULL || monitor->kq < 0) {
		log_message(LOG_LEVEL_ERR, "Invalid monitor state");
		return false;
	}
	
	/* Set timeout for kevent to be responsive but not too CPU-intensive */
	timeout.tv_sec = 0;
	timeout.tv_nsec = 100000000;  /* 100ms timeout */
	
	/* Wait for events with timeout */
	nev = kevent(monitor->kq, NULL, 0, events, MAX_EVENTS, &timeout);
	if (nev == -1) {
		if (errno == EINTR) {
			/* Interrupted, probably by a signal - just return */
			return true;
		}
		
		log_message(LOG_LEVEL_ERR, "kevent error: %s", strerror(errno));
		return false;
	}
	
	/* Process events */
	for (int i = 0; i < nev; i++) {
		watch_info_t *info = monitor_find_watch_info_by_wd(monitor, events[i].ident);
		if (info == NULL) {
			log_message(LOG_LEVEL_WARNING, "Received event for unknown watch descriptor: %d", 
					  (int)events[i].ident);
			continue;
		}
		
		/* Create file event */
		file_event_t event;
		memset(&event, 0, sizeof(event));
		
		event.path = info->path;
		event.type = flags_to_event_type(events[i].fflags);
		clock_gettime(CLOCK_MONOTONIC, &event.time);
		clock_gettime(CLOCK_REALTIME, &event.wall_time);
		event.user_id = getuid();
		
		/* Determine entity type from watch info */
		entity_type_t entity_type = (info->watch->type == WATCH_FILE) ? 
								  ENTITY_FILE : ENTITY_DIRECTORY;
		
		/* Track if we've processed this as a direct watch or parent watch */
		bool direct_processed = false;
		bool parent_match_found = false;
		
		/* Process for all parent watches that match this path */
		for (int j = 0; j < monitor->config->watch_count; j++) {
			watch_entry_t *watch = monitor->config->watches[j];
			
			/* Check if this path matches direct watch (exact path match) */
			if (strcmp(watch->path, event.path) == 0) {
				log_message(LOG_LEVEL_DEBUG, "Processing direct event for %s (watch: %s)", 
						  event.path, watch->name);
				process_event(watch, &event, entity_type);
				direct_processed = true;
				continue;
			}
			
			/* Check for parent directory relationship */
			if (watch->type == WATCH_DIRECTORY && is_path_in_watch(event.path, watch->path)) {
				parent_match_found = true;
				log_message(LOG_LEVEL_DEBUG, "Found parent watch for event in %s: %s (path: %s)", 
						  event.path, watch->name, watch->path);
				
				/* Create a modified event with the watch path (not the actual event path) */
				file_event_t parent_event = event;
				parent_event.path = watch->path;  /* Use the watch path for parent directory */
				
				/* Process event for this parent watch */
				process_event(watch, &parent_event, ENTITY_DIRECTORY);
			}
		}
		
		/* If it's a direct event for the watch that received it and wasn't processed yet */
		if (!direct_processed && !parent_match_found) {
			/* Process it for the direct watch that received it */
			process_event(info->watch, &event, entity_type);
		}
		
		/* Handle file deletion if needed */
		if (events[i].fflags & NOTE_DELETE) {
			/* Close the file descriptor */
			close(info->wd);
			
			/* Try to re-open the file */
			info->wd = open(info->path, O_RDONLY);
			if (info->wd == -1) {
				log_message(LOG_LEVEL_WARNING, "Failed to re-open %s after deletion: %s", 
						  info->path, strerror(errno));
				continue;
			}
			
			/* Re-add the kqueue watch */
			if (!monitor_add_kqueue_watch(monitor, info)) {
				log_message(LOG_LEVEL_WARNING, "Failed to re-add kqueue watch for %s after deletion", 
						  info->path);
			}
		}
	}
	
	/* Always process deferred directory scans */
	process_deferred_dir_scans(monitor);
	
	return true;
}

/* Start the monitor */
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
			log_message(LOG_LEVEL_ERR, "Error processing events");
			return false;
		}
	}
	
	return true;
}

/* Stop the monitor */
void monitor_stop(monitor_t *monitor) {
	if (monitor == NULL) {
		return;
	}
	
	monitor->running = false;
}
