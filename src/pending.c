#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "monitor.h"
#include "pending.h"
#include "logger.h"

/* Find the deepest existing parent directory of a path */
static char *find_deepest_parent(const char *path) {
	if (!path) return NULL;

	char *test_path = strdup(path);
	if (!test_path) return NULL;

	/* Work backwards from the full path to find the deepest existing parent */
	while (strlen(test_path) > 1) {
		struct stat info;
		if (stat(test_path, &info) == 0 && S_ISDIR(info.st_mode)) {
			return test_path; /* Found existing directory */
		}

		/* Remove the last component */
		char *last_slash = strrchr(test_path, '/');
		if (!last_slash || last_slash == test_path) {
			/* Reached root or no parent found */
			break;
		}
		*last_slash = '\0';
	}

	/* Check if root directory exists */
	struct stat info;
	if (stat("/", &info) == 0) {
		strcpy(test_path, "/");
		return test_path;
	}

	free(test_path);
	return NULL;
}

/* Get the next path component after the parent */
static char *get_next_component(const char *full_path, const char *parent_path) {
	if (!full_path || !parent_path) return NULL;

	int parent_len = strlen(parent_path);
	int path_len = strlen(full_path);

	/* Ensure full_path starts with parent_path */
	if (path_len <= parent_len || strncmp(full_path, parent_path, parent_len) != 0) {
		return NULL;
	}

	/* Skip past parent and any trailing slash */
	const char *start = full_path + parent_len;
	if (*start == '/') start++;

	/* Find the end of the next component */
	const char *end = strchr(start, '/');
	if (!end) end = start + strlen(start);

	/* Extract the component */
	int component_len = end - start;
	if (component_len == 0) return NULL;

	char *component = malloc(parent_len + 1 + component_len + 1);
	if (!component) return NULL;

	snprintf(component, parent_len + 1 + component_len + 1, "%s/%.*s", parent_path, component_len, start);
	return component;
}

/* Destroy a pending watch entry */
static void pending_destroy(pending_t *pending) {
	if (!pending) return;

	free(pending->target_path);
	free(pending->current_parent);
	free(pending->next_component);
	free(pending);
}

/* Remove a pending watch from the monitor's pending list */
static void pending_remove(monitor_t *monitor, int index) {
	if (!monitor || index < 0 || index >= monitor->num_pending) {
		return;
	}

	pending_destroy(monitor->pending[index]);

	/* Shift remaining entries */
	for (int j = index; j < monitor->num_pending - 1; j++) {
		monitor->pending[j] = monitor->pending[j + 1];
	}
	monitor->num_pending--;
}

/* Add a pending watch to the monitor's pending list */
bool pending_add(monitor_t *monitor, const char *target_path, watch_t *watch) {
	if (!monitor || !target_path || !watch) {
		return false;
	}

	/* Find the deepest existing parent */
	char *parent = find_deepest_parent(target_path);
	if (!parent) {
		log_message(ERROR, "No existing parent found for path: %s", target_path);
		return false;
	}

	/* Get the next component to wait for */
	char *next_component = get_next_component(target_path, parent);
	if (!next_component) {
		log_message(ERROR, "Unable to determine next component for path: %s", target_path);
		free(parent);
		return false;
	}

	/* Create pending watch entry */
	pending_t *pending = calloc(1, sizeof(pending_t));
	if (!pending) {
		log_message(ERROR, "Failed to allocate memory for pending watch");
		free(parent);
		free(next_component);
		return false;
	}

	pending->target_path = strdup(target_path);
	pending->current_parent = parent;
	pending->next_component = next_component;
	pending->watch = watch;
	pending->parent_watcher = NULL;

	/* Add watch on the parent directory */
	if (!monitor_path(monitor, parent, watch)) {
		log_message(WARNING, "Failed to add parent watch for %s, parent: %s", target_path, parent);
		pending_destroy(pending);
		return false;
	}

	/* Find the watcher we just created for the parent */
	for (int i = 0; i < monitor->num_watches; i++) {
		if (strcmp(monitor->watches[i]->path, parent) == 0 && monitor->watches[i]->watch == watch) {
			pending->parent_watcher = monitor->watches[i];
			break;
		}
	}

	/* Add to pending watches array */
	pending_t **new_pending = realloc(monitor->pending, (monitor->num_pending + 1) * sizeof(pending_t *));
	if (!new_pending) {
		log_message(ERROR, "Failed to allocate memory for pending watches array");
		pending_destroy(pending);
		return false;
	}

	monitor->pending = new_pending;
	monitor->pending[monitor->num_pending] = pending;
	monitor->num_pending++;

	log_message(DEBUG, "Added pending watch: target=%s, parent=%s, next=%s",
	            target_path, parent, next_component);
	return true;
}

/* Process pending watches for a given parent path */
void pending_process(monitor_t *monitor, const char *parent_path) {
	if (!monitor || !parent_path || monitor->num_pending == 0) {
		return;
	}

	for (int i = monitor->num_pending - 1; i >= 0; i--) {
		pending_t *pending = monitor->pending[i];

		/* Check if this pending watch is waiting for activity in this parent */
		if (strcmp(pending->current_parent, parent_path) == 0) {
			struct stat info;

			/* Check if the next component now exists */
			if (stat(pending->next_component, &info) == 0) {
				log_message(DEBUG, "Next component created: %s", pending->next_component);

				/* Check if this completes the full target path */
				if (strcmp(pending->next_component, pending->target_path) == 0) {
					/* Full path now exists - promote to regular watch */
					log_message(DEBUG, "Promoting pending watch to regular watch: %s", pending->target_path);

					if (monitor_add(monitor, pending->watch)) {
						log_message(INFO, "Successfully promoted pending watch: %s", pending->target_path);
					} else {
						log_message(WARNING, "Failed to promote pending watch: %s", pending->target_path);
					}

					/* Remove from pending list */
					pending_destroy(pending);
					for (int j = i; j < monitor->num_pending - 1; j++) {
						monitor->pending[j] = monitor->pending[j + 1];
					}
					monitor->num_pending--;
				} else {
					/* Intermediate directory created - update pending watch */
					log_message(DEBUG, "Intermediate component created, updating pending watch: %s", pending->next_component);

					free(pending->current_parent);
					pending->current_parent = strdup(pending->next_component);

					free(pending->next_component);
					pending->next_component = get_next_component(pending->target_path, pending->current_parent);

					if (!pending->next_component) {
						log_message(ERROR, "Failed to determine next component, removing pending watch");
						pending_destroy(pending);
						for (int j = i; j < monitor->num_pending - 1; j++) {
							monitor->pending[j] = monitor->pending[j + 1];
						}
						monitor->num_pending--;
						continue;
					}

					/* Add watch on the new parent directory */
					if (!monitor_path(monitor, pending->current_parent, pending->watch)) {
						log_message(WARNING, "Failed to add watch on new parent: %s", pending->current_parent);
						pending_destroy(pending);
						for (int j = i; j < monitor->num_pending - 1; j++) {
							monitor->pending[j] = monitor->pending[j + 1];
						}
						monitor->num_pending--;
						continue;
					}

					/* Update parent watcher reference */
					pending->parent_watcher = NULL;
					for (int j = 0; j < monitor->num_watches; j++) {
						if (strcmp(monitor->watches[j]->path, pending->current_parent) == 0 &&
						    monitor->watches[j]->watch == pending->watch) {
							pending->parent_watcher = monitor->watches[j];
							break;
						}
					}

					log_message(DEBUG, "Updated pending watch: target=%s, new_parent=%s, next=%s",
					            pending->target_path, pending->current_parent, pending->next_component);
				}
			}
		}
	}
}

/* Clean up all pending watches */
void pending_cleanup(monitor_t *monitor) {
	if (!monitor || !monitor->pending) {
		return;
	}

	for (int i = 0; i < monitor->num_pending; i++) {
		pending_destroy(monitor->pending[i]);
	}

	free(monitor->pending);
	monitor->pending = NULL;
	monitor->num_pending = 0;
}

/* Handle deletion of parent directories that affect pending watches */
void pending_delete(monitor_t *monitor, const char *deleted_path) {
	if (!monitor || !deleted_path || monitor->num_pending == 0) {
		return;
	}

	int deleted_path_len = strlen(deleted_path);

	/* Iterate backwards to safely remove entries */
	for (int i = monitor->num_pending - 1; i >= 0; i--) {
		pending_t *pending = monitor->pending[i];

		/* Check if this pending watch is affected by the deletion */
		bool affected = false;
		if (strcmp(pending->current_parent, deleted_path) == 0) {
			/* Exact match - current parent was deleted */
			affected = true;
		} else if (strncmp(pending->current_parent, deleted_path, deleted_path_len) == 0 &&
		           pending->current_parent[deleted_path_len] == '/') {
			/* current_parent is a subdirectory of deleted_path */
			affected = true;
		}

		if (affected) {
			log_message(DEBUG, "Pending watch affected by deletion of %s: target=%s, current_parent=%s",
			            deleted_path, pending->target_path, pending->current_parent);

			/* Find new deepest existing parent */
			char *new_parent = find_deepest_parent(pending->target_path);
			if (!new_parent) {
				log_message(WARNING, "No existing parent found for %s after deletion of %s, removing pending watch",
				            pending->target_path, deleted_path);
				pending_remove(monitor, i);
				continue;
			}

			/* Check if the new parent is different from the old parent */
			if (strcmp(new_parent, pending->current_parent) == 0) {
				/* No change needed - this shouldn't happen in deletion scenarios, but be safe */
				free(new_parent);
				continue;
			}

			/* Update pending watch to point to new parent */
			free(pending->current_parent);
			pending->current_parent = new_parent;

			free(pending->next_component);
			pending->next_component = get_next_component(pending->target_path, new_parent);

			if (!pending->next_component) {
				log_message(ERROR, "Failed to determine next component for %s after parent deletion, removing pending watch",
				            pending->target_path);
				pending_remove(monitor, i);
				continue;
			}

			/* Add watch on the new parent directory */
			if (!monitor_path(monitor, new_parent, pending->watch)) {
				log_message(WARNING, "Failed to add watch on new parent %s, removing pending watch", new_parent);
				pending_remove(monitor, i);
				continue;
			}

			/* Update parent watcher reference */
			pending->parent_watcher = NULL;
			for (int j = 0; j < monitor->num_watches; j++) {
				if (strcmp(monitor->watches[j]->path, new_parent) == 0 &&
				    monitor->watches[j]->watch == pending->watch) {
					pending->parent_watcher = monitor->watches[j];
					break;
				}
			}

			log_message(INFO, "Reset pending watch after deletion: target=%s, new_parent=%s, next=%s",
			            pending->target_path, new_parent, pending->next_component);
		}
	}
}
