#include "pending.h"

#include <dirent.h>
#include <fnmatch.h>
#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "logger.h"
#include "monitor.h"
#include "registry.h"

/* Check if a path contains glob patterns */
static bool pending_has_glob(const char *path) {
	if (!path) return false;
	return strpbrk(path, "*?[") != NULL;
}

/* Check if path exists and is a directory */
static bool pending_is_dir(const char *path) {
	if (!path) return false;
	struct stat info;
	return (stat(path, &info) == 0 && S_ISDIR(info.st_mode));
}

/* Join two path components */
static char *pending_join(const char *parent, const char *component) {
	if (!parent || !component) return NULL;

	int parent_len = strlen(parent);
	int component_len = strlen(component);
	bool needs_slash = (parent_len > 0 && parent[parent_len - 1] != '/');

	char *result = malloc(parent_len + (needs_slash ? 1 : 0) + component_len + 1);
	if (!result) return NULL;

	strcpy(result, parent);
	if (needs_slash) strcat(result, "/");
	strcat(result, component);
	return result;
}

/* Find watcher by path and watch reference */
static watcher_t *pending_watcher(monitor_t *monitor, const char *path, watchref_t watchref) {
	if (!monitor || !path || !watchref_valid(watchref)) return NULL;

	for (int i = 0; i < monitor->num_watches; i++) {
		if (strcmp(monitor->watches[i]->path, path) == 0 && watchref_equal(monitor->watches[i]->watchref, watchref)) {
			return monitor->watches[i];
		}
	}
	return NULL;
}

/* Find the deepest existing parent directory of a path */
static char *pending_parent(const char *path, bool stop_at_glob) {
	if (!path) return NULL;

	char *test_path = strdup(path);
	if (!test_path) return NULL;

	while (strlen(test_path) > 1) {
		if (pending_is_dir(test_path)) {
			return test_path;
		}

		if (stop_at_glob && pending_has_glob(test_path)) {
			char *last_slash = strrchr(test_path, '/');
			if (!last_slash || last_slash == test_path) break;
			*last_slash = '\0';
			continue;
		}

		char *last_slash = strrchr(test_path, '/');
		if (!last_slash || last_slash == test_path) break;
		*last_slash = '\0';
	}

	if (pending_is_dir("/")) {
		strcpy(test_path, "/");
		return test_path;
	}

	free(test_path);
	return NULL;
}

/* Extract next path component */
static char *pending_component(const char *full_path, const char *parent_path, bool return_full_path) {
	if (!full_path || !parent_path) return NULL;

	int parent_len = strlen(parent_path);
	int path_len = strlen(full_path);

	if (path_len <= parent_len || strncmp(full_path, parent_path, parent_len) != 0) {
		return NULL;
	}

	const char *start = full_path + parent_len;
	if (*start == '/') start++;

	const char *end = strchr(start, '/');
	if (!end) end = start + strlen(start);

	int component_len = end - start;
	if (component_len == 0) return NULL;

	char *component = malloc(component_len + 1);
	if (!component) return NULL;
	strncpy(component, start, component_len);
	component[component_len] = '\0';

	if (return_full_path) {
		char *full_path = pending_join(parent_path, component);
		free(component);
		return full_path;
	}

	return component;
}

/* Check if a created path matches the glob pattern */
static bool glob_matches(const char *created_path, const char *glob_pattern) {
	if (!created_path || !glob_pattern) return false;

	/* Use fnmatch for glob pattern matching */
	return fnmatch(glob_pattern, created_path, FNM_PATHNAME) == 0;
}

/* Find matching files in a directory for a glob component */
static bool glob_find_matches(const char *parent_path, const watch_t *watch, const char *glob_component, char ***matches, int *match_count) {
	if (!parent_path || !glob_component || !matches || !match_count) {
		return false;
	}

	*matches = NULL;
	*match_count = 0;

	DIR *dir = opendir(parent_path);
	if (!dir) {
		return false;
	}

	/* First pass: count matches */
	struct dirent *entry;
	int count = 0;
	while ((entry = readdir(dir)) != NULL) {
		/* Skip . and .. */
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
			continue;
		}

		/* Check if filename matches glob pattern */
		if (fnmatch(glob_component, entry->d_name, 0) == 0) {
			/* Check against exclude patterns */
			char *full_path = pending_join(parent_path, entry->d_name);
			if (full_path) {
				if (!watch || !config_exclude_match(watch, full_path)) {
					count++;
				}
				free(full_path);
			}
		}
	}

	if (count == 0) {
		closedir(dir);
		return true; /* No matches, but not an error */
	}

	/* Allocate array for matches */
	*matches = malloc(count * sizeof(char *));
	if (!*matches) {
		closedir(dir);
		return false;
	}

	/* Second pass: collect matches */
	rewinddir(dir);
	int index = 0;
	while ((entry = readdir(dir)) != NULL && index < count) {
		/* Skip . and .. */
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
			continue;
		}

		/* Check if filename matches glob pattern */
		if (fnmatch(glob_component, entry->d_name, 0) == 0) {
			/* Create full path */
			char *full_path = pending_join(parent_path, entry->d_name);
			if (full_path) {
				/* Check against exclude patterns */
				if (!watch || !config_exclude_match(watch, full_path)) {
					(*matches)[index++] = full_path;
				} else {
					free(full_path); /* Free excluded path */
				}
			}
		}
	}

	closedir(dir);
	*match_count = index;
	return true;
}

/* Destroy a pending watch entry */
void pending_destroy(pending_t *pending) {
	if (!pending) return;

	free(pending->target_path);
	free(pending->current_parent);
	free(pending->next_component);
	free(pending->unresolved_path);
	free(pending->glob_pattern);
	free(pending);
}

/* Remove a pending watch from the monitor's pending list */
void pending_remove(monitor_t *monitor, int index) {
	if (!monitor || index < 0 || index >= monitor->num_pending) {
		return;
	}

	pending_t *pending = monitor->pending[index];

	/* Clean up intermediate watch if this is a glob pattern */
	if (pending && pending->is_glob && watchref_valid(pending->parentref)) {
		registry_deactivate(monitor->registry, pending->parentref);
	}

	pending_destroy(pending);

	/* Shift remaining entries */
	for (int j = index; j < monitor->num_pending - 1; j++) {
		monitor->pending[j] = monitor->pending[j + 1];
	}
	monitor->num_pending--;
}

/* Generate unique name for individual glob intermediate watch */
static char *pending_glob_name(watchref_t original_ref) {
	static uint32_t counter = 0;
	char *name = malloc(64);
	if (!name) return NULL;
	snprintf(name, 64, "__glob_%u_%u_%u__", original_ref.watch_id, original_ref.generation, ++counter);
	return name;
}

/* Create individual glob intermediate watch with properties from original watch */
static watchref_t pending_glob_watch(monitor_t *monitor, const watch_t *original_watch, watchref_t original_ref, const char *parent_path) {
	if (!monitor || !original_watch || !parent_path) {
		return WATCH_REF_INVALID;
	}

	watch_t *glob_watch = calloc(1, sizeof(watch_t));
	if (!glob_watch) {
		log_message(ERROR, "Failed to allocate memory for individual glob watch");
		return WATCH_REF_INVALID;
	}

	/* Create unique name for this glob watch */
	glob_watch->name = pending_glob_name(original_ref);
	if (!glob_watch->name) {
		free(glob_watch);
		return WATCH_REF_INVALID;
	}

	glob_watch->path = strdup(parent_path);
	glob_watch->target = WATCH_DIRECTORY;
	glob_watch->filter = EVENT_STRUCTURE;
	glob_watch->command = NULL;
	glob_watch->is_dynamic = false;
	glob_watch->source_pattern = NULL;

	/* Copy relevant properties from original watch */
	glob_watch->recursive = original_watch->recursive;
	glob_watch->hidden = original_watch->hidden;

	/* Add to registry */
	watchref_t glob_ref = registry_add(monitor->registry, glob_watch);
	if (!watchref_valid(glob_ref)) {
		log_message(ERROR, "Failed to add individual glob watch to registry");
		config_destroy_watch(glob_watch);
		return WATCH_REF_INVALID;
	}

	log_message(DEBUG, "Created individual glob watch '%s' for pattern from watch %u:%u",
				glob_watch->name, original_ref.watch_id, original_ref.generation);

	return glob_ref;
}

/* Add a pending watch to the monitor's pending list */
bool pending_add(monitor_t *monitor, const char *target_path, watchref_t watchref) {
	watch_t *watch = registry_get(monitor->registry, watchref);
	if (!watch) {
		log_message(ERROR, "Invalid watch reference for pending watch");
		return false;
	}
	if (!monitor || !target_path || !watch) {
		return false;
	}

	/* Check if this is a glob pattern */
	bool is_glob = pending_has_glob(target_path);
	char *parent = NULL;
	char *next_component = NULL;

	if (is_glob) {
		/* Handle glob pattern */
		parent = pending_parent(target_path, true);
		if (!parent) {
			log_message(ERROR, "No existing parent found for glob pattern: %s", target_path);
			return false;
		}

		/* Get the glob component to match */
		next_component = pending_component(target_path, parent, false);
		if (!next_component) {
			log_message(ERROR, "Unable to determine glob component for pattern: %s", target_path);
			free(parent);
			return false;
		}
	} else {
		/* Handle exact path (existing logic) */
		parent = pending_parent(target_path, false);
		if (!parent) {
			log_message(ERROR, "No existing parent found for path: %s", target_path);
			return false;
		}

		next_component = pending_component(target_path, parent, true);
		if (!next_component) {
			log_message(ERROR, "Unable to determine next component for path: %s", target_path);
			free(parent);
			return false;
		}
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
	pending->is_glob = is_glob;
	pending->unresolved_path = is_glob ? strdup(parent) : NULL;
	pending->glob_pattern = is_glob ? strdup(target_path) : NULL;
	pending->watchref = watchref;
	pending->parent_watcher = NULL;
	pending->parentref = WATCH_REF_INVALID;

	/* Add watch on the parent directory */
	watchref_t pending_watchref;
	if (is_glob) {
		/* Create individual glob intermediate watch with correct properties */
		pending_watchref = pending_glob_watch(monitor, watch, watchref, parent);
		if (!watchref_valid(pending_watchref)) {
			log_message(ERROR, "Failed to create individual glob watch for %s", target_path);
			pending_destroy(pending);
			return false;
		}
		/* Store intermediate watch reference for cleanup */
		pending->parentref = pending_watchref;
	} else {
		pending_watchref = watchref;
	}

	if (!monitor_path(monitor, parent, pending_watchref)) {
		log_message(WARNING, "Failed to add parent watch for %s, parent: %s", target_path, parent);
		/* Clean up intermediate watch if it was created */
		if (is_glob && watchref_valid(pending->parentref)) {
			registry_deactivate(monitor->registry, pending->parentref);
		}
		pending_destroy(pending);
		return false;
	}

	/* Find the watcher we just created for the parent */
	pending->parent_watcher = pending_watcher(monitor, parent, pending_watchref);

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

	log_message(DEBUG, "Added pending watch (%s): target=%s, parent=%s, next=%s",
				is_glob ? "glob" : "exact", target_path, parent, next_component);
	return true;
}

/* Promote a fully matched glob path to a dynamic watch */
static void pending_promote_match(monitor_t *monitor, pending_t *pending, const char *path) {
	if (!monitor || !pending || !path) {
		log_message(ERROR, "Invalid parameters to pending_promote_match");
		return;
	}

	log_message(DEBUG, "Promoting glob match: %s from pattern %s",
				path, pending->glob_pattern ? pending->glob_pattern : "unknown");

	/* Check if a watch for this path with the same name already exists */
	if (monitor->config && path) {
		watch_t *pending_watch = registry_get(monitor->registry, pending->watchref);
		if (!pending_watch) {
			log_message(ERROR, "Invalid pending watch reference during promotion check");
			return;
		}

		/* Check for existing watches with same path and name */
		uint32_t num_active = 0;
		watchref_t *watchrefs = registry_active(monitor->registry, &num_active);
		if (watchrefs) {
			for (uint32_t i = 0; i < num_active; i++) {
				watch_t *watch = registry_get(monitor->registry, watchrefs[i]);
				if (watch && watch->path && watch->name && strcmp(watch->path, path) == 0 &&
					strcmp(watch->name, pending_watch->name) == 0) {
					log_message(INFO, "Watch for %s with name '%s' from pattern %s already exists, skipping promotion",
								path, watch->name, pending->glob_pattern);
					free(watchrefs);
					return;
				}
			}
			free(watchrefs);
		}
	}

	/* Create a dynamic watch from the original's properties */
	watch_t *pending_watch = registry_get(monitor->registry, pending->watchref);
	if (!pending_watch) {
		log_message(ERROR, "Invalid pending watch reference during resolution");
		return;
	}

	/* Clone watch for resolved path */
	watch_t *resolved_watch = config_clone_watch(pending_watch);
	if (!resolved_watch) {
		log_message(ERROR, "Failed to clone watch for resolved path: %s", path);
		return;
	}

	/* Update path and set dynamic fields */
	free(resolved_watch->path);
	resolved_watch->path = strdup(path);
	resolved_watch->is_dynamic = true;
	resolved_watch->source_pattern = strdup(pending->glob_pattern);

	if (!resolved_watch->path || !resolved_watch->source_pattern) {
		log_message(ERROR, "Failed to allocate strings for resolved watch");
		config_destroy_watch(resolved_watch);
		return;
	}

	/* Add dynamic watch to config */
	if (!config_add_watch(monitor->config, monitor->registry, resolved_watch)) {
		log_message(ERROR, "Failed to add dynamic watch to config: %s", path);
		/* Clean up manually since config addition failed */
		free(resolved_watch->name);
		free(resolved_watch->path);
		free(resolved_watch->command);
		free(resolved_watch);
		return;
	}

	/* Find the watch that was just added to the registry */
	watchref_t resolved_ref = WATCH_REF_INVALID;
	uint32_t num_active = 0;
	watchref_t *watchrefs = registry_active(monitor->registry, &num_active);
	if (watchrefs && num_active > 0) {
		/* Find the watch with matching path and name */
		for (uint32_t i = 0; i < num_active; i++) {
			watch_t *watch = registry_get(monitor->registry, watchrefs[i]);
			if (watch && watch->path && watch->name && strcmp(watch->path, path) == 0 &&
				strcmp(watch->name, resolved_watch->name) == 0) {
				resolved_ref = watchrefs[i];
				break;
			}
		}
		free(watchrefs);
	}

	if (watchref_valid(resolved_ref)) {
		log_message(INFO, "Adding resolved watch to monitoring system: %s (watchref %u:%u)", path,
					resolved_ref.watch_id, resolved_ref.generation);
	} else {
		log_message(ERROR, "Could not find watchref for newly added watch: %s", path);
		return;
	}

	if (monitor_add(monitor, resolved_ref, true)) {
		log_message(INFO, "Successfully promoted glob match: %s from pattern %s", path, pending->glob_pattern);
	} else {
		log_message(WARNING, "Failed to promote glob match: %s from pattern %s", path, pending->glob_pattern);
		/* Remove from config since monitor add failed */
		config_remove_watch(monitor->config, monitor->registry, resolved_ref);
	}
}

/* Create a new pending watch for an intermediate directory that matches a glob component */
static void pending_intermediate(monitor_t *monitor, pending_t *pending, const char *path) {
	/* For globs, this means we found an intermediate directory that matches part of the pattern */
	if (!pending_is_dir(path)) {
		return; /* Not a directory, so it can't be an intermediate step */
	}

	/* Check if a pending watch for this intermediate parent, glob pattern, and watchref already exists */
	for (int i = 0; i < monitor->num_pending; i++) {
		pending_t *p = monitor->pending[i];
		if (p->is_glob && strcmp(p->current_parent, path) == 0 && p->glob_pattern &&
			strcmp(p->glob_pattern, pending->glob_pattern) == 0 && watchref_equal(p->watchref, pending->watchref)) {
			log_message(DEBUG, "Pending watch for intermediate path %s with same watchref already exists", path);
			return;
		}
	}

	log_message(DEBUG, "Glob intermediate directory created: %s", path);

	/* Create a new pending watch for this path */
	pending_t *new_pending = calloc(1, sizeof(pending_t));
	if (!new_pending) {
		log_message(ERROR, "Failed to allocate memory for intermediate pending watch");
		return;
	}

	new_pending->target_path = strdup(pending->target_path);
	new_pending->current_parent = strdup(path); /* The resolved path */

	/* Construct the new unresolved path by appending the component that just matched */
	new_pending->unresolved_path = pending_join(pending->unresolved_path, pending->next_component);

	if (new_pending->unresolved_path) {
		new_pending->next_component = pending_component(pending->glob_pattern, new_pending->unresolved_path, false);
	} else {
		new_pending->next_component = NULL;
	}

	new_pending->is_glob = true;
	new_pending->glob_pattern = strdup(pending->glob_pattern);
	new_pending->watchref = pending->watchref;
	new_pending->parent_watcher = NULL;
	new_pending->parentref = WATCH_REF_INVALID;

	/* Create individual glob watch for this intermediate directory */
	watch_t *orig_watch = registry_get(monitor->registry, pending->watchref);
	if (!orig_watch) {
		log_message(ERROR, "Invalid original watch reference in pending_intermediate");
		pending_destroy(new_pending);
		return;
	}

	watchref_t parentref = pending_glob_watch(monitor, orig_watch, pending->watchref, path);
	if (!watchref_valid(parentref)) {
		log_message(ERROR, "Failed to create intermediate glob watch for %s", path);
		pending_destroy(new_pending);
		return;
	}

	/* Store intermediate watch reference for cleanup */
	new_pending->parentref = parentref;

	if (new_pending->next_component && monitor_tree(monitor, path, parentref)) {
		/* Find the watcher for this parent */
		new_pending->parent_watcher = pending_watcher(monitor, path, parentref);

		/* Add to pending array */
		pending_t **new_pending_array = realloc(monitor->pending, (monitor->num_pending + 1) * sizeof(pending_t *));
		if (new_pending_array) {
			monitor->pending = new_pending_array;
			monitor->pending[monitor->num_pending] = new_pending;
			monitor->num_pending++;

			log_message(DEBUG, "Added new glob pending watch: target=%s, parent=%s, next=%s",
						new_pending->target_path, new_pending->current_parent, new_pending->next_component);

			/* Recursively process the new parent to handle pre-existing subdirectories */
			pending_process(monitor, new_pending->current_parent);
		} else {
			log_message(ERROR, "Failed to allocate memory for new pending array");
			/* Clean up intermediate watch */
			registry_deactivate(monitor->registry, parentref);
			pending_destroy(new_pending);
		}
	} else {
		log_message(WARNING, "Failed to add monitor or get next component for '%s'", path);
		/* Clean up intermediate watch */
		registry_deactivate(monitor->registry, parentref);
		pending_destroy(new_pending);
	}
}

/* Process a pending watch for a glob pattern */
static void pending_process_glob(monitor_t *monitor, pending_t *pending) {
	char **matches = NULL;
	int match_count = 0;

	/* Get the original watch to check exclude patterns */
	watch_t *watch = registry_get(monitor->registry, pending->watchref);

	if (!glob_find_matches(pending->current_parent, watch, pending->next_component, &matches, &match_count)) {
		return;
	}

	if (match_count > 0) {
		log_message(DEBUG, "Found %d glob matches in %s for pattern %s",
					match_count, pending->current_parent, pending->next_component);

		/* For each matching file, check if it completes the pattern */
		for (int m = 0; m < match_count; m++) {
			if (glob_matches(matches[m], pending->glob_pattern)) {
				pending_promote_match(monitor, pending, matches[m]);
			} else {
				pending_intermediate(monitor, pending, matches[m]);
			}
		}
	}

	/* Free the matches array */
	for (int m = 0; m < match_count; m++) {
		free(matches[m]);
	}
	free(matches);
}

/* Process a pending watch for an exact path */
static void pending_process_exact(monitor_t *monitor, pending_t *pending, int index) {
	if (pending_is_dir(pending->next_component) || access(pending->next_component, F_OK) == 0) {
		log_message(DEBUG, "Next component created: %s", pending->next_component);

		/* Check if this completes the full target path */
		if (strcmp(pending->next_component, pending->target_path) == 0) {
			/* Full path now exists - promote to regular watch */
			log_message(DEBUG, "Promoting pending watch to regular watch: %s", pending->target_path);

			if (monitor_add(monitor, pending->watchref, true)) {
				log_message(INFO, "Successfully promoted pending watch: %s", pending->target_path);
			} else {
				log_message(WARNING, "Failed to promote pending watch: %s", pending->target_path);
			}

			/* Remove from pending list */
			pending_remove(monitor, index);
		} else {
			/* Intermediate directory created - update pending watch */
			log_message(DEBUG, "Intermediate component created, updating pending watch: %s", pending->next_component);

			free(pending->current_parent);
			pending->current_parent = strdup(pending->next_component);

			free(pending->next_component);
			pending->next_component = pending_component(pending->target_path, pending->current_parent, true);

			if (!pending->next_component) {
				log_message(ERROR, "Failed to determine next component, removing pending watch");
				pending_remove(monitor, index);
				return;
			}

			/* Add watch on the new parent directory */
			if (!monitor_path(monitor, pending->current_parent, pending->watchref)) {
				log_message(WARNING, "Failed to add watch on new parent: %s", pending->current_parent);
				pending_remove(monitor, index);
				return;
			}

			/* Update parent watcher reference */
			pending->parent_watcher = pending_watcher(monitor, pending->current_parent, pending->watchref);

			log_message(DEBUG, "Updated pending watch: target=%s, new_parent=%s, next=%s",
						pending->target_path, pending->current_parent, pending->next_component);
		}
	}
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
			log_message(DEBUG, "Found pending watch for parent '%s', target '%s'", parent_path, pending->target_path);

			if (pending->is_glob) {
				pending_process_glob(monitor, pending);
			} else {
				pending_process_exact(monitor, pending, i);
			}
		}
	}
}

/* Clean up all pending watches */
void pending_cleanup(monitor_t *monitor) {
	if (!monitor || !monitor->pending) {
		return;
	}

	/* Use pending_remove() to ensure proper cleanup of intermediate watches */
	while (monitor->num_pending > 0) {
		pending_remove(monitor, monitor->num_pending - 1);
	}

	/* Clean up the pointer */
	free(monitor->pending);
	monitor->pending = NULL;
}

/* Handle deletion of parent directories that affect pending watches */
void pending_delete(monitor_t *monitor, const char *deleted_path) {
	if (!monitor || !deleted_path || monitor->num_pending == 0) {
		return;
	}

	size_t deleted_path_len = strlen(deleted_path);

	/* Iterate backwards to safely remove entries */
	for (int i = monitor->num_pending - 1; i >= 0; i--) {
		pending_t *pending = monitor->pending[i];

		/* Check if this pending watch is affected by the deletion */
		bool affected = (strcmp(pending->current_parent, deleted_path) == 0) ||
						(strncmp(pending->current_parent, deleted_path, deleted_path_len) == 0 &&
						 pending->current_parent[deleted_path_len] == '/');

		if (affected) {
			log_message(DEBUG, "Pending watch (%s) affected by deletion of %s: target=%s, current_parent=%s",
						pending->is_glob ? "glob" : "exact", deleted_path, pending->target_path, pending->current_parent);

			/* Remove and re-add to find new deepest parent */
			char *target_path = strdup(pending->target_path);
			watchref_t watchref = pending->watchref;

			pending_remove(monitor, i);

			if (target_path) {
				pending_add(monitor, target_path, watchref);
				free(target_path);
			}
		}
	}
}

char **glob_scan_paths(const char *pattern, int *count) {
	glob_t glob_result;
	memset(&glob_result, 0, sizeof(glob_result));

	int return_value = glob(pattern, GLOB_TILDE | GLOB_BRACE | GLOB_MARK, NULL, &glob_result);
	if (return_value != 0) {
		globfree(&glob_result);
		if (return_value != GLOB_NOMATCH) {
			log_message(WARNING, "glob() failed with return value %d for pattern %s", return_value, pattern);
		}
		*count = 0;
		return NULL;
	}

	*count = glob_result.gl_pathc;
	char **matches = malloc(*count * sizeof(char *));
	if (!matches) {
		globfree(&glob_result);
		*count = 0;
		return NULL;
	}

	for (size_t i = 0; i < glob_result.gl_pathc; i++) {
		matches[i] = strdup(glob_result.gl_pathv[i]);
	}

	globfree(&glob_result);
	return matches;
}

void glob_free_paths(char **matches, int count) {
	if (!matches) return;
	for (int i = 0; i < count; i++) {
		free(matches[i]);
	}
	free(matches);
}

/* Observer callback for watch deactivation */
void pending_handle_deactivation(watchref_t watchref, void *context) {
	monitor_t *monitor = (monitor_t *) context;
	if (!monitor || !monitor->pending) {
		return;
	}

	log_message(DEBUG, "Watch ID %u (gen %u) deactivated, cleaning up pending entries",
				watchref.watch_id, watchref.generation);

	int entries_removed = 0;

	/* Scan pending entries for the deactivated watch (iterate backwards for safe removal) */
	for (int i = monitor->num_pending - 1; i >= 0; i--) {
		pending_t *pending = monitor->pending[i];
		if (pending && watchref_equal(pending->watchref, watchref)) {
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
