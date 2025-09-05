#include "pending.h"

#include <dirent.h>
#include <errno.h>
#include <fnmatch.h>
#include <glob.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "events.h"
#include "logger.h"
#include "monitor.h"
#include "registry.h"

/* Check if a path contains glob patterns */
static bool pending_pattern(const char *target_path) {
	if (!target_path) return false;
	return strpbrk(target_path, "*?[") != NULL;
}

/* Check if path exists and is a directory */
static bool pending_directory(const char *dir_path) {
	if (!dir_path) return false;
	struct stat info;
	return (stat(dir_path, &info) == 0 && S_ISDIR(info.st_mode));
}

/* Join two path components */
static char *pending_join(const char *parent_path, const char *component) {
	if (!parent_path || !component) return NULL;

	int parent_len = strlen(parent_path);
	int component_len = strlen(component);
	bool needs_slash = (parent_len > 0 && parent_path[parent_len - 1] != '/');

	int size = parent_len + (needs_slash ? 1 : 0) + component_len + 1;
	char *result = malloc(size);
	if (!result) return NULL;

	/* Use snprintf for safer string construction */
	snprintf(result, size, "%s%s%s", parent_path, needs_slash ? "/" : "", component);
	return result;
}

/* Find watcher by path and watch reference using hash table lookup */
static watcher_t *pending_watcher(monitor_t *monitor, const char *target_path, watchref_t watchref) {
	if (!monitor || !target_path || !watchref_valid(watchref)) return NULL;
	if (monitor->bucket_count == 0) return NULL;

	/* Use hash table for path lookup */
	unsigned int bucket = watcher_hash(target_path, monitor->bucket_count);
	watcher_t *watcher = monitor->buckets[bucket];

	/* Check hash bucket for matching path and watchref */
	while (watcher) {
		if (watcher->path && strcmp(watcher->path, target_path) == 0 &&
			watchref_equal(watcher->watchref, watchref)) {
			return watcher;
		}
		watcher = watcher->next;
	}

	return NULL;
}

/* Check if a path is reasonable for monitoring */
static bool pending_reasonable(const char *path) {
	if (!path) {
		log_message(DEBUG, "Path validation failed: NULL path");
		return false;
	}

	size_t path_len = strlen(path);

	/* Reject empty paths */
	if (path_len == 0) {
		log_message(DEBUG, "Path validation failed: empty path");
		return false;
	}

	/* Reject root directory */
	if (strcmp(path, "/") == 0) {
		log_message(WARNING, "Path validation failed: cannot monitor root directory");
		return false;
	}

	/* Reject excessively long paths */
	if (path_len > 4096) { /* PATH_MAX is typically 4096 */
		log_message(WARNING, "Path validation failed: path too long (%zu bytes): %s", path_len, path);
		return false;
	}

	/* Reject paths that are too shallow and avoid critical system directories */
	int slash_count = 0;
	size_t len = strlen(path);
	size_t effective_len = len;

	if (len > 1 && path[len - 1] == '/') {
		effective_len = len - 1;
	}

	for (size_t i = 0; i < effective_len; i++) {
		if (path[i] == '/') slash_count++;
	}

	/* Must have at least 2 path components (e.g., "/home/user", not just "/usr") */
	if (slash_count < 2) {
		log_message(WARNING, "Path validation failed: path too shallow for safe monitoring: %s", path);
		return false;
	}

	/* Check for potentially problematic system directories */
	static const char *system_prefixes[] = {
		"/proc/", "/sys/", "/dev/", "/tmp/",
		NULL};

	for (int i = 0; system_prefixes[i]; i++) {
		if (strncmp(path, system_prefixes[i], strlen(system_prefixes[i])) == 0) {
			log_message(WARNING, "Path validation failed: system directory not recommended: %s", path);
			return false;
		}
	}

	/* Verify path accessibility */
	struct stat info;
	if (stat(path, &info) != 0) {
		log_message(DEBUG, "Path validation failed: cannot access path: %s (%s)", path, strerror(errno));
		return false;
	}

	/* Must be a directory for parent monitoring */
	if (!S_ISDIR(info.st_mode)) {
		log_message(DEBUG, "Path validation failed: not a directory: %s", path);
		return false;
	}

	return true;
}

/* Find the deepest existing parent directory of a path */
static char *pending_parent(const char *target_path) {
	if (!target_path) return NULL;

	char *test_path = strdup(target_path);
	if (!test_path) return NULL;

	char *deepest_valid = NULL;

	/* Walk up the directory tree to find the deepest existing directory */
	while (strlen(test_path) > 1) {
		if (pending_directory(test_path)) {
			/* Found an existing directory - validate if it's reasonable for monitoring */
			if (pending_reasonable(test_path)) {
				deepest_valid = strdup(test_path);
				break;
			} else {
				/* Directory exists but is not reasonable for monitoring */
				log_message(WARNING, "Found existing parent '%s' for target '%s', but it's not suitable for monitoring",
							test_path, target_path);
			}
		}

		char *last_slash = strrchr(test_path, '/');
		if (!last_slash || last_slash == test_path) break;
		*last_slash = '\0';
	}

	free(test_path);

	if (!deepest_valid) {
		log_message(WARNING, "No suitable parent directory found for pending watch: %s", target_path);
	} else {
		log_message(DEBUG, "Found suitable parent '%s' for target '%s'", deepest_valid, target_path);
	}

	return deepest_valid;
}

/* Extract next path component */
static char *pending_component(const char *full_path, const char *parent_path, bool resolve_path) {
	if (!full_path || !parent_path) return NULL;

	int parent_len = strlen(parent_path);
	int path_len = strlen(full_path);

	if (path_len <= parent_len || strncmp(full_path, parent_path, parent_len) != 0) return NULL;

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

	if (resolve_path) {
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
static bool glob_find(const char *parent_path, const watch_t *watch, const char *glob_component, char ***matches, int *match_count) {
	if (!parent_path || !glob_component || !matches || !match_count) return false;

	*matches = NULL;
	*match_count = 0;

	DIR *dir = opendir(parent_path);
	if (!dir) {
		return false;
	}

	/* First pass: count matches */
	struct dirent *dirent;
	int count = 0;
	while ((dirent = readdir(dir)) != NULL) {
		/* Skip . and .. */
		if (strcmp(dirent->d_name, ".") == 0 || strcmp(dirent->d_name, "..") == 0) {
			continue;
		}

		/* Check if filename matches glob pattern */
		if (fnmatch(glob_component, dirent->d_name, 0) == 0) {
			/* Check against exclude patterns */
			char *full_path = pending_join(parent_path, dirent->d_name);
			if (full_path) {
				if (!watch || !exclude_match(watch, full_path)) {
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
	while ((dirent = readdir(dir)) != NULL && index < count) {
		/* Skip . and .. */
		if (strcmp(dirent->d_name, ".") == 0 || strcmp(dirent->d_name, "..") == 0) {
			continue;
		}

		/* Check if filename matches glob pattern */
		if (fnmatch(glob_component, dirent->d_name, 0) == 0) {
			/* Create full path */
			char *full_path = pending_join(parent_path, dirent->d_name);
			if (full_path) {
				/* Check against exclude patterns */
				if (!watch || !exclude_match(watch, full_path)) {
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

/* Find filesystem paths that match pattern using glob() */
char **glob_scan(const char *pattern, int *count) {
	glob_t glob_result;
	memset(&glob_result, 0, sizeof(glob_result));

	int return_value = glob(pattern, GLOB_TILDE | GLOB_BRACE | GLOB_MARK, NULL, &glob_result);
	if (return_value != 0) {
		globfree(&glob_result);
		if (return_value != GLOB_NOMATCH) {
			log_message(WARNING, "glob() failed with return value %d for pattern %s",
						return_value, pattern);
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
		if (!matches[i]) {
			log_message(ERROR, "Failed to allocate memory for glob match");
			for (size_t j = 0; j < i; j++) {
				free(matches[j]);
			}
			free(matches);
			globfree(&glob_result);
			*count = 0;
			return NULL;
		}
	}

	globfree(&glob_result);
	return matches;
}

/* Free an array returned by glob_scan() */
void glob_free(char **matches, int count) {
	if (!matches) return;

	for (int i = 0; i < count; i++) {
		free(matches[i]);
	}
	free(matches);
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
	if (!monitor || index < 0 || index >= monitor->num_pending) return;

	pending_t *pending = monitor->pending[index];

	/* Clean up the proxy watch on the parent directory */
	if (pending && watchref_valid(pending->proxyref)) {
		registry_deactivate(monitor->registry, pending->proxyref);
	}

	pending_destroy(pending);

	/* Use swap-with-last for removal */
	monitor->num_pending--;
	if (index < monitor->num_pending) {
		monitor->pending[index] = monitor->pending[monitor->num_pending];
	}
	monitor->pending[monitor->num_pending] = NULL; /* Clear the now-unused slot */
}

/* Generate unique name for a proxy watch */
static char *proxy_name(watchref_t watchref, const char *type) {
	static uint32_t counter = 0;
	static pthread_mutex_t counter_mutex = PTHREAD_MUTEX_INITIALIZER;

	char *name = malloc(PROXY_NAME_MAX_LEN);
	if (!name) return NULL;

	/* Thread-safe counter increment */
	pthread_mutex_lock(&counter_mutex);
	uint32_t current_counter = ++counter;
	pthread_mutex_unlock(&counter_mutex);

	snprintf(name, PROXY_NAME_MAX_LEN, "__%s_%u_%u_%u__", type, watchref.watch_id, watchref.generation, current_counter);
	return name;
}

/* Create a proxy watch for a pending path's parent */
static watchref_t proxy_create(monitor_t *monitor, const watch_t *watch, watchref_t watchref, const char *parent_path, const char *type) {
	if (!monitor || !watch || !parent_path) return WATCHREF_INVALID;

	watch_t *proxy_watch = calloc(1, sizeof(watch_t));
	if (!proxy_watch) {
		log_message(ERROR, "Failed to allocate memory for proxy watch");
		return WATCHREF_INVALID;
	}

	/* Create unique name for this proxy watch */
	proxy_watch->name = proxy_name(watchref, type);
	if (!proxy_watch->name) {
		free(proxy_watch);
		return WATCHREF_INVALID;
	}

	proxy_watch->path = strdup(parent_path);
	proxy_watch->target = WATCH_DIRECTORY;
	proxy_watch->filter = EVENT_STRUCTURE;
	proxy_watch->enabled = true;
	proxy_watch->command = NULL;
	proxy_watch->is_dynamic = false;
	proxy_watch->source_pattern = NULL;

	/* Copy relevant properties from source watch */
	proxy_watch->recursive = watch->recursive;
	proxy_watch->hidden = watch->hidden;

	/* Add to registry */
	watchref_t proxyref = registry_add(monitor->registry, proxy_watch);
	if (!watchref_valid(proxyref)) {
		log_message(ERROR, "Failed to add proxy watch to registry");
		watch_destroy(proxy_watch);
		return WATCHREF_INVALID;
	}

	log_message(DEBUG, "Created proxy watch '%s' for pattern from watch %u:%u",
				proxy_watch->name, watchref.watch_id, watchref.generation);

	return proxyref;
}

/* Add a pending watch to the monitor's pending list */
bool pending_add(monitor_t *monitor, const char *target_path, watchref_t watchref) {
	watch_t *watch = registry_get(monitor->registry, watchref);
	if (!watch) return false;
	if (!monitor || !target_path) return false;

	/* Check if this is a glob pattern */
	bool is_glob = pending_pattern(target_path);
	char *parent_path = NULL;
	char *next_component = NULL;

	if (is_glob) {
		/* Handle glob pattern */
		parent_path = pending_parent(target_path);
		if (!parent_path) {
			log_message(ERROR, "No existing parent found for glob pattern: %s", target_path);
			return false;
		}

		/* Get the glob component to match */
		next_component = pending_component(target_path, parent_path, false);
		if (!next_component) {
			log_message(ERROR, "Unable to determine glob component for pattern: %s", target_path);
			free(parent_path);
			return false;
		}
	} else {
		/* Handle exact path */
		parent_path = pending_parent(target_path);
		if (!parent_path) {
			log_message(ERROR, "No existing parent found for path: %s", target_path);
			return false;
		}

		next_component = pending_component(target_path, parent_path, true);
		if (!next_component) {
			log_message(ERROR, "Unable to determine next component for path: %s", target_path);
			free(parent_path);
			return false;
		}
	}

	/* Create pending watch entry */
	pending_t *pending = calloc(1, sizeof(pending_t));
	if (!pending) {
		log_message(ERROR, "Failed to allocate memory for pending watch");
		free(parent_path);
		free(next_component);
		return false;
	}

	pending->target_path = strdup(target_path);
	pending->current_parent = parent_path;
	pending->next_component = next_component;
	pending->is_glob = is_glob;
	pending->unresolved_path = is_glob ? strdup(parent_path) : NULL;
	pending->glob_pattern = is_glob ? strdup(target_path) : NULL;
	pending->watchref = watchref;
	pending->proxy_watcher = NULL;

	/* Create a dedicated proxy watch to monitor the parent directory */
	const char *type = is_glob ? "proxy_glob" : "proxy_exact";
	watchref_t proxyref = proxy_create(monitor, watch, watchref, parent_path, type);
	if (!watchref_valid(proxyref)) {
		log_message(ERROR, "Failed to create proxy watch for %s", target_path);
		pending_destroy(pending);
		return false;
	}
	pending->proxyref = proxyref; /* Store for cleanup */

	/* Add watch on the parent directory using the proxy watch's ref */
	if (!monitor_path(monitor, parent_path, proxyref)) {
		log_message(WARNING, "Failed to add parent watch for %s, parent: %s", target_path, parent_path);
		registry_deactivate(monitor->registry, proxyref); /* Clean up proxy watch */
		pending_destroy(pending);
		return false;
	}

	/* Find the watcher we just created for the parent */
	pending->proxy_watcher = pending_watcher(monitor, parent_path, proxyref);

	/* Add to pending watches array using exponential growth */
	if (monitor->num_pending >= monitor->pending_capacity) {
		int new_capacity = (monitor->pending_capacity == 0) ? 4 : monitor->pending_capacity * 2;
		pending_t **new_pending = realloc(monitor->pending, new_capacity * sizeof(pending_t *));
		if (!new_pending) {
			log_message(ERROR, "Failed to allocate memory for pending watches array (capacity: %d)", new_capacity);
			pending_destroy(pending);
			return false;
		}
		monitor->pending = new_pending;
		monitor->pending_capacity = new_capacity;
		log_message(DEBUG, "Expanded pending array capacity to %d", new_capacity);
	}

	monitor->pending[monitor->num_pending] = pending;
	monitor->num_pending++;

	log_message(DEBUG, "Added pending watch (%s): target=%s, parent=%s, next=%s",
				is_glob ? "glob" : "exact", target_path, parent_path, next_component);
	return true;
}

/* Generate synthetic creation event for promoted pending path */
static void pending_event(monitor_t *monitor, watchref_t watchref, const char *promoted_path, const char *promotion_type) {
	if (!monitor || !promoted_path || !promotion_type) return;

	/* Only generate synthetic events during active monitoring, not during startup or config reload */
	if (!monitor->running || monitor->reloading) {
		const char *reason = !monitor->running ? "startup" : "configuration reload";
		log_message(DEBUG, "Skipping synthetic event for promoted %s path during %s: %s",
					promotion_type, reason, promoted_path);
		return;
	}

	/* Generate synthetic creation event for the newly promoted path */
	struct timespec current_time;
	clock_gettime(CLOCK_MONOTONIC, &current_time);

	event_t promotion_event = {
		.path = (char *) promoted_path,
		.type = EVENT_STRUCTURE | EVENT_CONTENT, /* Both structure and content for creation */
		.time = current_time,
		.wall_time = {0},
		.user_id = getuid(),
		.diff = NULL,
		.baseline_snapshot = NULL};

	clock_gettime(CLOCK_REALTIME, &promotion_event.wall_time);

	/* Determine entity kind for the promoted watch */
	watch_t *promoted_watch = registry_get(monitor->registry, watchref);
	kind_t entity_kind = (promoted_watch && promoted_watch->target == WATCH_FILE) ? ENTITY_FILE : ENTITY_DIRECTORY;

	log_message(DEBUG, "Generating synthetic creation event for promoted %s path: %s",
				promotion_type, promoted_path);

	/* Process the synthetic creation event immediately */
	events_process(monitor, watchref, &promotion_event, entity_kind, false);
}

/* Promote a fully matched glob path to a dynamic watch */
static void pending_promote(monitor_t *monitor, pending_t *pending, const char *matched_path) {
	if (!monitor || !pending || !matched_path) return;

	log_message(DEBUG, "Promoting glob match: %s from pattern %s", matched_path,
				pending->glob_pattern ? pending->glob_pattern : "unknown");

	/* Create a dynamic watch from the source's properties */
	watch_t *pending_watch = registry_get(monitor->registry, pending->watchref);
	if (!pending_watch) return;

	/* Clone watch for resolved path first */
	watch_t *resolved_watch = watch_clone(pending_watch);
	if (!resolved_watch) {
		log_message(ERROR, "Failed to clone watch for resolved path: %s", matched_path);
		return;
	}

	/* Update path and set dynamic fields */
	free(resolved_watch->path);
	resolved_watch->path = strdup(matched_path);
	resolved_watch->is_dynamic = true;
	resolved_watch->source_pattern = strdup(pending->glob_pattern);

	if (!resolved_watch->path || !resolved_watch->source_pattern) {
		log_message(ERROR, "Failed to allocate strings for resolved watch");
		watch_destroy(resolved_watch);
		return;
	}

	/* Add dynamic watch to config, atomic duplicate checking handled in registry_add() */
	watchref_t resolvedref = watch_add(monitor->config, monitor->registry, resolved_watch);
	if (!watchref_valid(resolvedref)) {
		log_message(ERROR, "Failed to add dynamic watch to config: %s", matched_path);
		/* Clean up avoid memory leaks */
		watch_destroy(resolved_watch);
		return;
	}

	log_message(INFO, "Adding resolved watch to monitoring system: %s (watchref %u:%u)", matched_path,
				resolvedref.watch_id, resolvedref.generation);

	if (monitor_add(monitor, resolvedref, true)) {
		log_message(INFO, "Successfully promoted glob match: %s from pattern %s", matched_path,
					pending->glob_pattern);

		/* Generate synthetic creation event for the newly promoted path */
		pending_event(monitor, resolvedref, matched_path, "glob");
	} else {
		log_message(WARNING, "Failed to promote glob match: %s from pattern %s", matched_path,
					pending->glob_pattern);
		/* Remove from config since monitor add failed */
		watch_remove(monitor->config, monitor->registry, resolvedref);
	}
}

/* Create a new pending watch for a proxy directory that matches a glob component */
static void pending_proxy(monitor_t *monitor, pending_t *pending, const char *proxy_path) {
	/* For globs, this means we found a proxy directory that matches part of the pattern */
	if (!pending_directory(proxy_path)) {
		return; /* Not a directory, so it can't be a proxy step */
	}

	/* Check if a pending watch for this proxy parent, glob pattern, and watchref already exists */
	for (int i = 0; i < monitor->num_pending; i++) {
		pending_t *p = monitor->pending[i];
		if (p->is_glob && strcmp(p->current_parent, proxy_path) == 0 && p->glob_pattern &&
			strcmp(p->glob_pattern, pending->glob_pattern) == 0 && watchref_equal(p->watchref, pending->watchref)) {
			log_message(DEBUG, "Pending watch for proxy path %s with same watchref already exists", proxy_path);
			return;
		}
	}

	log_message(DEBUG, "Glob proxy directory created: %s", proxy_path);

	/* Create a new pending watch for this path */
	pending_t *new_pending = calloc(1, sizeof(pending_t));
	if (!new_pending) {
		log_message(ERROR, "Failed to allocate memory for proxy pending watch");
		return;
	}

	new_pending->target_path = strdup(pending->target_path);
	new_pending->current_parent = strdup(proxy_path); /* The resolved path */

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
	new_pending->proxy_watcher = NULL;
	new_pending->proxyref = WATCHREF_INVALID;

	/* Create individual proxy watch for this glob directory */
	watch_t *watch = registry_get(monitor->registry, pending->watchref);
	if (!watch) {
		log_message(ERROR, "Invalid source watch reference in pending_proxy");
		pending_destroy(new_pending);
		return;
	}

	watchref_t proxyref = proxy_create(monitor, watch, pending->watchref, proxy_path, "proxy_glob");
	if (!watchref_valid(proxyref)) {
		log_message(ERROR, "Failed to create proxy glob watch for %s", proxy_path);
		pending_destroy(new_pending);
		return;
	}

	/* Store proxy watch reference for cleanup */
	new_pending->proxyref = proxyref;

	if (new_pending->next_component && monitor_tree(monitor, proxy_path, proxyref)) {
		/* Find the watcher for this parent */
		new_pending->proxy_watcher = pending_watcher(monitor, proxy_path, proxyref);

		/* Add to pending array using exponential growth */
		if (monitor->num_pending >= monitor->pending_capacity) {
			int new_capacity = (monitor->pending_capacity == 0) ? 4 : monitor->pending_capacity * 2;
			pending_t **new_pending_array = realloc(monitor->pending, new_capacity * sizeof(pending_t *));
			if (!new_pending_array) {
				log_message(ERROR, "Failed to expand pending array capacity to %d", new_capacity);
				pending_destroy(new_pending);
				return;
			}
			monitor->pending = new_pending_array;
			monitor->pending_capacity = new_capacity;
			log_message(DEBUG, "Expanded pending array capacity to %d", new_capacity);
		}

		monitor->pending[monitor->num_pending] = new_pending;
		monitor->num_pending++;

		log_message(DEBUG, "Added new glob pending watch: target=%s, parent=%s, next=%s",
					new_pending->target_path, new_pending->current_parent, new_pending->next_component);

		/* Recursively process the new parent to handle pre-existing subdirectories */
		pending_process(monitor, new_pending->current_parent);
	} else {
		log_message(WARNING, "Failed to add monitor or get next component for '%s'", proxy_path);
		/* Clean up proxy watch */
		registry_deactivate(monitor->registry, proxyref);
		pending_destroy(new_pending);
	}
}

/* Process a pending watch for a glob pattern */
static void process_glob(monitor_t *monitor, pending_t *pending) {
	char **matches = NULL;
	int match_count = 0;

	/* Get the source watch to check exclude patterns and target type */
	watch_t *watch = registry_get(monitor->registry, pending->watchref);
	if (!watch) {
		log_message(WARNING, "Could not find source watch for pending glob processing.");
		return;
	}

	if (!glob_find(pending->current_parent, watch, pending->next_component, &matches, &match_count)) {
		return;
	}

	if (match_count > 0) {
		log_message(DEBUG, "Found %d glob matches in %s for pattern %s",
					match_count, pending->current_parent, pending->next_component);

		/* For each matching file, check if it completes the pattern */
		for (int m = 0; m < match_count; m++) {
			if (glob_matches(matches[m], pending->glob_pattern)) {
				/* This match completes the full glob pattern, check its type before promoting */
				struct stat info;
				if (stat(matches[m], &info) != 0) {
					log_message(WARNING, "Failed to stat glob match %s: %s", matches[m], strerror(errno));
					continue;
				}

				bool type_match = (S_ISDIR(info.st_mode) && watch->target == WATCH_DIRECTORY) ||
								  (S_ISREG(info.st_mode) && watch->target == WATCH_FILE);

				if (type_match) {
					pending_promote(monitor, pending, matches[m]);
				} else {
					log_message(DEBUG, "Skipping promotion of glob match %s: type mismatch (expected %s, found %s)",
								matches[m], watch->target == WATCH_DIRECTORY ? "directory" : "file",
								S_ISDIR(info.st_mode) ? "directory" : "file");
				}
			} else {
				/* This is an intermediate match, must be a directory to continue */
				pending_proxy(monitor, pending, matches[m]);
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
static bool process_exact(monitor_t *monitor, pending_t *pending, int index) {
	/* Loop to process multiple path components created in a single event */
	while (true) {
		if (pending_directory(pending->next_component) || access(pending->next_component, F_OK) == 0) {
			log_message(DEBUG, "Next component created: %s", pending->next_component);

			/* Check if this completes the full target path */
			if (strcmp(pending->next_component, pending->target_path) == 0) {
				/* Full path now exists - promote to regular watch */
				log_message(DEBUG, "Promoting pending watch to regular watch: %s", pending->target_path);

				if (monitor_add(monitor, pending->watchref, true)) {
					log_message(INFO, "Successfully promoted pending watch: %s", pending->target_path);

					/* Generate synthetic creation event for the newly promoted path */
					pending_event(monitor, pending->watchref, pending->target_path, "exact");
				} else {
					log_message(WARNING, "Failed to promote pending watch: %s", pending->target_path);
				}

				/* Remove from pending list and exit */
				pending_remove(monitor, index);
				return true;
			} else {
				/* Proxy directory created, update pending watch and continue loop */
				log_message(DEBUG, "Proxy component created, updating pending watch: %s",
							pending->next_component);

				free(pending->current_parent);
				pending->current_parent = strdup(pending->next_component);

				free(pending->next_component);
				pending->next_component = pending_component(pending->target_path, pending->current_parent, true);

				if (!pending->next_component) {
					log_message(ERROR, "Failed to determine next component, removing pending watch");
					pending_remove(monitor, index);
					return true;
				}

				/* Add watch on the new parent directory */
				if (!monitor_path(monitor, pending->current_parent, pending->proxyref)) {
					log_message(WARNING, "Failed to add watch on new parent: %s", pending->current_parent);
					pending_remove(monitor, index);
					return true;
				}

				/* Update parent watcher reference */
				pending->proxy_watcher = pending_watcher(monitor, pending->current_parent, pending->proxyref);

				log_message(DEBUG, "Updated pending watch: target=%s, new_parent=%s, next=%s",
							pending->target_path, pending->current_parent, pending->next_component);
			}
		} else {
			/* Next component does not exist, so we stop here and wait for another event */
			break;
		}
	}
	return false;
}

/* Process pending watches for a given parent path */
void pending_process(monitor_t *monitor, const char *parent_path) {
	if (!monitor || !parent_path || monitor->num_pending == 0) return;

	for (int i = monitor->num_pending - 1; i >= 0; i--) {
		pending_t *pending = monitor->pending[i];

		/* Check if this pending watch is waiting for activity in this parent */
		if (strcmp(pending->current_parent, parent_path) == 0) {
			log_message(DEBUG, "Found pending watch for parent '%s', target '%s'",
						parent_path, pending->target_path);

			if (pending->is_glob) {
				process_glob(monitor, pending);
			} else {
				if (process_exact(monitor, pending, i)) {
					/* Reset loop to handle swap-with-last */
					i = monitor->num_pending;
				}
			}
		}
	}
}

/* Clean up all pending watches */
void pending_cleanup(monitor_t *monitor, registry_t *registry) {
	if (!monitor || !monitor->pending) return;

	if (!registry) {
		log_message(WARNING, "pending_cleanup called with NULL registry");
		return;
	}

	/* Deactivate proxy watches and destroy pending entries */
	for (int i = 0; i < monitor->num_pending; i++) {
		pending_t *pending = monitor->pending[i];
		if (pending) {
			if (watchref_valid(pending->proxyref)) {
				registry_deactivate(registry, pending->proxyref);
			}
			pending_destroy(pending);
		}
	}

	free(monitor->pending);
	monitor->pending = NULL;
	monitor->num_pending = 0;
	monitor->pending_capacity = 0;
}

/* Handle deletion of parent directories that affect pending watches */
void pending_delete(monitor_t *monitor, const char *deleted_path) {
	if (!monitor || !deleted_path || monitor->num_pending == 0) return;

	size_t deleted_path_len = strlen(deleted_path);

	/* Iterate backwards to safely remove entries */
	for (int i = monitor->num_pending - 1; i >= 0; i--) {
		pending_t *pending = monitor->pending[i];
		if (!pending || !pending->current_parent) continue;

		/* Check if this pending watch is affected by the deletion */
		bool affected = (strcmp(pending->current_parent, deleted_path) == 0) ||
						(strncmp(pending->current_parent, deleted_path, deleted_path_len) == 0 &&
						 pending->current_parent[deleted_path_len] == '/');

		if (affected) {
			log_message(DEBUG, "Pending watch (%s) affected by deletion of %s: target=%s, current_parent=%s",
						pending->is_glob ? "glob" : "exact", deleted_path, pending->target_path,
						pending->current_parent);

			/* Remove and re-add to find new deepest parent */
			char *target_path = strdup(pending->target_path);
			watchref_t watchref = pending->watchref;

			pending_remove(monitor, i);
			/* Reset loop to handle swap-with-last */
			i = monitor->num_pending;

			if (target_path) {
				pending_add(monitor, target_path, watchref);
				free(target_path);
			}
		}
	}
}

/* Check for deleted child directories that may affect pending watches */
void pending_reassess(monitor_t *monitor, const char *changed_path) {
	if (!monitor || !changed_path || monitor->num_pending == 0) return;

	log_message(DEBUG, "Directory content changed, checking for deleted child directories: %s",
				changed_path);

	int deleted_count = 0;
	int deleted_capacity = 0;
	char **deleted_parents = NULL;

	for (int i = 0; i < monitor->num_pending; i++) {
		pending_t *pending = monitor->pending[i];
		if (!pending || !pending->current_parent) continue;

		/* Check if the pending parent is a child of the directory that changed */
		size_t parent_len = strlen(changed_path);
		if (strlen(pending->current_parent) <= parent_len ||
			strncmp(pending->current_parent, changed_path, parent_len) != 0 ||
			pending->current_parent[parent_len] != '/') {
			continue;
		}

		/* Check if the pending parent path still exists */
		struct stat info;
		if (stat(pending->current_parent, &info) == 0) continue;

		/* The path was deleted, check if we've already queued it for processing */
		bool found = false;
		for (int j = 0; j < deleted_count; j++) {
			if (strcmp(deleted_parents[j], pending->current_parent) == 0) {
				found = true;
				break;
			}
		}

		if (found) continue;

		/* This is a new deleted path, add it to our list */
		if (deleted_count >= deleted_capacity) {
			deleted_capacity = (deleted_capacity == 0) ? 4 : deleted_capacity * 2;
			char **new_parents = realloc(deleted_parents, deleted_capacity * sizeof(char *));
			if (!new_parents) {
				log_message(ERROR, "Failed to allocate memory for deleted parent paths");
				for (int k = 0; k < deleted_count; k++) {
					free(deleted_parents[k]);
				}
				free(deleted_parents);
				deleted_parents = NULL;
				break;
			}
			deleted_parents = new_parents;
		}

		deleted_parents[deleted_count] = strdup(pending->current_parent);
		if (deleted_parents[deleted_count]) deleted_count++;
	}

	/* Now process the deletions */
	if (deleted_parents) {
		for (int i = 0; i < deleted_count; i++) {
			log_message(DEBUG, "Detected deletion of pending watch parent: %s", deleted_parents[i]);
			pending_delete(monitor, deleted_parents[i]);
			free(deleted_parents[i]);
		}

		free(deleted_parents);
	}
}

/* Observer callback for watch deactivation */
void pending_deactivation(watchref_t watchref, void *context) {
	monitor_t *monitor = (monitor_t *) context;
	if (!monitor || !monitor->pending) return;

	log_message(DEBUG, "Watch (watch_id=%u, gen=%u) deactivated, cleaning up pending entries",
				watchref.watch_id, watchref.generation);

	int entries_removed = 0;

	/* Scan pending entries for the deactivated watch */
	for (int i = monitor->num_pending - 1; i >= 0; i--) {
		pending_t *pending = monitor->pending[i];
		if (pending && watchref_equal(pending->watchref, watchref)) {
			log_message(DEBUG, "Removing orphaned pending entry for path: %s",
						pending->target_path ? pending->target_path : "<null>");

			/* Remove using the public pending_remove function for proper cleanup */
			pending_remove(monitor, i);
			entries_removed++;
			/* Reset loop to handle swap-with-last */
			i = monitor->num_pending;
		}
	}

	if (entries_removed > 0) {
		log_message(DEBUG, "Pending cleanup complete: removed %d orphaned entries",
					entries_removed);
	}
}
