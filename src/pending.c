#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fnmatch.h>
#include <dirent.h>
#include <glob.h>

#include "monitor.h"
#include "pending.h"
#include "logger.h"
#include "config.h"

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

/* Check if a path contains glob patterns */
static bool has_glob_pattern(const char *path) {
	if (!path) return false;
	
	/* Look for glob metacharacters */
	return (strchr(path, '*') != NULL || 
	        strchr(path, '?') != NULL || 
	        strchr(path, '[') != NULL);
}

/* Find the deepest non-glob parent directory of a glob pattern */
static char *find_glob_parent(const char *glob_pattern) {
	if (!glob_pattern) return NULL;

	char *pattern_copy = strdup(glob_pattern);
	if (!pattern_copy) return NULL;

	/* Work backwards to find the first path component without glob characters */
	char *current = pattern_copy + strlen(pattern_copy);
	
	while (current > pattern_copy) {
		/* Move to previous path separator */
		while (current > pattern_copy && *current != '/') {
			current--;
		}
		
		if (current == pattern_copy) break;
		
		/* Null-terminate at the separator */
		*current = '\0';
		
		/* Check if this portion contains globs */
		if (!has_glob_pattern(pattern_copy)) {
			/* This portion is non-glob, check if it exists */
			struct stat info;
			if (stat(pattern_copy, &info) == 0 && S_ISDIR(info.st_mode)) {
				return pattern_copy; /* Found existing non-glob parent */
			}
		}
		
		/* Continue searching backwards */
		if (current > pattern_copy) {
			current--;
		}
	}

	/* Check root directory as fallback */
	struct stat info;
	if (stat("/", &info) == 0) {
		strcpy(pattern_copy, "/");
		return pattern_copy;
	}

	free(pattern_copy);
	return NULL;
}

/* Get the glob pattern component that should match in the parent directory */
static char *get_glob_component(const char *glob_pattern, const char *parent_path) {
	if (!glob_pattern || !parent_path) return NULL;

	int parent_len = strlen(parent_path);
	int pattern_len = strlen(glob_pattern);

	/* Ensure glob_pattern starts with parent_path */
	if (pattern_len < parent_len || strncmp(glob_pattern, parent_path, parent_len) != 0) {
		return NULL;
	}

	/* Skip past parent and any trailing slash */
	const char *start = glob_pattern + parent_len;
	if (*start == '/') start++;

	/* Find the end of the next component */
	const char *end = strchr(start, '/');
	if (!end) {
		/* This is the final component */
		return strdup(start);
	}

	/* Extract just this component */
	int component_len = end - start;
	char *component = malloc(component_len + 1);
	if (!component) return NULL;

	strncpy(component, start, component_len);
	component[component_len] = '\0';
	return component;
}

/* Check if a created path matches the glob pattern */
static bool matches_glob_pattern(const char *created_path, const char *glob_pattern) {
	if (!created_path || !glob_pattern) return false;
	
	/* Use fnmatch for glob pattern matching */
	return fnmatch(glob_pattern, created_path, FNM_PATHNAME) == 0;
}

/* Find matching files in a directory for a glob component */
static bool find_glob_matches(const char *parent_path, const char *glob_component, char ***matches, int *match_count) {
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
			count++;
		}
	}

	if (count == 0) {
		closedir(dir);
		return true; /* No matches, but not an error */
	}

	/* Allocate array for matches */
	*matches = malloc(count * sizeof(char*));
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
			int path_len = strlen(parent_path) + 1 + strlen(entry->d_name) + 1;
			char *full_path = malloc(path_len);
			if (full_path) {
				snprintf(full_path, path_len, "%s/%s", parent_path, entry->d_name);
				(*matches)[index++] = full_path;
			}
		}
	}

	closedir(dir);
	*match_count = index;
	return true;
}

/* Destroy a pending watch entry */
static void pending_destroy(pending_t *pending) {
	if (!pending) return;

	free(pending->target_path);
	free(pending->current_parent);
	free(pending->next_component);
	free(pending->unresolved_path);
	free(pending->glob_pattern);
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

/* Check if a dynamic watch for a given path and source pattern already exists */
static bool dynamic_watch_exists(monitor_t *monitor, const char *path, const char *source_pattern) {
	for (int i = 0; i < monitor->config->num_watches; i++) {
		watch_t *w = monitor->config->watches[i];
		if (w->is_dynamic && strcmp(w->path, path) == 0 &&
		    w->source_pattern && strcmp(w->source_pattern, source_pattern) == 0) {
			return true;
		}
	}
	return false;
}

/* Check if a pending watch for a given intermediate parent and glob pattern already exists */
static bool pending_watch_exists(monitor_t *monitor, const char *parent, const char *glob_pattern) {
	for (int i = 0; i < monitor->num_pending; i++) {
		pending_t *p = monitor->pending[i];
		if (p->is_glob && strcmp(p->current_parent, parent) == 0 &&
		    p->glob_pattern && strcmp(p->glob_pattern, glob_pattern) == 0) {
			return true;
		}
	}
	return false;
}

/* Add a pending watch to the monitor's pending list */
bool pending_add(monitor_t *monitor, const char *target_path, watch_t *watch) {
	if (!monitor || !target_path || !watch) {
		return false;
	}

	/* Check if this is a glob pattern */
	bool is_glob = has_glob_pattern(target_path);
	char *parent = NULL;
	char *next_component = NULL;

	if (is_glob) {
		/* Handle glob pattern */
		parent = find_glob_parent(target_path);
		if (!parent) {
			log_message(ERROR, "No existing parent found for glob pattern: %s", target_path);
			return false;
		}

		/* Get the glob component to match */
		next_component = get_glob_component(target_path, parent);
		if (!next_component) {
			log_message(ERROR, "Unable to determine glob component for pattern: %s", target_path);
			free(parent);
			return false;
		}
	} else {
		/* Handle exact path (existing logic) */
		parent = find_deepest_parent(target_path);
		if (!parent) {
			log_message(ERROR, "No existing parent found for path: %s", target_path);
			return false;
		}

		next_component = get_next_component(target_path, parent);
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
	pending->watch = watch;
	pending->parent_watcher = NULL;

	/* Add watch on the parent directory */
	watch_t *watch_to_use = is_glob ? monitor->glob_watch : watch;
	if (is_glob) {
		/* Copy relevant properties from original watch */
		monitor->glob_watch->recursive = watch->recursive;
		monitor->glob_watch->hidden = watch->hidden;
	}

	if (!monitor_path(monitor, parent, watch_to_use)) {
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

	log_message(DEBUG, "Added pending watch (%s): target=%s, parent=%s, next=%s",
	            is_glob ? "glob" : "exact", target_path, parent, next_component);
	return true;
}

/* Process pending watches for a given parent path */
void pending_process(monitor_t *monitor, const char *parent_path) {
	if (!monitor || !parent_path || monitor->num_pending == 0) {
		return;
	}
	log_message(DEBUG, "pending_process: Checking for pending watches under '%s'", parent_path);

	for (int i = monitor->num_pending - 1; i >= 0; i--) {
		pending_t *pending = monitor->pending[i];

		/* Check if this pending watch is waiting for activity in this parent */
		if (strcmp(pending->current_parent, parent_path) == 0) {
			log_message(DEBUG, "pending_process: Found pending watch for parent '%s', target '%s'", parent_path, pending->target_path);
			
			if (pending->is_glob) {
				/* Handle glob pattern matching */
				char **matches = NULL;
				int match_count = 0;
				
				log_message(DEBUG, "pending_process: Finding glob matches in '%s' for component '%s'", parent_path, pending->next_component);
				if (find_glob_matches(parent_path, pending->next_component, &matches, &match_count)) {
					if (match_count > 0) {
						log_message(DEBUG, "pending_process: Found %d glob matches in %s for pattern %s", 
								    match_count, parent_path, pending->next_component);
						
						/* For each matching file, check if it completes the pattern */
						for (int m = 0; m < match_count; m++) {
							log_message(DEBUG, "pending_process: Checking match '%s' against full pattern '%s'", matches[m], pending->glob_pattern);
							if (matches_glob_pattern(matches[m], pending->glob_pattern)) {
								/* Full pattern matched - create independent watch */
								if (dynamic_watch_exists(monitor, matches[m], pending->glob_pattern)) {
									log_message(DEBUG, "Dynamic watch for %s from pattern %s already exists.", matches[m], pending->glob_pattern);
									continue;
								}
								
								log_message(INFO, "pending_process: Glob pattern fully matched, promoting: %s", matches[m]);
								
								/* Create a dynamic deep copy with the resolved path and source pattern tracking */
								watch_t *resolved_watch = watch_deep_copy_dynamic(pending->watch, matches[m], pending->glob_pattern);
								if (!resolved_watch) {
									log_message(ERROR, "Failed to create resolved watch for: %s", matches[m]);
									continue;
								}
								
								/* Add to configuration for proper lifecycle management */
								if (!config_add_dynamic_watch(monitor->config, resolved_watch)) {
									log_message(ERROR, "Failed to add dynamic watch to config: %s", matches[m]);
									/* Clean up manually since config addition failed */
									free(resolved_watch->name);
									free(resolved_watch->path);
									free(resolved_watch->command);
									free(resolved_watch);
									continue;
								}
								
								/* Add to monitoring system - now it's a first-class citizen */
								if (monitor_add(monitor, resolved_watch, true)) {
									log_message(INFO, "Successfully promoted glob match: %s", matches[m]);
								} else {
									log_message(WARNING, "Failed to promote glob match: %s", matches[m]);
								}
							} else {
								/* Partial match - need to continue monitoring deeper */
								/* For globs, this means we found an intermediate directory that matches part of the pattern */
								struct stat info;
								if (stat(matches[m], &info) == 0 && S_ISDIR(info.st_mode)) {
									if (pending_watch_exists(monitor, matches[m], pending->glob_pattern)) {
										log_message(DEBUG, "Pending watch for intermediate path %s already exists.", matches[m]);
										continue;
									}
									
									log_message(DEBUG, "pending_process: Glob intermediate directory created: %s", matches[m]);
									
									/* Create a new pending watch for this path */
									pending_t *new_pending = calloc(1, sizeof(pending_t));
									if (new_pending) {
										new_pending->target_path = strdup(pending->target_path);
										new_pending->current_parent = strdup(matches[m]); // The resolved path

										/* Construct the new unresolved path by appending the component that just matched */
										char *new_unresolved_path;
										if (strcmp(pending->unresolved_path, "/") == 0) {
											int len = snprintf(NULL, 0, "/%s", pending->next_component);
											new_unresolved_path = malloc(len + 1);
											if(new_unresolved_path) snprintf(new_unresolved_path, len + 1, "/%s", pending->next_component);
										} else {
											int len = snprintf(NULL, 0, "%s/%s", pending->unresolved_path, pending->next_component);
											new_unresolved_path = malloc(len + 1);
											if(new_unresolved_path) snprintf(new_unresolved_path, len + 1, "%s/%s", pending->unresolved_path, pending->next_component);
										}
										new_pending->unresolved_path = new_unresolved_path;

										if (new_unresolved_path) {
											new_pending->next_component = get_glob_component(pending->glob_pattern, new_unresolved_path);
										} else {
											new_pending->next_component = NULL;
										}

										new_pending->is_glob = true;
										new_pending->glob_pattern = strdup(pending->glob_pattern);
										new_pending->watch = pending->watch;
										new_pending->parent_watcher = NULL;
										
										/* Use the special glob watch for intermediate directories */
										watch_t *watch_to_use = monitor->glob_watch;
										watch_to_use->recursive = pending->watch->recursive;
										watch_to_use->hidden = pending->watch->hidden;

										log_message(DEBUG, "pending_process: Adding monitor for intermediate dir '%s' with watch '%s'", matches[m], watch_to_use->name);
										if (new_pending->next_component && monitor_tree(monitor, matches[m], watch_to_use)) {
											/* Find the watcher for this parent */
											for (int w = 0; w < monitor->num_watches; w++) {
												if (strcmp(monitor->watches[w]->path, matches[m]) == 0 && 
												    monitor->watches[w]->watch == watch_to_use) {
													new_pending->parent_watcher = monitor->watches[w];
													break;
												}
											}
											
											/* Add to pending array */
											pending_t **new_pending_array = realloc(monitor->pending, 
											                                       (monitor->num_pending + 1) * sizeof(pending_t *));
											if (new_pending_array) {
												monitor->pending = new_pending_array;
												monitor->pending[monitor->num_pending] = new_pending;
												monitor->num_pending++;
												
												log_message(DEBUG, "Added new glob pending watch: target=%s, parent=%s, next=%s",
												           new_pending->target_path, new_pending->current_parent, new_pending->next_component);
												
												/* Recursively process the new parent to handle pre-existing subdirectories */
												pending_process(monitor, new_pending->current_parent);
											} else {
												pending_destroy(new_pending);
											}
										} else {
											log_message(WARNING, "pending_process: Failed to add monitor or get next component for '%s'", matches[m]);
											pending_destroy(new_pending);
										}
									}
								}
							}
						}
						
						/* Free the matches array */
						for (int m = 0; m < match_count; m++) {
							free(matches[m]);
						}
						free(matches);
						
						/*
						 * DO NOT remove the original pending watch. It must persist to find other
						 * potential matches in the same directory in the future. The checks for
						 * dynamic_watch_exists() and pending_watch_exists() prevent duplicates.
						 */
					}
				}
			} else {
				/* Handle exact path matching (original logic) */
				struct stat info;
				
				if (stat(pending->next_component, &info) == 0) {
					log_message(DEBUG, "Next component created: %s", pending->next_component);

					/* Check if this completes the full target path */
					if (strcmp(pending->next_component, pending->target_path) == 0) {
						/* Full path now exists - promote to regular watch */
						log_message(DEBUG, "Promoting pending watch to regular watch: %s", pending->target_path);

						if (monitor_add(monitor, pending->watch, true)) {
							log_message(INFO, "Successfully promoted pending watch: %s", pending->target_path);
						} else {
							log_message(WARNING, "Failed to promote pending watch: %s", pending->target_path);
						}

						/* Remove from pending list */
						pending_remove(monitor, i);
					} else {
						/* Intermediate directory created - update pending watch */
						log_message(DEBUG, "Intermediate component created, updating pending watch: %s", pending->next_component);

						free(pending->current_parent);
						pending->current_parent = strdup(pending->next_component);

						free(pending->next_component);
						pending->next_component = get_next_component(pending->target_path, pending->current_parent);

						if (!pending->next_component) {
							log_message(ERROR, "Failed to determine next component, removing pending watch");
							pending_remove(monitor, i);
							continue;
						}

						/* Add watch on the new parent directory */
						if (!monitor_path(monitor, pending->current_parent, pending->watch)) {
							log_message(WARNING, "Failed to add watch on new parent: %s", pending->current_parent);
							pending_remove(monitor, i);
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
			log_message(DEBUG, "Pending watch (%s) affected by deletion of %s: target=%s, current_parent=%s",
			            pending->is_glob ? "glob" : "exact", deleted_path, pending->target_path, pending->current_parent);

			/* Find new deepest existing parent based on type */
			char *new_parent = NULL;
			if (pending->is_glob) {
				new_parent = find_glob_parent(pending->glob_pattern);
			} else {
				new_parent = find_deepest_parent(pending->target_path);
			}
			
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
			if (pending->is_glob) {
				pending->next_component = get_glob_component(pending->glob_pattern, new_parent);
			} else {
				pending->next_component = get_next_component(pending->target_path, new_parent);
			}

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

char **pending_scan(const char *pattern, int *count) {
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

void pending_free_matches(char **matches, int count) {
    if (!matches) return;
    for (int i = 0; i < count; i++) {
        free(matches[i]);
    }
    free(matches);
}