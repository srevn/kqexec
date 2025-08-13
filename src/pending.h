#ifndef PENDING_H
#define PENDING_H

#include <stdbool.h>

#include "registry.h"

/* Maximum length for proxy watch names */
#define PROXY_NAME_MAX_LEN 64

/* Forward declarations */
typedef struct monitor monitor_t;
typedef struct watcher watcher_t;

/* Pending watch for non-existent paths */
typedef struct pending {
	char *target_path;                     /* Full target path to eventually watch */
	char *current_parent;                  /* Current parent directory being watched */
	char *next_component;                  /* Next path component we're waiting for */
	char *unresolved_path;                 /* The unresolved glob path up to the current parent */
	char *glob_pattern;                    /* Original glob pattern for matching */
	bool is_glob;                          /* Whether this is a glob pattern */
	watcher_t *proxy_watcher;              /* The watcher on the current parent directory */
	watchref_t watchref;                   /* Reference to the original watch configuration */
	watchref_t proxyref;                   /* Reference to proxy watch */
} pending_t;

/* Pending watch management functions */
bool pending_add(monitor_t *monitor, const char *target_path, watchref_t watchref);
void pending_process(monitor_t *monitor, const char *parent_path);
void pending_delete(monitor_t *monitor, const char *deleted_path);

/* Pending cleanup functions */
void pending_cleanup(monitor_t *monitor, registry_t *registry);
void pending_destroy(pending_t *pending);
void pending_remove(monitor_t *monitor, int index);

/* Glob scanning functions */
char **glob_scan_paths(const char *pattern, int *count);
void glob_free_paths(char **matches, int count);

/* Observer callback for watch deactivation */
void pending_handle_deactivation(watchref_t watchref, void *context);

#endif /* PENDING_H */
