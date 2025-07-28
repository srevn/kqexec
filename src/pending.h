#ifndef PENDING_H
#define PENDING_H

#include <stdbool.h>

/* Forward declarations */
typedef struct monitor monitor_t;
typedef struct watcher watcher_t;
typedef struct watch watch_t;

/* Pending watch for non-existent paths */
typedef struct pending {
	char *target_path;                     /* Full target path to eventually watch */
	char *current_parent;                  /* Current parent directory being watched */
	char *next_component;                  /* Next path component we're waiting for */
	char *unresolved_path;                 /* The unresolved glob path up to the current parent */
	bool is_glob;                          /* Whether this is a glob pattern */
	char *glob_pattern;                    /* Original glob pattern for matching */
	watch_t *watch;                        /* The original watch configuration */
	watcher_t *parent_watcher;             /* The watcher on the current parent directory */
} pending_t;

/* Pending watch management functions */
bool pending_add(monitor_t *monitor, const char *target_path, watch_t *watch);
void pending_process(monitor_t *monitor, const char *parent_path);
void pending_delete(monitor_t *monitor, const char *deleted_path);
void pending_cleanup(monitor_t *monitor);

/* Glob scanning functions */
char **pending_scan(const char *pattern, int *count);
void pending_free_matches(char **matches, int count);

#endif /* PENDING_H */
