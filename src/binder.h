#ifndef BINDER_H
#define BINDER_H

#include <stdbool.h>
#include <stddef.h>

#include "monitor.h"
#include "events.h"

/* Result metadata for placeholder resolution */
typedef struct placeholder {
	char *value;                           /* The resolved value */
	bool allocated;                        /* Should we free this value? */
	bool formatted;                        /* Is this already formatted? */
} placeholder_t;

/* Context for placeholder binding operations */
typedef struct binder {
	monitor_t *monitor;                    /* Monitor reference */
	watchref_t watchref;                   /* Watch reference */
	const event_t *event;                  /* Event data */
	const watch_t *watch;                  /* Watch configuration */
	
	/* Cached expensive computations */
	char *escaped_path;                    /* Shell-escaped event path */
	char *basename;                        /* Basename of event path */
	char *dirname;                         /* Directory name of event path */
	char *relative_path;                   /* Path relative to watch root */
	char *escaped_relative_path;           /* Escaped relative path */
	char *escaped_basename;                /* Escaped basename */
	char *escaped_dirname;                 /* Escaped directory name */
	char *escaped_watch_path;              /* Escaped watch path */
	char *escaped_watch_name;              /* Escaped watch name */
	char *time_string;                     /* Formatted time string */
	char *user_string;                     /* User name or ID string */
	char *event_string;                    /* Event type string */
	char *size_string;                     /* File size as string */
	char *human_size_string;               /* Human-readable size string */
	
	/* Size calculation cache */
	size_t file_size;                      /* Calculated file size */
	bool size_calculated;                  /* Whether size has been calculated */
} binder_t;

/* Context lifecycle */
binder_t *binder_create(monitor_t *monitor, watchref_t watchref, const event_t *event);
void binder_destroy(binder_t *ctx);

/* Main binding operations */
char *binder_placeholders(binder_t *ctx, const char *template);
void binder_environment(binder_t *ctx);

#endif /* BINDER_H */
