#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>

#include "registry.h"

#define MAX_LINE_LEN 1024                  /* Maximum line length in config file */

/* Event types that can be monitored */
typedef enum filter {
	EVENT_NONE = 0,                        /* No events */
	EVENT_STRUCTURE = 1 << 0,              /* Directory structure changes (WRITE, EXTEND) */
	EVENT_METADATA = 1 << 1,               /* Metadata changes (ATTRIB, LINK) */
	EVENT_CONTENT = 1 << 2,                /* File content changes (CREATE, DELETE, RENAME) */
	EVENT_ALL = EVENT_STRUCTURE | EVENT_METADATA | EVENT_CONTENT
} filter_t;

/* Type of the watch entry */
typedef enum target {
	WATCH_FILE,                            /* Watch a specific file */
	WATCH_DIRECTORY                        /* Watch a directory */
} target_t;

/* Entity kind for clarity in handling */
typedef enum kind {
	ENTITY_UNKNOWN,                        /* Unknown type, to be determined */
	ENTITY_FILE,                           /* Regular file */
	ENTITY_DIRECTORY,                      /* Directory */
} kind_t;

/* Structure for a watch entry in the configuration */
typedef struct watch {
	/* Basic watch configuration */
	char *name;                            /* Section name in config */
	char *path;                            /* Path to watch */
	target_t target;                       /* File or directory */
	filter_t filter;                       /* Events to monitor */
	char *command;                         /* Command to execute */
	
	/* Output handling */
	bool log_output;                       /* Whether to capture and log command output */
	bool buffer_output;                    /* Whether to buffer output until command completes */
	
	/* Monitoring options */
	bool enabled;                          /* Whether the watch is currently enabled */
	bool hidden;                           /* Whether to monitor hidden files/directories */
	bool recursive;                        /* Whether to recursively monitor (for directories) */
	bool environment;                      /* Whether to inject KQ_* environment variables */
	double complexity;                     /* Multiplier for system responsiveness (default: 1.0) */
	bool requires_snapshot;                /* Whether snapshots are needed for this watch */
	
	/* Timing configuration */
	int batch_timeout;                     /* Event batching timeout duration in ms */
	int processing_delay;                  /* Delay before processing events */
	
	/* Exclusion patterns */
	char **exclude;                        /* Array of exclude patterns */
	int num_exclude;                       /* Number of exclude patterns */
	
	/* Dynamic watch tracking */
	bool is_dynamic;                       /* True if created from glob promotion */
	char *source_pattern;                  /* Original glob pattern that created this watch */
} watch_t;

/* Configuration file section parsing state */
typedef enum section {
	SECTION_NONE,                          /* No section */
	SECTION_ENTRY                          /* Configuration entry section */
} section_t;

/* Global configuration structure */
typedef struct config {
	char *config_path;                     /* Path to config file */
	bool daemon_mode;                      /* Run as daemon */
	int syslog_level;                      /* Syslog verbosity */
} config_t;

/* Function prototypes */
config_t *config_create(void);
void config_destroy(config_t *config);
bool config_parse(config_t *config, registry_t *registry, const char *filename);
bool config_events(const char *events_str, filter_t *events);
const char *filter_to_string(filter_t filter);

/* Watch management functions */
bool watch_add(config_t *config, registry_t *registry, watch_t *watch);
void watch_destroy(watch_t *watch);
watch_t *watch_clone(const watch_t *source);
bool watch_remove(config_t *config, registry_t *registry, watchref_t watchref);

/* Exclude pattern functions */
bool exclude_add(watch_t *watch, const char *pattern);
bool exclude_match(const watch_t *watch, const char *path);

/* Snapshot detection functions */
bool config_snapshot(const watch_t *watch);

#endif /* CONFIG_H */
