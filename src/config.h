#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>

/* Maximum line length in config file */
#define MAX_LINE_LEN 1024

/* Event types that can be monitored */
typedef enum filter {
	EVENT_NONE = 0,                        /* No events */
	EVENT_STRUCTURE = 1 << 0,              /* Directory content changes (WRITE, EXTEND) */
	EVENT_METADATA = 1 << 1,               /* Metadata changes (ATTRIB, LINK) */
	EVENT_CONTENT = 1 << 2,                /* Modification events (CREATE, DELETE, RENAME) */
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
	char *name;                            /* Section name in config */
	char *path;                            /* Path to watch */
	target_t target;                       /* File or directory */
	filter_t filter;                       /* Events to monitor */
	char *command;                         /* Command to execute */
	bool log_output;                       /* Whether to capture and log command output */
	bool buffer_output;                    /* Whether to buffer output until command completes */
	bool recursive;                        /* Whether to recursively monitor (for directories) */
	bool hidden;                           /* Whether to monitor hidden files/directories */
	bool environment;                      /* Whether to inject KQ_* environment variables */
	double complexity;                     /* Multiplier for quiet period calculation (default: 1.0) */
	int processing_delay;                  /* Delay in milliseconds before processing events (0 = no delay) */
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
	watch_t **watches;                     /* Array of watch entries */
	int num_watches;                       /* Number of watch entries */
} config_t;

/* Function prototypes */
config_t *config_create(void);
void config_destroy(config_t *config);
bool config_parse(config_t *config, const char *filename);
bool config_events(const char *events_str, filter_t *events);
const char *filter_to_string(filter_t filter);

#endif /* CONFIG_H */
