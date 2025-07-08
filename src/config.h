#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>

/* Event types that can be monitored */
typedef enum {
	EVENT_NONE = 0,             /* No events */
	EVENT_STRUCTURE = 1 << 0,   /* Directory content changes (WRITE, EXTEND) */
	EVENT_METADATA = 1 << 1,    /* Metadata changes (ATTRIB, LINK) */
	EVENT_CONTENT = 1 << 2,     /* Modification events (CREATE, DELETE, RENAME) */
	EVENT_ALL = EVENT_STRUCTURE | EVENT_METADATA | EVENT_CONTENT
} event_type_t;

/* Type of the watch entry */
typedef enum {
	WATCH_FILE,                 /* Watch a specific file */
	WATCH_DIRECTORY             /* Watch a directory */
} watch_type_t;

/* Structure for a watch entry in the configuration */
typedef struct {
	char *name;                 /* Section name in config */
	char *path;                 /* Path to watch */
	watch_type_t type;          /* File or directory */
	event_type_t events;        /* Events to monitor */
	char *command;              /* Command to execute */
	bool log_output;            /* Whether to capture and log command output */
	bool buffer_output;         /* Whether to buffer output until command completes */
	bool recursive;             /* Whether to recursively monitor (for directories) */
	bool hidden;                /* Whether to monitor hidden files/directories */
	double complexity;          /* Multiplier for quiet period calculation (default: 1.0) */
	int processing_delay;       /* Delay in milliseconds before processing events (0 = no delay) */
} watch_entry_t;

/* Global configuration structure */
typedef struct {
	char *config_file;      	/* Path to config file */
	bool daemon_mode;       	/* Run as daemon */
	int syslog_level;       	/* Syslog verbosity */
	watch_entry_t **watches;	/* Array of watch entries */
	int watch_count;        	/* Number of watch entries */
} config_t;

/* Function prototypes */
config_t *config_create(void);
void config_destroy(config_t *config);
bool config_parse_file(config_t *config, const char *filename);
bool config_parse_events(const char *events_str, event_type_t *events);
const char *event_type_to_string(event_type_t event);

#endif /* CONFIG_H */
