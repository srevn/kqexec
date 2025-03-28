#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "config.h"
#include "log.h"

/* Maximum line length in config file */
#define MAX_LINE_LEN 1024

/* Configuration file section parsing state */
typedef enum {
	SECTION_NONE,
	SECTION_ENTRY
} section_state_t;

/* Trim whitespace from a string */
static char *trim(char *str) {
	if (str == NULL) {
		return NULL;
	}
	
	char *end;
	
	/* Trim leading space */
	while (isspace((unsigned char)*str)) {
		str++;
	}
	
	if (*str == 0) { /* All spaces */
		return str;
	}
	
	/* Trim trailing space */
	end = str + strlen(str) - 1;
	while (end > str && isspace((unsigned char)*end)) {
		end--;
	}
	
	/* Write new null terminator */
	*(end + 1) = 0;
	
	return str;
}

/* Parse event type string */
event_type_t config_parse_events(const char *events_str) {
	event_type_t events = EVENT_NONE;
	char *events_copy, *token, *saveptr;
	
	if (events_str == NULL) {
		return events;
	}
	
	events_copy = strdup(events_str);
	if (events_copy == NULL) {
		return events;
	}
	
	token = strtok_r(events_copy, ",", &saveptr);
	while (token != NULL) {
		char *trimmed_token = trim(token);
		
		if (strcasecmp(trimmed_token, "CONTENT") == 0) {
			events |= EVENT_CONTENT;
		} else if (strcasecmp(trimmed_token, "METADATA") == 0) {
			events |= EVENT_METADATA;
		} else if (strcasecmp(trimmed_token, "MODIFY") == 0) {
			events |= EVENT_MODIFY;
		} else if (strcasecmp(trimmed_token, "ALL") == 0) {
			events |= EVENT_ALL;
		} else {
			log_message(LOG_LEVEL_WARNING, "Unknown event type: %s", trimmed_token);
		}
		
		token = strtok_r(NULL, ",", &saveptr);
	}
	
	free(events_copy);
	return events;
}

/* Convert event type to string representation */
const char *event_type_to_string(event_type_t event) {
	if (event == EVENT_NONE) return "NONE";
	
	/* Handle composite event types by listing all that apply */
	static char buffer[64];
	buffer[0] = '\0';
	
	if (event & EVENT_CONTENT) {
		strcat(buffer, "CONTENT ");
	}
	if (event & EVENT_METADATA) {
		strcat(buffer, "METADATA ");
	}
	if (event & EVENT_MODIFY) {
		strcat(buffer, "MODIFY ");
	}
	
	/* Remove trailing space if any */
	if (buffer[0] != '\0') {
		buffer[strlen(buffer) - 1] = '\0';
	}
	
	return buffer;
}

/* Create a new configuration structure */
config_t *config_create(void) {
	config_t *config = calloc(1, sizeof(config_t));
	if (config == NULL) {
		log_message(LOG_LEVEL_ERR, "Failed to allocate memory for configuration");
		return NULL;
	}
	
	/* Set default values */
	config->daemon_mode = false;
	config->syslog_level = LOG_LEVEL_NOTICE;
	config->watches = NULL;
	config->watch_count = 0;
	
	return config;
}

/* Free a watch entry */
static void watch_entry_destroy(watch_entry_t *watch) {
	if (watch == NULL) {
		return;
	}
	
	free(watch->name);
	free(watch->path);
	free(watch->command);
	free(watch);
}

/* Destroy a configuration structure */
void config_destroy(config_t *config) {
	if (config == NULL) {
		return;
	}
	
	free(config->config_file);
	
	for (int i = 0; i < config->watch_count; i++) {
		watch_entry_destroy(config->watches[i]);
	}
	
	free(config->watches);
	free(config);
}

/* Add a watch entry to the configuration */
static bool config_add_watch(config_t *config, watch_entry_t *watch) {
	watch_entry_t **new_watches;
	
	new_watches = realloc(config->watches, (config->watch_count + 1) * sizeof(watch_entry_t *));
	if (new_watches == NULL) {
		log_message(LOG_LEVEL_ERR, "Failed to allocate memory for watch entry");
		return false;
	}
	
	config->watches = new_watches;
	config->watches[config->watch_count] = watch;
	config->watch_count++;
	
	return true;
}

/* Parse the configuration file */
bool config_parse_file(config_t *config, const char *filename) {
	FILE *fp;
	char line[MAX_LINE_LEN];
	section_state_t state = SECTION_NONE;
	watch_entry_t *current_watch = NULL;
	int line_number = 0;
	
	if (config == NULL || filename == NULL) {
		log_message(LOG_LEVEL_ERR, "Invalid arguments to config_parse_file");
		return false;
	}
	
	fp = fopen(filename, "r");
	if (fp == NULL) {
		log_message(LOG_LEVEL_ERR, "Failed to open config file %s: %s", 
				  filename, strerror(errno));
		return false;
	}
	
	config->config_file = strdup(filename);
	
	while (fgets(line, sizeof(line), fp) != NULL) {
		char *str;
		
		line_number++;
		
		/* Remove comments */
		str = strchr(line, '#');
		if (str != NULL) {
			*str = '\0';
		}
		
		/* Trim whitespace */
		str = trim(line);
		
		/* Skip empty lines */
		if (*str == '\0') {
			continue;
		}
		
		/* Parse section header */
		if (*str == '[') {
			char *end = strchr(str, ']');
			if (end == NULL) {
				log_message(LOG_LEVEL_ERR, "Malformed section header at line %d", line_number);
				fclose(fp);
				return false;
			}
			
			*end = '\0';
			
			/* Create a new watch entry */
			if (current_watch != NULL) {
				/* Validate the previous watch entry */
				if (current_watch->path == NULL) {
					log_message(LOG_LEVEL_ERR, "Missing path in section [%s]", current_watch->name);
					watch_entry_destroy(current_watch);
					fclose(fp);
					return false;
				}
				
				if (current_watch->events == EVENT_NONE) {
					log_message(LOG_LEVEL_ERR, "Missing or invalid events in section [%s]", current_watch->name);
					watch_entry_destroy(current_watch);
					fclose(fp);
					return false;
				}
				
				if (current_watch->command == NULL) {
					log_message(LOG_LEVEL_ERR, "Missing command in section [%s]", current_watch->name);
					watch_entry_destroy(current_watch);
					fclose(fp);
					return false;
				}
				
				/* Add the watch entry to the configuration */
				if (!config_add_watch(config, current_watch)) {
					watch_entry_destroy(current_watch);
					fclose(fp);
					return false;
				}
			}
			
			/* Start a new section */
			current_watch = calloc(1, sizeof(watch_entry_t));
			if (current_watch == NULL) {
				log_message(LOG_LEVEL_ERR, "Failed to allocate memory for watch entry");
				fclose(fp);
				return false;
			}
			
			current_watch->name = strdup(str + 1);
			current_watch->recursive = true;  /* Default to recursive for directories */
			current_watch->hidden = false;	/* Default to not including hidden files */
			state = SECTION_ENTRY;
			
			continue;
		}
		
		/* Parse key-value pairs */
		if (state == SECTION_ENTRY) {
			char *key, *value;
			
			key = strtok(str, "=");
			if (key == NULL) {
				log_message(LOG_LEVEL_ERR, "Malformed key-value pair at line %d", line_number);
				watch_entry_destroy(current_watch);
				fclose(fp);
				return false;
			}
			
			value = strtok(NULL, "");
			if (value == NULL) {
				log_message(LOG_LEVEL_ERR, "Missing value at line %d", line_number);
				watch_entry_destroy(current_watch);
				fclose(fp);
				return false;
			}
			
			key = trim(key);
			value = trim(value);
			
			if (strcasecmp(key, "file") == 0) {
				current_watch->type = WATCH_FILE;
				current_watch->path = strdup(value);
			} else if (strcasecmp(key, "directory") == 0) {
				current_watch->type = WATCH_DIRECTORY;
				current_watch->path = strdup(value);
			} else if (strcasecmp(key, "events") == 0) {
				current_watch->events = config_parse_events(value);
			} else if (strcasecmp(key, "command") == 0) {
				current_watch->command = strdup(value);
			} else if (strcasecmp(key, "recursive") == 0) {
				if (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0) {
					current_watch->recursive = true;
				} else if (strcasecmp(value, "false") == 0 || strcmp(value, "0") == 0) {
					current_watch->recursive = false;
				} else {
					log_message(LOG_LEVEL_WARNING, "Invalid value for recursive at line %d: %s", 
							  line_number, value);
				}
			} else if (strcasecmp(key, "hidden") == 0 || strcasecmp(key, "include_hidden") == 0) {
				if (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0) {
					current_watch->hidden = true;
				} else if (strcasecmp(value, "false") == 0 || strcmp(value, "0") == 0) {
					current_watch->hidden = false;
				} else {
					log_message(LOG_LEVEL_WARNING, "Invalid value for hidden at line %d: %s", 
							  line_number, value);
				}
			} else {
				log_message(LOG_LEVEL_WARNING, "Unknown key at line %d: %s", line_number, key);
			}
		}
	}
	
	/* Process the last watch entry */
	if (current_watch != NULL) {
		/* Validate the watch entry */
		if (current_watch->path == NULL) {
			log_message(LOG_LEVEL_ERR, "Missing path in section [%s]", current_watch->name);
			watch_entry_destroy(current_watch);
			fclose(fp);
			return false;
		}
		
		if (current_watch->events == EVENT_NONE) {
			log_message(LOG_LEVEL_ERR, "Missing or invalid events in section [%s]", current_watch->name);
			watch_entry_destroy(current_watch);
			fclose(fp);
			return false;
		}
		
		if (current_watch->command == NULL) {
			log_message(LOG_LEVEL_ERR, "Missing command in section [%s]", current_watch->name);
			watch_entry_destroy(current_watch);
			fclose(fp);
			return false;
		}
		
		/* Add the watch entry to the configuration */
		if (!config_add_watch(config, current_watch)) {
			watch_entry_destroy(current_watch);
			fclose(fp);
			return false;
		}
	}
	
	fclose(fp);
	
	/* Check if we have at least one watch entry */
	if (config->watch_count == 0) {
		log_message(LOG_LEVEL_ERR, "No valid watch entries found in config file");
		return false;
	}
	
	return true;
}
