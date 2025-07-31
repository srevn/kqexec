#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>

#include "config.h"
#include "registry.h"
#include "logger.h"

/* Trim whitespace from a string */
static char *trim(char *str) {
	if (str == NULL) {
		return NULL;
	}

	char *end;

	/* Trim leading space */
	while (isspace((unsigned char) *str)) {
		str++;
	}

	if (*str == 0) {
		/* All spaces */
		return str;
	}

	/* Trim trailing space */
	end = str + strlen(str) - 1;
	while (end > str && isspace((unsigned char) *end)) {
		end--;
	}

	/* Write new null terminator */
	*(end + 1) = 0;

	return str;
}

/* Canonize a file path using realpath(), with graceful fallback */
static char *canonize_path(const char *path, int line_number) {
	if (path == NULL) {
		return NULL;
	}

	char resolved_path[PATH_MAX];
	char *result;

	if (realpath(path, resolved_path) != NULL) {
		/* Success - path exists and was canonicalized */
		log_message(DEBUG, "Canonized path '%s' -> '%s' at line %d", path, resolved_path, line_number);
		result = strdup(resolved_path);
	} else {
		/* realpath() failed - log warning and use original path */
		log_message(WARNING, "Failed to canonicalize path '%s' at line %d: %s (using original path)",
		            path, line_number, strerror(errno));
		result = strdup(path);
	}

	if (result == NULL) {
		log_message(ERROR, "Memory allocation failed for path at line %d", line_number);
	}

	return result;
}

/* Parse event type string */
bool config_events(const char *events_str, filter_t *events) {
	*events = EVENT_NONE;
	char *events_copy, *token, *saveptr;

	if (events_str == NULL) {
		return true;
	}

	events_copy = strdup(events_str);
	if (events_copy == NULL) {
		return false;
	}

	token = strtok_r(events_copy, ",", &saveptr);
	while (token != NULL) {
		char *trimmed_token = trim(token);

		if (strcasecmp(trimmed_token, "STRUCTURE") == 0) {
			*events |= EVENT_STRUCTURE;
		} else if (strcasecmp(trimmed_token, "METADATA") == 0) {
			*events |= EVENT_METADATA;
		} else if (strcasecmp(trimmed_token, "CONTENT") == 0) {
			*events |= EVENT_CONTENT;
		} else if (strcasecmp(trimmed_token, "ALL") == 0) {
			*events |= EVENT_ALL;
		} else {
			log_message(ERROR, "Unknown event type: %s", trimmed_token);
			free(events_copy);
			return false;
		}

		token = strtok_r(NULL, ",", &saveptr);
	}

	free(events_copy);
	return true;
}

/* Convert event type to string representation */
const char *filter_to_string(filter_t event) {
	if (event == EVENT_NONE) return "NONE";

	/* Handle composite event types by listing all that apply */
	static char buffer[64];
	buffer[0] = '\0';

	if (event & EVENT_STRUCTURE) {
		strcat(buffer, "STRUCTURE ");
	}
	if (event & EVENT_METADATA) {
		strcat(buffer, "METADATA ");
	}
	if (event & EVENT_CONTENT) {
		strcat(buffer, "CONTENT ");
	}

	/* Remove trailing space if any */
	if (buffer[0] != '\0') {
		buffer[strlen(buffer) - 1] = '\0';
	}

	return buffer;
}



/* Add a watch entry to the configuration */
bool config_add_watch(config_t *config, watch_t *watch, registry_t *registry) {
	if (!config || !watch || !registry) {
		log_message(ERROR, "Invalid parameters to config_add_watch");
		return false;
	}

	/* For non-dynamic watches, check for duplicate names */
	if (!watch->is_dynamic) {
		for (int i = 0; i < config->num_watches; i++) {
			watch_t *existing = registry_get(registry, config->watchrefs[i]);
			if (existing && existing->name && watch->name &&
				strcmp(existing->name, watch->name) == 0) {
				log_message(ERROR, "Duplicate watch name '%s' found in configuration", watch->name);
				return false;
			}
		}
	}

	/* Add watch to registry */
	watchref_t watchref = registry_add(registry, watch);
	if (!watchref_valid(watchref)) {
		log_message(ERROR, "Failed to add watch to registry");
		return false;
	}

	/* Expand watchrefs array */
	watchref_t *new_watchrefs = realloc(config->watchrefs, (config->num_watches + 1) * sizeof(watchref_t));
	if (new_watchrefs == NULL) {
		log_message(ERROR, "Failed to allocate memory for watch reference");
		/* Clean up registry entry */
		registry_deactivate(registry, watchref);
		return false;
	}

	config->watchrefs = new_watchrefs;
	config->watchrefs[config->num_watches] = watchref;
	config->num_watches++;

	if (watch->is_dynamic) {
		log_message(DEBUG, "Added dynamic watch: %s", watch->path);
	}

	return true;
}

/* Remove a watch entry from the configuration */
bool config_remove_watch(config_t *config, watchref_t watchref, registry_t *registry) {
	if (!config || !registry || !watchref_valid(watchref)) {
		return false;
	}

	for (int i = 0; i < config->num_watches; i++) {
		if (watchref_equal(config->watchrefs[i], watchref)) {
			watch_t *watch = registry_get(registry, watchref);
			if (watch) {
				log_message(DEBUG, "Removing watch '%s' for path '%s' from config.", watch->name, watch->path);
			}
			
			/* Deactivate in registry (triggers observer notifications) */
			registry_deactivate(registry, watchref);
			
			/* Remove from config array */
			for (int j = i; j < config->num_watches - 1; j++) {
				config->watchrefs[j] = config->watchrefs[j+1];
			}
			config->num_watches--;
			return true;
		}
	}
	
	log_message(WARNING, "Could not find watch reference in config to remove.");
	return false;
}

/* Free a watch entry */
void config_destroy_watch(watch_t *watch) {
	if (watch == NULL) {
		return;
	}

	free(watch->name);
	free(watch->path);
	free(watch->command);
	free(watch->source_pattern);
	free(watch);
}

/* Create a deep copy of a watch structure */
watch_t *config_clone_watch(const watch_t *source) {
	if (source == NULL) {
		return NULL;
	}

	watch_t *clone = calloc(1, sizeof(watch_t));
	if (clone == NULL) {
		log_message(ERROR, "Failed to allocate memory for watch clone");
		return NULL;
	}

	/* Copy all fields from the source watch */
	clone->name = source->name ? strdup(source->name) : NULL;
	clone->path = source->path ? strdup(source->path) : NULL;
	clone->command = source->command ? strdup(source->command) : NULL;
	clone->source_pattern = source->source_pattern ? strdup(source->source_pattern) : NULL;
	clone->target = source->target;
	clone->filter = source->filter;
	clone->log_output = source->log_output;
	clone->buffer_output = source->buffer_output;
	clone->recursive = source->recursive;
	clone->hidden = source->hidden;
	clone->environment = source->environment;
	clone->complexity = source->complexity;
	clone->processing_delay = source->processing_delay;
	clone->is_dynamic = source->is_dynamic;

	/* Check for strdup failures */
	if ((source->name && !clone->name) ||
	    (source->path && !clone->path) ||
	    (source->command && !clone->command) ||
	    (source->source_pattern && !clone->source_pattern)) {
		log_message(ERROR, "Failed to allocate strings for watch clone");
		config_destroy_watch(clone);
		return NULL;
	}

	return clone;
}

/* Create a new configuration structure */
config_t *config_create(void) {
	config_t *config = calloc(1, sizeof(config_t));
	if (config == NULL) {
		log_message(ERROR, "Failed to allocate memory for configuration");
		return NULL;
	}

	/* Set default values */
	config->daemon_mode = false;
	config->syslog_level = NOTICE;
	config->watchrefs = NULL;
	config->num_watches = 0;

	return config;
}

/* Destroy a configuration structure */
void config_destroy(config_t *config) {
	if (config == NULL) {
		return;
	}

	free(config->config_path);
	free(config->watchrefs);
	free(config);
}

/* Parse the configuration file */
bool config_parse(config_t *config, const char *filename, registry_t *registry) {
	FILE *fp;
	char line[MAX_LINE_LEN];
	section_t state = SECTION_NONE;
	watch_t *current_watch = NULL;
	int line_number = 0;

	if (config == NULL || filename == NULL) {
		log_message(ERROR, "Invalid arguments to config_parse");
		return false;
	}

	fp = fopen(filename, "r");
	if (fp == NULL) {
		log_message(ERROR, "Failed to open config file %s: %s",
		            filename, strerror(errno));
		return false;
	}

	config->config_path = strdup(filename);

	while (fgets(line, sizeof(line), fp) != NULL) {
		char *str;
		char continued_line[MAX_LINE_LEN * 10] = {0}; /* Buffer for continued lines */

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

		/* Handle line continuation */
		strcpy(continued_line, str);

		/* Check if line ends with backslash for continuation */
		while (strlen(continued_line) > 0 && continued_line[strlen(continued_line) - 1] == '\\') {
			char next_line[MAX_LINE_LEN];
			char *next_str;

			/* Remove the trailing backslash */
			continued_line[strlen(continued_line) - 1] = '\0';

			/* Read next line */
			if (fgets(next_line, sizeof(next_line), fp) == NULL) {
				break; /* End of file */
			}

			line_number++;

			/* Remove comments from next line */
			next_str = strchr(next_line, '#');
			if (next_str != NULL) {
				*next_str = '\0';
			}

			/* Trim whitespace from next line */
			next_str = trim(next_line);

			/* Skip empty continuation lines */
			if (*next_str == '\0') {
				continue;
			}

			/* Append next line with a space separator */
			if (strlen(continued_line) + strlen(next_str) + 1 < sizeof(continued_line)) {
				strcat(continued_line, " ");
				strcat(continued_line, next_str);
			} else {
				log_message(ERROR, "Line too long after continuation at line %d", line_number);
				fclose(fp);
				return false;
			}
		}

		/* Use the continued line for further processing */
		str = continued_line;

		/* Parse section header */
		if (*str == '[') {
			char *end = strchr(str, ']');
			if (end == NULL) {
				log_message(ERROR, "Malformed section header at line %d", line_number);
				fclose(fp);
				return false;
			}

			*end = '\0';

			/* Create a new watch entry */
			if (current_watch != NULL) {
				/* Validate the previous watch entry */
				if (current_watch->path == NULL) {
					log_message(ERROR, "Missing path in section [%s]", current_watch->name);
					config_destroy_watch(current_watch);
					fclose(fp);
					return false;
				}

				if (current_watch->filter == EVENT_NONE) {
					log_message(ERROR, "Missing or invalid events in section [%s]", current_watch->name);
					config_destroy_watch(current_watch);
					fclose(fp);
					return false;
				}

				if (current_watch->command == NULL) {
					log_message(ERROR, "Missing command in section [%s]", current_watch->name);
					config_destroy_watch(current_watch);
					fclose(fp);
					return false;
				}

				/* Add the watch entry to the configuration */
				if (!config_add_watch(config, current_watch, registry)) {
					config_destroy_watch(current_watch);
					fclose(fp);
					return false;
				}
			}

			/* Start a new section */
			current_watch = calloc(1, sizeof(watch_t));
			if (current_watch == NULL) {
				log_message(ERROR, "Failed to allocate memory for watch entry");
				fclose(fp);
				return false;
			}

			current_watch->name = strdup(str + 1);
			current_watch->log_output = false; /* Default to not logging command output */
			current_watch->buffer_output = false; /* Default to not buffering output */
			current_watch->recursive = true; /* Default to recursive for directories */
			current_watch->hidden = false; /* Default to not including hidden files */
			current_watch->environment = false; /* Default to not injecting environment variables */
			current_watch->processing_delay = 0; /* Default to no delay */
			current_watch->complexity = 1.0; /* Default complexity multiplier */
			
			/* Initialize dynamic tracking fields */
			current_watch->is_dynamic = false;
			current_watch->source_pattern = NULL;
			state = SECTION_ENTRY;

			continue;
		}

		/* Parse key-value pairs */
		if (state == SECTION_ENTRY) {
			char *key, *value;

			key = strtok(str, "=");
			if (key == NULL) {
				log_message(ERROR, "Malformed key-value pair at line %d", line_number);
				config_destroy_watch(current_watch);
				fclose(fp);
				return false;
			}

			value = strtok(NULL, "");
			if (value == NULL) {
				log_message(ERROR, "Missing value at line %d", line_number);
				config_destroy_watch(current_watch);
				fclose(fp);
				return false;
			}

			key = trim(key);
			value = trim(value);

			if (strcasecmp(key, "file") == 0) {
				current_watch->target = WATCH_FILE;
				current_watch->path = canonize_path(value, line_number);
				if (current_watch->path == NULL) {
					config_destroy_watch(current_watch);
					fclose(fp);
					return false;
				}
			} else if (strcasecmp(key, "directory") == 0) {
				current_watch->target = WATCH_DIRECTORY;
				current_watch->path = canonize_path(value, line_number);
				if (current_watch->path == NULL) {
					config_destroy_watch(current_watch);
					fclose(fp);
					return false;
				}
			} else if (strcasecmp(key, "events") == 0) {
				if (!config_events(value, &current_watch->filter)) {
					log_message(ERROR, "Invalid value for %s at line %d: %s", key,
					            line_number, value);
					config_destroy_watch(current_watch);
					fclose(fp);
					return false;
				}
			} else if (strcasecmp(key, "command") == 0) {
				current_watch->command = strdup(value);
			} else if (strcasecmp(key, "log_output") == 0 || strcasecmp(key, "log") == 0) {
				if (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0) {
					current_watch->log_output = true;
				} else if (strcasecmp(value, "false") == 0 || strcmp(value, "0") == 0) {
					current_watch->log_output = false;
				} else {
					log_message(ERROR, "Invalid value for %s at line %d: %s", key,
					            line_number, value);
					config_destroy_watch(current_watch);
					fclose(fp);
					return false;
				}
			} else if (strcasecmp(key, "buffer_output") == 0 || strcasecmp(key, "buffer") == 0) {
				if (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0) {
					current_watch->buffer_output = true;
				} else if (strcasecmp(value, "false") == 0 || strcmp(value, "0") == 0) {
					current_watch->buffer_output = false;
				} else {
					log_message(ERROR, "Invalid value for %s at line %d: %s", key,
					            line_number, value);
					config_destroy_watch(current_watch);
					fclose(fp);
					return false;
				}
			} else if (strcasecmp(key, "recursive") == 0) {
				if (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0) {
					current_watch->recursive = true;
				} else if (strcasecmp(value, "false") == 0 || strcmp(value, "0") == 0) {
					current_watch->recursive = false;
				} else {
					log_message(ERROR, "Invalid value for %s at line %d: %s", key,
					            line_number, value);
					config_destroy_watch(current_watch);
					fclose(fp);
					return false;
				}
			} else if (strcasecmp(key, "hidden") == 0 || strcasecmp(key, "include_hidden") == 0) {
				if (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0) {
					current_watch->hidden = true;
				} else if (strcasecmp(value, "false") == 0 || strcmp(value, "0") == 0) {
					current_watch->hidden = false;
				} else {
					log_message(ERROR, "Invalid value for %s at line %d: %s", key,
					            line_number, value);
					config_destroy_watch(current_watch);
					fclose(fp);
					return false;
				}
			} else if (strcasecmp(key, "environment") == 0 || strcasecmp(key, "env_vars") == 0) {
				if (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0) {
					current_watch->environment = true;
				} else if (strcasecmp(value, "false") == 0 || strcmp(value, "0") == 0) {
					current_watch->environment = false;
				} else {
					log_message(ERROR, "Invalid value for %s at line %d: %s", key,
					            line_number, value);
					config_destroy_watch(current_watch);
					fclose(fp);
					return false;
				}
			} else if (strcasecmp(key, "complexity") == 0) {
				double complexity_value = atof(value);
				if (complexity_value <= 0) {
					log_message(ERROR, "Invalid %s value at line %d: %s (must be > 0)", key,
					            line_number, value);
					config_destroy_watch(current_watch);
					fclose(fp);
					return false;
				} else {
					current_watch->complexity = complexity_value;
				}
			} else if (strcasecmp(key, "processing_delay") == 0 || strcasecmp(key, "delay") == 0) {
				int processing_delay_value = atoi(value);
				if (processing_delay_value < 0) {
					log_message(ERROR, "Invalid %s value at line %d: %s (must be >= 0)", key,
					            line_number, value);
					config_destroy_watch(current_watch);
					fclose(fp);
					return false;
				} else {
					current_watch->processing_delay = processing_delay_value;
				}
			} else {
				log_message(WARNING, "Unknown key at line %d: %s", line_number, key);
			}
		}
	}

	/* Process the last watch entry */
	if (current_watch != NULL) {
		/* Validate the watch entry */
		if (current_watch->path == NULL) {
			log_message(ERROR, "Missing path in section [%s]", current_watch->name);
			config_destroy_watch(current_watch);
			fclose(fp);
			return false;
		}

		if (current_watch->filter == EVENT_NONE) {
			log_message(ERROR, "Missing or invalid events in section [%s]", current_watch->name);
			config_destroy_watch(current_watch);
			fclose(fp);
			return false;
		}

		if (current_watch->command == NULL) {
			log_message(ERROR, "Missing command in section [%s]", current_watch->name);
			config_destroy_watch(current_watch);
			fclose(fp);
			return false;
		}

		/* Add the watch entry to the configuration */
		if (!config_add_watch(config, current_watch, registry)) {
			config_destroy_watch(current_watch);
			fclose(fp);
			return false;
		}
	}

	fclose(fp);

	/* Check if we have at least one watch entry */
	if (config->num_watches == 0) {
		log_message(ERROR, "No valid watch entries found in config file");
		return false;
	}

	return true;
}

/* Get watch by index using registry lookup */
watch_t *config_get_watch(config_t *config, int index, registry_t *registry) {
	if (!config || !registry || index < 0 || index >= config->num_watches) {
		return NULL;
	}
	
	return registry_get(registry, config->watchrefs[index]);
}

/* Get watch reference by index */
watchref_t config_get_watchref(config_t *config, int index) {
	if (!config || index < 0 || index >= config->num_watches) {
		return WATCH_REF_INVALID;
	}
	
	return config->watchrefs[index];
}
