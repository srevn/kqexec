#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <fnmatch.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "logger.h"
#include "registry.h"

/* Trim whitespace from a string */
static char *config_trim(char *str) {
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
static char *config_canonize(const char *path, int line_number) {
	if (path == NULL) {
		return NULL;
	}

	char resolved_path[PATH_MAX];
	char absolute_path[PATH_MAX];
	char *result;

	/* First try realpath on the original path (handles both absolute and relative) */
	if (realpath(path, resolved_path) != NULL) {
		/* Success - path exists and was canonicalized */
		log_message(DEBUG, "Canonized path '%s' -> '%s' at line %d", path,
					resolved_path, line_number);
		result = strdup(resolved_path);
	} else {
		/* realpath() failed - need to construct absolute path if relative */
		if (path[0] == '/') {
			/* Already absolute, just use it */
			log_message(DEBUG, "Failed to canonicalize absolute path '%s' at line %d: %s",
						path, line_number, strerror(errno));
			result = strdup(path);
		} else {
			/* Relative path - make it absolute based on current working directory */
			if (getcwd(absolute_path, sizeof(absolute_path)) == NULL) {
				log_message(ERROR, "Failed to get current working directory at line %d: %s",
							line_number, strerror(errno));
				return NULL;
			}

			/* Construct absolute path */
			int ret = snprintf(resolved_path, sizeof(resolved_path), "%s/%s", absolute_path, path);
			if (ret >= (int) sizeof(resolved_path)) {
				log_message(ERROR, "Constructed path too long at line %d", line_number);
				return NULL;
			}

			/* Try to canonicalize the constructed absolute path */
			if (realpath(resolved_path, absolute_path) != NULL) {
				log_message(DEBUG, "Canonized relative path '%s' -> '%s' at line %d", path,
							absolute_path, line_number);
				result = strdup(absolute_path);
			} else {
				/* Use the constructed absolute path anyway */
				log_message(DEBUG, "Failed to canonicalize constructed path '%s' at line %d: %s",
							resolved_path, line_number, strerror(errno));
				result = strdup(resolved_path);
			}
		}
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
		char *trimmed_token = config_trim(token);

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
	static __thread char buffer[64];
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
watchref_t watch_add(config_t *config, registry_t *registry, watch_t *watch) {
	if (!config || !watch || !registry) {
		log_message(ERROR, "Invalid parameters to watch_add");
		return WATCHREF_INVALID;
	}

	/* Determine if snapshots are needed for this watch */
	watch->requires_snapshot = config_snapshot(watch);

	/* Add watch to registry */
	watchref_t watchref = registry_add(registry, watch);
	if (!watchref_valid(watchref)) {
		log_message(ERROR, "Failed to add watch to registry");
		return WATCHREF_INVALID;
	}

	if (watch->is_dynamic) {
		log_message(DEBUG, "Added dynamic watch: %s", watch->path);
	}

	return watchref;
}

/* Remove a watch entry from the configuration */
bool watch_remove(config_t *config, registry_t *registry, watchref_t watchref) {
	if (!config || !registry || !watchref_valid(watchref)) {
		return false;
	}

	watch_t *watch = registry_get(registry, watchref);
	if (watch) {
		log_message(DEBUG, "Removing watch '%s' for path '%s' from config",
					watch->name, watch->path);
	}

	/* Deactivate in registry */
	registry_deactivate(registry, watchref);

	return true;
}

/* Free a watch entry */
void watch_destroy(watch_t *watch) {
	if (watch == NULL) {
		return;
	}

	free(watch->name);
	free(watch->path);
	free(watch->command);
	free(watch->source_pattern);

	/* Free exclude patterns array */
	if (watch->exclude) {
		for (int i = 0; i < watch->num_exclude; i++) {
			free(watch->exclude[i]);
		}
		free(watch->exclude);
	}

	free(watch);
}

/* Create a deep copy of a watch structure */
watch_t *watch_clone(const watch_t *source) {
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
	clone->enabled = source->enabled;
	clone->log_output = source->log_output;
	clone->buffer_output = source->buffer_output;
	clone->recursive = source->recursive;
	clone->hidden = source->hidden;
	clone->environment = source->environment;
	clone->requires_snapshot = source->requires_snapshot;
	clone->complexity = source->complexity;
	clone->batch_timeout = source->batch_timeout;
	clone->processing_delay = source->processing_delay;
	clone->is_dynamic = source->is_dynamic;
	clone->suppressed = source->suppressed;

	/* Copy exclude patterns array */
	clone->num_exclude = source->num_exclude;
	if (source->num_exclude > 0 && source->exclude) {
		clone->exclude = malloc(source->num_exclude * sizeof(char *));
		if (clone->exclude) {
			for (int i = 0; i < source->num_exclude; i++) {
				clone->exclude[i] = source->exclude[i] ? strdup(source->exclude[i]) : NULL;
			}
		} else {
			clone->num_exclude = 0;
		}
	} else {
		clone->exclude = NULL;
	}

	/* Check for strdup failures */
	bool exclude_failure = false;
	if (source->num_exclude > 0 && source->exclude) {
		for (int i = 0; i < source->num_exclude; i++) {
			if (source->exclude[i] && !clone->exclude[i]) {
				exclude_failure = true;
				break;
			}
		}
	}

	if ((source->name && !clone->name) || (source->path && !clone->path) || (source->command && !clone->command) ||
		(source->source_pattern && !clone->source_pattern) || exclude_failure) {
		log_message(ERROR, "Failed to allocate strings for watch clone");
		watch_destroy(clone);
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
	config->socket_path = NULL;
	config->daemon_mode = false;
	config->syslog_level = NOTICE;

	/* Initialize variables storage */
	config->variables = NULL;
	config->num_variables = 0;
	config->variables_capacity = 0;

	return config;
}

/* Destroy a configuration structure */
void config_destroy(config_t *config) {
	if (config == NULL) {
		return;
	}

	free(config->config_path);
	free(config->socket_path);

	/* Free variables array */
	if (config->variables) {
		for (int i = 0; i < config->num_variables; i++) {
			free(config->variables[i].key);
			free(config->variables[i].value);
		}
		free(config->variables);
	}

	free(config);
}

/* Parse the configuration file */
bool config_parse(config_t *config, registry_t *registry, const char *filename) {
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
		log_message(ERROR, "Failed to open config file %s: %s", filename, strerror(errno));
		return false;
	}

	config->config_path = strdup(filename);

	/* Parse variables and watches */
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
		str = config_trim(line);

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
			next_str = config_trim(next_line);

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

			/* Check section type for inline processing */
			char *section_name = config_trim(str + 1);
			if (strcasecmp(section_name, "Variables") == 0) {
				state = SECTION_VARIABLES;
				log_message(DEBUG, "Entering [Variables] section for inline processing");
				continue;
			}

			/* Create a new watch entry */
			if (current_watch != NULL) {
				/* Validate the previous watch entry */
				if (current_watch->path == NULL) {
					log_message(ERROR, "Missing path in section [%s]", current_watch->name);
					watch_destroy(current_watch);
					fclose(fp);
					return false;
				}

				if (current_watch->filter == EVENT_NONE) {
					log_message(ERROR, "Missing or invalid events in section [%s]", current_watch->name);
					watch_destroy(current_watch);
					fclose(fp);
					return false;
				}

				if (current_watch->command == NULL) {
					log_message(ERROR, "Missing command in section [%s]", current_watch->name);
					watch_destroy(current_watch);
					fclose(fp);
					return false;
				}

				/* Add the watch entry to the configuration */
				if (!watchref_valid(watch_add(config, registry, current_watch))) {
					watch_destroy(current_watch);
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
			current_watch->enabled = true;					   /* Default to enabled */
			current_watch->log_output = false;				   /* Default to not logging command output */
			current_watch->buffer_output = false;			   /* Default to not buffering output */
			current_watch->recursive = true;				   /* Default to recursive for directories */
			current_watch->hidden = false;					   /* Default to not including hidden files */
			current_watch->complexity = 1.0;				   /* Default complexity multiplier */
			current_watch->environment = false;				   /* Default to not injecting environment variables */
			current_watch->batch_timeout = 0;				   /* Default to disabled */
			current_watch->processing_delay = 0;			   /* Default to no delay */
			current_watch->suppressed = (struct timespec) {0}; /* Default to not suppressed */

			/* Initialize exclude patterns */
			current_watch->exclude = NULL;
			current_watch->num_exclude = 0;

			/* Initialize dynamic tracking fields */
			current_watch->is_dynamic = false;
			current_watch->source_pattern = NULL;
			state = SECTION_ENTRY;

			continue;
		}

		/* Parse key-value pairs */
		if (state == SECTION_VARIABLES) {
			/* Handle Variables section entries */
			char *key, *value;

			key = strtok(str, "=");
			if (key == NULL) {
				log_message(ERROR, "Malformed variable assignment at line %d", line_number);
				fclose(fp);
				return false;
			}

			value = strtok(NULL, "");
			if (value == NULL) {
				log_message(ERROR, "Missing value for variable at line %d", line_number);
				fclose(fp);
				return false;
			}

			key = config_trim(key);
			value = config_trim(value);

			/* Add variable to configuration */
			if (!variable_add(config, key, value)) {
				log_message(ERROR, "Failed to add variable '%s' at line %d", key, line_number);
				fclose(fp);
				return false;
			}
		} else if (state == SECTION_ENTRY) {
			char *key, *value;

			key = strtok(str, "=");
			if (key == NULL) {
				log_message(ERROR, "Malformed key-value pair at line %d", line_number);
				watch_destroy(current_watch);
				fclose(fp);
				return false;
			}

			value = strtok(NULL, "");
			if (value == NULL) {
				log_message(ERROR, "Missing value at line %d", line_number);
				watch_destroy(current_watch);
				fclose(fp);
				return false;
			}

			key = config_trim(key);
			value = config_trim(value);

			if (strcasecmp(key, "file") == 0) {
				/* Expand variables in file path */
				char *expanded_value = variable_resolve(config, value);
				if (!expanded_value) {
					log_message(ERROR, "Failed to expand variables in file path at line %d", line_number);
					watch_destroy(current_watch);
					fclose(fp);
					return false;
				}
				current_watch->target = WATCH_FILE;
				current_watch->path = config_canonize(expanded_value, line_number);
				free(expanded_value);
				if (current_watch->path == NULL) {
					watch_destroy(current_watch);
					fclose(fp);
					return false;
				}
			} else if (strcasecmp(key, "directory") == 0) {
				/* Expand variables in directory path */
				char *expanded_value = variable_resolve(config, value);
				if (!expanded_value) {
					log_message(ERROR, "Failed to expand variables in directory path at line %d", line_number);
					watch_destroy(current_watch);
					fclose(fp);
					return false;
				}
				current_watch->target = WATCH_DIRECTORY;
				current_watch->path = config_canonize(expanded_value, line_number);
				free(expanded_value);
				if (current_watch->path == NULL) {
					watch_destroy(current_watch);
					fclose(fp);
					return false;
				}
			} else if (strcasecmp(key, "events") == 0) {
				if (!config_events(value, &current_watch->filter)) {
					log_message(ERROR, "Invalid value for %s at line %d: %s", key,
								line_number, value);
					watch_destroy(current_watch);
					fclose(fp);
					return false;
				}
			} else if (strcasecmp(key, "enabled") == 0) {
				if (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0) {
					current_watch->enabled = true;
				} else if (strcasecmp(value, "false") == 0 || strcmp(value, "0") == 0) {
					current_watch->enabled = false;
				} else {
					log_message(ERROR, "Invalid value for %s at line %d: %s", key,
								line_number, value);
					watch_destroy(current_watch);
					fclose(fp);
					return false;
				}
			} else if (strcasecmp(key, "command") == 0) {
				/* Expand variables in command */
				char *expanded_value = variable_resolve(config, value);
				if (!expanded_value) {
					log_message(ERROR, "Failed to expand variables in command at line %d", line_number);
					watch_destroy(current_watch);
					fclose(fp);
					return false;
				}
				current_watch->command = expanded_value;
			} else if (strcasecmp(key, "log_output") == 0 || strcasecmp(key, "log") == 0) {
				if (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0) {
					current_watch->log_output = true;
				} else if (strcasecmp(value, "false") == 0 || strcmp(value, "0") == 0) {
					current_watch->log_output = false;
				} else {
					log_message(ERROR, "Invalid value for %s at line %d: %s", key,
								line_number, value);
					watch_destroy(current_watch);
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
					watch_destroy(current_watch);
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
					watch_destroy(current_watch);
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
					watch_destroy(current_watch);
					fclose(fp);
					return false;
				}
			} else if (strcasecmp(key, "complexity") == 0) {
				double complexity_value = atof(value);
				if (complexity_value < 0.1 || complexity_value > 5.0) {
					log_message(ERROR, "Invalid %s value at line %d: %s, must be between 0.1 and 5.0",
								key, line_number, value);
					watch_destroy(current_watch);
					fclose(fp);
					return false;
				} else {
					current_watch->complexity = complexity_value;
				}
			} else if (strcasecmp(key, "environment") == 0 || strcasecmp(key, "env_vars") == 0) {
				if (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0) {
					current_watch->environment = true;
				} else if (strcasecmp(value, "false") == 0 || strcmp(value, "0") == 0) {
					current_watch->environment = false;
				} else {
					log_message(ERROR, "Invalid value for %s at line %d: %s", key,
								line_number, value);
					watch_destroy(current_watch);
					fclose(fp);
					return false;
				}
			} else if (strcasecmp(key, "batch_timeout") == 0 || strcasecmp(key, "timeout") == 0) {
				int batch_timeout_value = atoi(value);
				if (batch_timeout_value < 0) {
					log_message(ERROR, "Invalid %s value at line %d: %s (must be >= 0)", key,
								line_number, value);
					watch_destroy(current_watch);
					fclose(fp);
					return false;
				} else {
					current_watch->batch_timeout = batch_timeout_value;
				}
			} else if (strcasecmp(key, "processing_delay") == 0 || strcasecmp(key, "delay") == 0) {
				int processing_delay_value = atoi(value);
				if (processing_delay_value < 0) {
					log_message(ERROR, "Invalid %s value at line %d: %s (must be >= 0)", key,
								line_number, value);
					watch_destroy(current_watch);
					fclose(fp);
					return false;
				} else {
					current_watch->processing_delay = processing_delay_value;
				}
			} else if (strcasecmp(key, "exclude") == 0 || strcasecmp(key, "ignore") == 0) {
				char *patterns = strdup(value);
				if (patterns == NULL) {
					log_message(ERROR, "Failed to allocate memory for exclude patterns at line %d",
								line_number);
					watch_destroy(current_watch);
					fclose(fp);
					return false;
				}
				char *token, *saveptr;
				token = strtok_r(patterns, ",", &saveptr);
				while (token != NULL) {
					char *trimmed_pattern = config_trim(token);
					if (strlen(trimmed_pattern) > 0) {
						if (!exclude_add(current_watch, trimmed_pattern)) {
							log_message(ERROR, "Failed to add exclude pattern '%s' at line %d",
										trimmed_pattern, line_number);
							free(patterns);
							watch_destroy(current_watch);
							fclose(fp);
							return false;
						}
					}
					token = strtok_r(NULL, ",", &saveptr);
				}
				free(patterns);
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
			watch_destroy(current_watch);
			fclose(fp);
			return false;
		}

		if (current_watch->filter == EVENT_NONE) {
			log_message(ERROR, "Missing or invalid events in section [%s]", current_watch->name);
			watch_destroy(current_watch);
			fclose(fp);
			return false;
		}

		if (current_watch->command == NULL) {
			log_message(ERROR, "Missing command in section [%s]", current_watch->name);
			watch_destroy(current_watch);
			fclose(fp);
			return false;
		}

		/* Add the watch entry to the configuration */
		if (!watchref_valid(watch_add(config, registry, current_watch))) {
			watch_destroy(current_watch);
			fclose(fp);
			return false;
		}
	}

	fclose(fp);

	/* Log variables summary */
	if (config->num_variables > 0) {
		log_message(INFO, "Parsed %d variables from [Variables] section", config->num_variables);
	}

	/* Final pass to resolve all variables against each other for consistency */
	for (int i = 0; i < config->num_variables; i++) {
		char *resolved_value = variable_resolve(config, config->variables[i].value);
		if (!resolved_value) {
			log_message(ERROR, "Failed to resolve variable '%s' during final resolution pass",
						config->variables[i].key);
			return false;
		}
		free(config->variables[i].value);
		config->variables[i].value = resolved_value;
	}

	/* Check if we have at least one watch entry */
	uint32_t num_active = 0;
	watchref_t *watchrefs = registry_active(registry, &num_active);
	if (watchrefs) {
		free(watchrefs);
	}
	if (num_active == 0) {
		log_message(ERROR, "No valid watch entries found in config file");
		return false;
	}

	return true;
}

/* Determine if a watch needs snapshot functionality */
bool config_snapshot(const watch_t *watch) {
	if (!watch) return false;

	/* Snapshots are only applicable to directory watches */
	if (watch->target != WATCH_DIRECTORY) {
		return false;
	}

	/* If environment flag is set, we need snapshots for KQ_* variables */
	if (watch->environment) {
		return true;
	}

	/* If no command is specified, no snapshots needed */
	if (!watch->command) {
		return false;
	}

	/* Check for snapshot-dependent placeholders in the command */
	const char *snapshot_placeholders[] = {
		"%created",
		"%deleted",
		"%modified",
		"%renamed",
		"%l", /* List of changed basenames */
		"%L", /* List of changed full paths */
		NULL
	};

	for (int i = 0; snapshot_placeholders[i]; i++) {
		if (strstr(watch->command, snapshot_placeholders[i])) {
			return true;
		}
	}

	/* Check for template-based diff array placeholders */
	if (strstr(watch->command, "%[")) {
		/* Look for diff array templates like %[created:%s] */
		const char *template_arrays[] = {
			"%[created",
			"%[deleted",
			"%[modified",
			"%[renamed",
			"%[created_path",
			"%[deleted_path",
			"%[modified_path",
			"%[renamed_path",
			NULL
		};

		for (int i = 0; template_arrays[i]; i++) {
			if (strstr(watch->command, template_arrays[i])) {
				return true;
			}
		}
	}

	return false;
}

/* Add an exclude pattern to a watch */
bool exclude_add(watch_t *watch, const char *pattern) {
	if (!watch || !pattern || strlen(pattern) == 0) {
		return false;
	}

	/* Expand exclude array */
	char **new_exclude = realloc(watch->exclude, (watch->num_exclude + 1) * sizeof(char *));
	if (new_exclude == NULL) {
		log_message(ERROR, "Failed to allocate memory for exclude pattern");
		return false;
	}

	watch->exclude = new_exclude;
	watch->exclude[watch->num_exclude] = strdup(pattern);
	if (watch->exclude[watch->num_exclude] == NULL) {
		log_message(ERROR, "Failed to duplicate exclude pattern: %s", pattern);
		return false;
	}

	watch->num_exclude++;
	log_message(DEBUG, "Added exclude pattern: %s", pattern);
	return true;
}

/* Check if a path matches any exclude pattern in a watch */
bool exclude_match(const watch_t *watch, const char *path) {
	if (!watch || !path || watch->num_exclude == 0 || !watch->exclude) {
		return false;
	}

	/* Calculate relative path from watch base to target path */
	const char *relative_path = path;
	if (watch->path && strncmp(path, watch->path, strlen(watch->path)) == 0) {
		/* Verify path is truly within watch directory hierarchy */
		size_t base_len = strlen(watch->path);
		if (path[base_len] == '/') {
			/* Path is under watch directory, extract relative portion */
			relative_path = path + base_len + 1; /* Skip the base path and trailing slash */
		} else if (path[base_len] == '\0') {
			/* Target is the watch directory itself */
			relative_path = ".";
		} else if (strcmp(watch->path, "/") == 0 && path[0] == '/') {
			/* Root directory watch - all absolute paths are within hierarchy */
			relative_path = path + 1; /* Skip the leading slash */
		} else {
			/* Path starts with watch path but is not within hierarchy */
			return false;
		}
	}

	for (int i = 0; i < watch->num_exclude; i++) {
		const char *pattern = watch->exclude[i];
		if (!pattern) continue;

		/* Determine matching strategy based on pattern content */
		if (strchr(pattern, '/') != NULL) {
			/* Pattern contains '/' - match against relative path */
			if (fnmatch(pattern, relative_path, FNM_PATHNAME) == 0) {
				return true;
			}

			/* Handle trailing slash patterns for directories */
			size_t pattern_len = strlen(pattern);
			if (pattern_len > 0 && pattern[pattern_len - 1] == '/') {
				/* Create pattern without trailing slash */
				char dir_pattern[PATH_MAX];
				strncpy(dir_pattern, pattern, pattern_len - 1);
				dir_pattern[pattern_len - 1] = '\0';

				/* Check if it matches the directory itself */
				if (fnmatch(dir_pattern, relative_path, FNM_PATHNAME) == 0) {
					return true;
				}

				/* Check if relative_path is within this directory */
				size_t dir_len = strlen(dir_pattern);
				if (strncmp(relative_path, dir_pattern, dir_len) == 0) {
					/* Path starts with directory name */
					if (relative_path[dir_len] == '/') {
						return true;
					}
				}
			}

			/* Check for recursive pattern ending with suffix */
			if (pattern_len >= 3 && strcmp(pattern + pattern_len - 3, "/**") == 0) {
				/* Create base pattern without suffix */
				char base_pattern[PATH_MAX];
				strncpy(base_pattern, pattern, pattern_len - 3);
				base_pattern[pattern_len - 3] = '\0';

				/* Check if path starts with the base pattern */
				if (strncmp(relative_path, base_pattern, strlen(base_pattern)) == 0) {
					/* Path starts with base pattern - check if it's exactly the directory or under it */
					size_t base_len = strlen(base_pattern);
					if (relative_path[base_len] == '\0' || relative_path[base_len] == '/') {
						return true;
					}
				}
			}
		} else {
			/* Pattern is basename-only - check both directory components and final basename */
			if (strchr(relative_path, '/') != NULL) {
				char path_copy[PATH_MAX];
				strncpy(path_copy, relative_path, sizeof(path_copy) - 1);
				path_copy[sizeof(path_copy) - 1] = '\0';
				char *saveptr;

				char *dir_component = strtok_r(path_copy, "/", &saveptr);
				while (dir_component != NULL) {
					if (fnmatch(pattern, dir_component, 0) == 0) {
						return true; /* Path is within a directory that matches the pattern */
					}
					dir_component = strtok_r(NULL, "/", &saveptr);
				}
			}

			/* Then, check the basename */
			const char *basename;

			/* Handle root and current dir edge cases */
			if (strcmp(relative_path, "/") == 0) {
				/* Root path has no meaningful basename for exclude matching */
				basename = "";
			} else if (strcmp(relative_path, ".") == 0) {
				/* For the watch directory itself, use the basename of the watch path */
				if (watch->path && strcmp(watch->path, "/") == 0) {
					/* Watch path is root, no meaningful basename */
					basename = "";
				} else {
					const char *last_slash = strrchr(watch->path, '/');
					basename = last_slash ? last_slash + 1 : watch->path;
				}
			} else {
				const char *last_slash = strrchr(relative_path, '/');
				basename = last_slash ? last_slash + 1 : relative_path;
			}

			/* Don't match empty basename unless pattern is specifically empty */
			if (strlen(basename) > 0 || strlen(pattern) == 0) {
				if (fnmatch(pattern, basename, 0) == 0) {
					return true;
				}
			}
		}
	}

	return false;
}

/* Add a variable to the configuration */
bool variable_add(config_t *config, const char *key, const char *value) {
	if (!config || !key || !value) {
		log_message(ERROR, "Invalid arguments to variable_add");
		return false;
	}

	/* Validate variable name - alphanumeric and underscore only */
	for (const char *p = key; *p; p++) {
		if (!isalnum((unsigned char) *p) && *p != '_') {
			log_message(ERROR, "Invalid variable name '%s', contains invalid characters", key);
			return false;
		}
	}

	/* Check for reserved prefixes to avoid conflicts */
	if (strncasecmp(key, "KQ_", 3) == 0) {
		log_message(ERROR, "Variable name '%s' conflicts with reserved KQ_ prefix", key);
		return false;
	}

	/* Check if variable already exists (overwrite) */
	for (int i = 0; i < config->num_variables; i++) {
		if (strcmp(config->variables[i].key, key) == 0) {
			/* Replace existing variable */
			free(config->variables[i].value);
			config->variables[i].value = strdup(value);
			if (!config->variables[i].value) {
				log_message(ERROR, "Failed to allocate memory for variable value");
				return false;
			}
			log_message(DEBUG, "Updated variable '%s' = '%s'", key, value);
			return true;
		}
	}

	/* Grow array if needed */
	if (config->num_variables >= config->variables_capacity) {
		int new_capacity = config->variables_capacity == 0 ? 8 : config->variables_capacity * 2;
		variable_t *new_vars = realloc(config->variables, new_capacity * sizeof(variable_t));
		if (!new_vars) {
			log_message(ERROR, "Failed to allocate memory for variables array");
			return false;
		}
		config->variables = new_vars;
		config->variables_capacity = new_capacity;
	}

	/* Add new variable */
	variable_t *new_var = &config->variables[config->num_variables];
	new_var->key = strdup(key);
	new_var->value = strdup(value);

	if (!new_var->key || !new_var->value) {
		log_message(ERROR, "Failed to allocate memory for variable");
		free(new_var->key);
		free(new_var->value);
		return false;
	}

	config->num_variables++;
	log_message(DEBUG, "Added variable '%s' = '%s'", key, value);

	return true;
}

/* Expands all variables found in configuraion file */
static char *variable_expand(const config_t *config, const char *input) {
	const char *src = input;
	size_t input_len = strlen(input);
	size_t result_capacity = input_len * 2; /* Start with reasonable capacity */
	char *result = malloc(result_capacity + 1);

	if (!result) {
		log_message(ERROR, "Failed to allocate memory for variable expansion");
		return NULL;
	}

	size_t result_len = 0;

	while (*src) {
		if (src[0] == '$' && src[1] == '{') {
			/* Found variable reference */
			const char *var_start = src + 2;
			const char *var_end = strchr(var_start, '}');

			if (!var_end) {
				log_message(ERROR, "Unclosed variable reference in: %s", input);
				free(result);
				return NULL;
			}

			/* Extract variable name */
			size_t var_name_len = var_end - var_start;
			char *var_name = malloc(var_name_len + 1);
			if (!var_name) {
				log_message(ERROR, "Failed to allocate memory for variable name");
				free(result);
				return NULL;
			}
			memcpy(var_name, var_start, var_name_len);
			var_name[var_name_len] = '\0';

			/* Look up variable value */
			const char *var_value = NULL;
			for (int i = 0; i < config->num_variables; i++) {
				if (strcmp(config->variables[i].key, var_name) == 0) {
					var_value = config->variables[i].value;
					break;
				}
			}

			/* Check for self-reference like VAR=${VAR} which indicates env var import */
			if (var_value) {
				char self_reference[MAX_LINE_LEN];
				snprintf(self_reference, sizeof(self_reference), "${%s}", var_name);
				if (strcmp(var_value, self_reference) == 0) {
					var_value = NULL; /* Treat as not found to fall through to getenv */
				}
			}

			/* If not found in config, try environment variables */
			if (!var_value) {
				var_value = getenv(var_name);
			}

			if (!var_value) {
				log_message(ERROR, "Undefined variable: %s", var_name);
				free(var_name);
				free(result);
				return NULL;
			}

			/* Ensure result buffer has enough capacity */
			size_t var_value_len = strlen(var_value);
			if (result_len + var_value_len >= result_capacity) {
				result_capacity = (result_len + var_value_len + input_len) * 2;
				char *new_result = realloc(result, result_capacity + 1);
				if (!new_result) {
					log_message(ERROR, "Failed to reallocate memory for variable expansion");
					free(var_name);
					free(result);
					return NULL;
				}
				result = new_result;
			}

			/* Copy variable value to result */
			memcpy(result + result_len, var_value, var_value_len);
			result_len += var_value_len;

			/* Clean up */
			free(var_name);

			/* Move past the variable reference */
			src = var_end + 1;
		} else {
			/* Regular character - ensure buffer capacity */
			if (result_len >= result_capacity) {
				result_capacity *= 2;
				char *new_result = realloc(result, result_capacity + 1);
				if (!new_result) {
					log_message(ERROR, "Failed to reallocate memory for variable expansion");
					free(result);
					return NULL;
				}
				result = new_result;
			}

			/* Copy regular character */
			result[result_len++] = *src++;
		}
	}

	result[result_len] = '\0';
	return result;
}

/* Variable expansion resolving with circular reference detection */
char *variable_resolve(const config_t *config, const char *value) {
	if (!config || !value) {
		return value ? strdup(value) : NULL;
	}

	/* If no variables defined or no ${} patterns, return copy of original */
	if (config->num_variables == 0 || strstr(value, "${") == NULL) {
		return strdup(value);
	}

	/* Multi-pass expansion for nested variables with circular reference detection */
	char *current = strdup(value);
	if (!current) {
		log_message(ERROR, "Failed to allocate memory for variable expansion");
		return NULL;
	}

	int max_depth = 32;
	for (int depth = 0; depth < max_depth; depth++) {
		char *expanded = variable_expand(config, current);
		if (!expanded) {
			free(current);
			return NULL;
		}

		/* If no change occurred, we're done */
		if (strcmp(current, expanded) == 0) {
			free(current);
			log_message(DEBUG, "Variable expansion completed after %d passes", depth + 1);
			return expanded;
		}

		free(current);
		current = expanded;
		log_message(DEBUG, "Variable expansion (pass %d): %s", depth + 1, current);
	}

	log_message(ERROR, "Circular reference in variable expansion: max depth %d", max_depth);
	free(current);
	return NULL;
}
