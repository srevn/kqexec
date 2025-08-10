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
	char absolute_path[PATH_MAX];
	char *result;

	/* First try realpath on the original path (handles both absolute and relative) */
	if (realpath(path, resolved_path) != NULL) {
		/* Success - path exists and was canonicalized */
		log_message(DEBUG, "Canonized path '%s' -> '%s' at line %d", path, resolved_path, line_number);
		result = strdup(resolved_path);
	} else {
		/* realpath() failed - need to construct absolute path if relative */
		if (path[0] == '/') {
			/* Already absolute, just use it */
			log_message(DEBUG, "Failed to canonicalize absolute path '%s' at line %d: %s (using original path)",
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
			if (ret >= (int)sizeof(resolved_path)) {
				log_message(ERROR, "Constructed path too long at line %d", line_number);
				return NULL;
			}

			/* Try to canonicalize the constructed absolute path */
			if (realpath(resolved_path, absolute_path) != NULL) {
				log_message(DEBUG, "Canonized relative path '%s' -> '%s' at line %d", path, absolute_path, line_number);
				result = strdup(absolute_path);
			} else {
				/* Use the constructed absolute path anyway */
				log_message(DEBUG, "Failed to canonicalize constructed path '%s' at line %d: %s (using constructed absolute path)",
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
bool config_add_watch(config_t *config, registry_t *registry, watch_t *watch) {
	if (!config || !watch || !registry) {
		log_message(ERROR, "Invalid parameters to config_add_watch");
		return false;
	}

	/* For non-dynamic watches, check for duplicate names against all active watches */
	if (!watch->is_dynamic) {
		uint32_t num_active = 0;
		watchref_t *watchrefs = registry_active(registry, &num_active);
		if (watchrefs) {
			for (uint32_t i = 0; i < num_active; i++) {
				watch_t *existing = registry_get(registry, watchrefs[i]);
				if (existing && existing->name && watch->name && strcmp(existing->name, watch->name) == 0) {
					log_message(ERROR, "Duplicate watch name '%s' found in configuration", watch->name);
					free(watchrefs);
					return false;
				}
			}
			free(watchrefs);
		}
	}

	/* Add watch to registry */
	watchref_t watchref = registry_add(registry, watch);
	if (!watchref_valid(watchref)) {
		log_message(ERROR, "Failed to add watch to registry");
		return false;
	}

	if (watch->is_dynamic) {
		log_message(DEBUG, "Added dynamic watch: %s", watch->path);
	}

	return true;
}

/* Remove a watch entry from the configuration */
bool config_remove_watch(config_t *config, registry_t *registry, watchref_t watchref) {
	if (!config || !registry || !watchref_valid(watchref)) {
		return false;
	}

	watch_t *watch = registry_get(registry, watchref);
	if (watch) {
		log_message(DEBUG, "Removing watch '%s' for path '%s' from config", watch->name, watch->path);
	}

	/* Deactivate in registry (triggers observer notifications) */
	registry_deactivate(registry, watchref);

	return true;
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

	return config;
}

/* Destroy a configuration structure */
void config_destroy(config_t *config) {
	if (config == NULL) {
		return;
	}

	free(config->config_path);
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
				if (!config_add_watch(config, registry, current_watch)) {
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
			current_watch->log_output = false;	  /* Default to not logging command output */
			current_watch->buffer_output = false; /* Default to not buffering output */
			current_watch->recursive = true;	  /* Default to recursive for directories */
			current_watch->hidden = false;		  /* Default to not including hidden files */
			current_watch->environment = false;	  /* Default to not injecting environment variables */
			current_watch->processing_delay = 0;  /* Default to no delay */
			current_watch->complexity = 1.0;	  /* Default complexity multiplier */

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
			} else if (strcasecmp(key, "exclude") == 0 || strcasecmp(key, "ignore") == 0) {
				char *patterns = strdup(value);
				if (patterns == NULL) {
					log_message(ERROR, "Failed to allocate memory for exclude patterns at line %d",
								line_number);
					config_destroy_watch(current_watch);
					fclose(fp);
					return false;
				}
				char *token, *saveptr;
				token = strtok_r(patterns, ",", &saveptr);
				while (token != NULL) {
					char *trimmed_pattern = trim(token);
					if (strlen(trimmed_pattern) > 0) {
						if (!config_exclude_add(current_watch, trimmed_pattern)) {
							log_message(ERROR, "Failed to add exclude pattern '%s' at line %d",
										trimmed_pattern, line_number);
							free(patterns);
							config_destroy_watch(current_watch);
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
		if (!config_add_watch(config, registry, current_watch)) {
			config_destroy_watch(current_watch);
			fclose(fp);
			return false;
		}
	}

	fclose(fp);

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

/* Add an exclude pattern to a watch */
bool config_exclude_add(watch_t *watch, const char *pattern) {
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
bool config_exclude_match(const watch_t *watch, const char *path) {
	if (!watch || !path || watch->num_exclude == 0 || !watch->exclude) {
		return false;
	}

	/* Calculate relative path from watch base to target path */
	const char *relative_path = path;
	if (watch->path && strncmp(path, watch->path, strlen(watch->path)) == 0) {
		/* Path is under watch directory, extract relative portion */
		size_t base_len = strlen(watch->path);
		if (path[base_len] == '/') {
			relative_path = path + base_len + 1; /* Skip the base path and trailing slash */
		} else if (path[base_len] == '\0') {
			relative_path = "."; /* Target is the watch directory itself */
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

			/* Check for recursive pattern ending with suffix */
			size_t pattern_len = strlen(pattern);
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
			/* Pattern is basename-only - extract basename and match */
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
