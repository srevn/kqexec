#include "binder.h"

#include <errno.h>
#include <libgen.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>

#include "logger.h"
#include "resource.h"
#include "snapshot.h"
#include "stability.h"
#include "utilities.h"


/* Forward declarations for placeholder resolvers */
static placeholder_t resolve_path(binder_t *ctx);
static placeholder_t resolve_basename(binder_t *ctx);
static placeholder_t resolve_dirname(binder_t *ctx);
static placeholder_t resolve_watch_path(binder_t *ctx);
static placeholder_t resolve_watch_name(binder_t *ctx);
static placeholder_t resolve_relative_path(binder_t *ctx);
static placeholder_t resolve_time(binder_t *ctx);
static placeholder_t resolve_user(binder_t *ctx);
static placeholder_t resolve_event_type(binder_t *ctx);
static placeholder_t resolve_size(binder_t *ctx);
static placeholder_t resolve_human_size(binder_t *ctx);
static placeholder_t resolve_diff(binder_t *ctx, const char *type, bool basename_only);
static placeholder_t resolve_array(binder_t *ctx, const char *array_spec);
static placeholder_t resolve_exclusion(binder_t *ctx);

/* Create a new binder context */
binder_t *binder_create(monitor_t *monitor, watchref_t watchref, const event_t *event) {
	if (!monitor || !event) {
		log_message(ERROR, "Invalid arguments to binder_create");
		return NULL;
	}
	
	const watch_t *watch = registry_get(monitor->registry, watchref);
	if (!watch) {
		log_message(ERROR, "Invalid watchref in binder_create");
		return NULL;
	}
	
	binder_t *ctx = calloc(1, sizeof(binder_t));
	if (!ctx) {
		log_message(ERROR, "Failed to allocate binder context");
		return NULL;
	}
	
	ctx->monitor = monitor;
	ctx->watchref = watchref;
	ctx->event = event;
	ctx->watch = watch;
	ctx->size_calculated = false;
	
	return ctx;
}

/* Destroy binder context and free all cached data */
void binder_destroy(binder_t *ctx) {
	if (!ctx) return;
	
	free(ctx->escaped_path);
	free(ctx->basename);
	free(ctx->dirname);
	free(ctx->relative_path);
	free(ctx->escaped_relative_path);
	free(ctx->escaped_basename);
	free(ctx->escaped_dirname);
	free(ctx->escaped_watch_path);
	free(ctx->escaped_watch_name);
	free(ctx->time_string);
	free(ctx->user_string);
	free(ctx->event_string);
	free(ctx->size_string);
	free(ctx->human_size_string);
	
	free(ctx);
}

/* Lazy-computed path placeholder */
static placeholder_t resolve_path(binder_t *ctx) {
	if (!ctx->escaped_path) {
		ctx->escaped_path = string_escape(ctx->event->path);
	}
	return (placeholder_t){
		.value = ctx->escaped_path ? ctx->escaped_path : "",
		.allocated = false,     /* Don't free - it's cached in context */
		.pre_formatted = true   /* Already escaped, use as-is */
	};
}

/* Lazy-computed basename placeholder */
static placeholder_t resolve_basename(binder_t *ctx) {
	if (!ctx->basename) {
		char *path_copy = strdup(ctx->event->path);
		if (path_copy) {
			ctx->basename = strdup(basename(path_copy));
			free(path_copy);
		}
	}
	
	if (!ctx->escaped_basename && ctx->basename) {
		ctx->escaped_basename = string_escape(ctx->basename);
	}
	
	return (placeholder_t){
		.value = ctx->escaped_basename ? ctx->escaped_basename : "",
		.allocated = false,  /* Don't free - it's cached in context */
		.pre_formatted = true
	};
}

/* Lazy-computed dirname placeholder */
static placeholder_t resolve_dirname(binder_t *ctx) {
	if (!ctx->dirname) {
		char *path_copy = strdup(ctx->event->path);
		if (path_copy) {
			ctx->dirname = strdup(dirname(path_copy));
			free(path_copy);
		}
	}
	
	if (!ctx->escaped_dirname && ctx->dirname) {
		ctx->escaped_dirname = string_escape(ctx->dirname);
	}
	
	return (placeholder_t){
		.value = ctx->escaped_dirname ? ctx->escaped_dirname : "",
		.allocated = false,
		.pre_formatted = true
	};
}

/* Watch path placeholder */
static placeholder_t resolve_watch_path(binder_t *ctx) {
	if (!ctx->escaped_watch_path) {
		ctx->escaped_watch_path = string_escape(ctx->watch->path);
	}
	return (placeholder_t){
		.value = ctx->escaped_watch_path ? ctx->escaped_watch_path : "",
		.allocated = false,
		.pre_formatted = true
	};
}

/* Watch name placeholder */
static placeholder_t resolve_watch_name(binder_t *ctx) {
	if (!ctx->escaped_watch_name && ctx->watch->name) {
		ctx->escaped_watch_name = string_escape(ctx->watch->name);
	}
	return (placeholder_t){
		.value = ctx->escaped_watch_name ? ctx->escaped_watch_name : "",
		.allocated = false,
		.pre_formatted = true
	};
}

/* Relative path placeholder */
static placeholder_t resolve_relative_path(binder_t *ctx) {
	if (!ctx->relative_path) {
		const char *rel_path = ctx->event->path + strlen(ctx->watch->path);
		if (*rel_path == '/') {
			rel_path++;
		}
		ctx->relative_path = strdup(rel_path);
	}
	
	if (!ctx->escaped_relative_path && ctx->relative_path) {
		ctx->escaped_relative_path = string_escape(ctx->relative_path);
	}
	
	return (placeholder_t){
		.value = ctx->escaped_relative_path ? ctx->escaped_relative_path : "",
		.allocated = false,
		.pre_formatted = true
	};
}

/* Time placeholder */
static placeholder_t resolve_time(binder_t *ctx) {
	if (!ctx->time_string) {
		ctx->time_string = malloc(64);
		if (ctx->time_string) {
			struct tm tm;
			localtime_r(&ctx->event->wall_time.tv_sec, &tm);
			strftime(ctx->time_string, 64, "%Y-%m-%d %H:%M:%S", &tm);
		}
	}
	return (placeholder_t){
		.value = ctx->time_string ? ctx->time_string : "",
		.allocated = false,
		.pre_formatted = true
	};
}

/* User placeholder */
static placeholder_t resolve_user(binder_t *ctx) {
	if (!ctx->user_string) {
		ctx->user_string = malloc(128);
		if (ctx->user_string) {
			struct passwd pwd;
			struct passwd *result;
			char pw_buf[1024];
			int ret = getpwuid_r(ctx->event->user_id, &pwd, pw_buf, sizeof(pw_buf), &result);
			if (ret == 0 && result != NULL) {
				snprintf(ctx->user_string, 128, "%s", pwd.pw_name);
			} else {
				snprintf(ctx->user_string, 128, "%d", ctx->event->user_id);
			}
		}
	}
	return (placeholder_t){
		.value = ctx->user_string ? ctx->user_string : "",
		.allocated = false,
		.pre_formatted = true
	};
}

/* Event type placeholder */
static placeholder_t resolve_event_type(binder_t *ctx) {
	if (!ctx->event_string) {
		const char *event_str = filter_to_string(ctx->event->type);
		ctx->event_string = strdup(event_str);
	}
	return (placeholder_t){
		.value = ctx->event_string ? ctx->event_string : "",
		.allocated = false,
		.pre_formatted = true
	};
}

/* File size placeholder */
static placeholder_t resolve_size(binder_t *ctx) {
	if (!ctx->size_calculated) {
		subscription_t *subscription = NULL;
		if (watchref_valid(ctx->watchref)) {
			subscription = resources_subscription(ctx->monitor->resources, ctx->monitor->registry,
												  ctx->event->path, ctx->watchref, ENTITY_UNKNOWN);
		}
		
		if (subscription && subscription->resource->kind == ENTITY_DIRECTORY) {
			subscription_t *size_subscription = stability_root(ctx->monitor, subscription);
			if (size_subscription) {
				resource_lock(size_subscription->resource);
				if (size_subscription->profile && size_subscription->profile->stability) {
					ctx->file_size = size_subscription->profile->stability->stats.tree_size;
				}
				resource_unlock(size_subscription->resource);
			}
		} else {
			struct stat info;
			if (stat(ctx->event->path, &info) == 0) {
				ctx->file_size = info.st_size;
			}
		}
		ctx->size_calculated = true;
	}
	
	if (!ctx->size_string) {
		ctx->size_string = malloc(32);
		if (ctx->size_string) {
			snprintf(ctx->size_string, 32, "%zu", ctx->file_size);
		}
	}
	
	return (placeholder_t){
		.value = ctx->size_string ? ctx->size_string : "0",
		.allocated = false,
		.pre_formatted = true
	};
}

/* Human-readable size placeholder */
static placeholder_t resolve_human_size(binder_t *ctx) {
	if (!ctx->size_calculated) {
		/* Trigger size calculation */
		resolve_size(ctx);
	}
	
	if (!ctx->human_size_string) {
		const char *human_size = format_size((ssize_t)ctx->file_size, false);
		ctx->human_size_string = strdup(human_size);
	}
	
	return (placeholder_t){
		.value = ctx->human_size_string ? ctx->human_size_string : "0 B",
		.allocated = false,
		.pre_formatted = true
	};
}

/* Diff-based placeholder resolution using unified diff_list() function */
static placeholder_t resolve_diff(binder_t *ctx, const char *type, bool basename_only) {
	if (ctx->watch->target != WATCH_DIRECTORY || !ctx->event->diff) {
		return (placeholder_t){.value = "", .allocated = false, .pre_formatted = true};
	}
	
	/* Use unified diff_list() function for efficiency */
	char *result = diff_list(ctx->event->diff, basename_only, type);
	if (result && result[0] != '\0') {
		return (placeholder_t){
			.value = result,
			.allocated = true,       /* diff_list() returns allocated memory */
			.pre_formatted = false   /* Raw list that needs escaping */
		};
	}
	
	/* Free empty result */
	free(result);
	return (placeholder_t){.value = "", .allocated = false, .pre_formatted = true};
}

/* Exclusion patterns placeholder */
static placeholder_t resolve_exclusion(binder_t *ctx) {
	if (!ctx->watch->exclude || ctx->watch->num_exclude == 0) {
		return (placeholder_t){.value = "", .allocated = false, .pre_formatted = true};
	}
	
	char *result = format_array((const char *const *)ctx->watch->exclude, ctx->watch->num_exclude, "'%s'", ",");
	return (placeholder_t){
		.value = result ? result : "",
		.allocated = result != NULL,  /* format_array() returns allocated memory */
		.pre_formatted = true        /* Pre-formatted, no additional escaping needed */
	};
}

/* Array placeholder resolver using unified diff_list() for efficiency */
static placeholder_t resolve_array(binder_t *ctx, const char *array_spec) {
	char *spec_copy = strdup(array_spec);
	if (!spec_copy) {
		return (placeholder_t){.value = "", .allocated = false, .pre_formatted = true};
	}
	
	char *colon = strchr(spec_copy, ':');
	if (!colon) {
		free(spec_copy);
		return (placeholder_t){.value = "", .allocated = false, .pre_formatted = true};
	}
	
	*colon = '\0';
	const char *array_name = spec_copy;
	const char *template = colon + 1;
	
	char *result = NULL;
	
	/* Handle exclusion patterns */
	if (strcmp(array_name, "excluded") == 0) {
		if (ctx->watch->exclude && ctx->watch->num_exclude > 0) {
			result = format_array((const char *const *)ctx->watch->exclude, ctx->watch->num_exclude, template, " ");
		}
	} else if (ctx->watch->target == WATCH_DIRECTORY && ctx->event->diff) {
		/* Handle diff-based arrays using unified diff_list() */
		bool basename_only = true; /* Default to basenames */
		char *base_name = strdup(array_name);

		if (base_name) {
			/* Check for _path suffix to get full paths */
			char *path_suffix = strstr(base_name, "_path");
			if (path_suffix) {
				*path_suffix = '\0';
				basename_only = false;
			}

			/* Get list using unified diff_list() function */
			char *list_str = diff_list(ctx->event->diff, basename_only, base_name);
			if (list_str && list_str[0] != '\0') {
				/* Convert newline-separated list to a formatted string based on the template */
				builder_t builder;
				if (builder_init(&builder, strlen(list_str) * 2)) {
					char *list_copy = strdup(list_str);
					if (list_copy) {
						char *token = strtok(list_copy, "\n");
						while (token) {
							char *formatted_item = string_substitute(template, "%s", token);
							if (formatted_item) {
								builder_append(&builder, "%s", formatted_item);
								free(formatted_item);
							}
							token = strtok(NULL, "\n");
						}
						free(list_copy);
					}
					result = builder_string(&builder);
				}
			}
			free(list_str);
			free(base_name);
		}
	}
	
	free(spec_copy);
	return (placeholder_t){
		.value = result ? result : "",
		.allocated = result != NULL,  /* format_array() returns allocated memory */
		.pre_formatted = true        /* Pre-formatted, no additional escaping needed */
	};
}

/* Substitutes placeholders in the command string:
 * %created: List of created items (newline-separated)
 * %deleted: List of deleted items (newline-separated)
 * %renamed: List of renamed items (format: old -> new, newline-separated)
 * %modified: List of modified files (newline-separated)
 * %p: Path where the event occurred
 * %n: Filename (for files) or subdirectory name (for directories) which triggered the event
 * %d: Directory containing the path that triggered the event
 * %b: Base path of the watch from the config
 * %w: Name of the watch from the config
 * %r: Event path relative to the watch path
 * %l: List of items (basenames) changed
 * %L: List of items changed (newline-separated)
 * %h: Size of the file in bytes (recursive for directories)
 * %H: Human-readable size (e.g., 1.2M, 512K)
 * %t: Time of the event (format: YYYY-MM-DD HH:MM:SS)
 * %u: User who triggered the event
 * %e: Event type which occurred
 * %x: Comma-separated list of exclusion patterns for this watch
 * %[array:template]: Advanced template substitution where 'array' can be:
 *   - created, created_path: created items (basenames by default, or full paths with _path)
 *   - deleted, deleted_path: deleted items (basenames by default, or full paths with _path)
 *   - renamed, renamed_path: renamed items (basenames by default, or full paths with _path)
 *   - modified, modified_path: modified items (basenames by default, or full paths with _path)
 *   - excluded: exclusion patterns from configuration
 *   Template is applied to each item in the array (e.g., %[created_path:'%s'] wraps each created file path in quotes)
 */
char *binder_placeholders(binder_t *ctx, const char *template) {
	if (!ctx || !template) {
		log_message(ERROR, "Invalid arguments to binder_placeholders");
		return NULL;
	}
	
	builder_t builder;
	if (!builder_init(&builder, strlen(template) * 2)) {
		log_message(ERROR, "Failed to initialize string builder");
		return NULL;
	}
	
	const char *current = template;
	while (*current) {
		if (*current == '%') {
			const char *placeholder_start = current;
			current++;
			
			/* Handle array placeholders like %[excluded:--exclude=%s] */
			if (*current == '[') {
				const char *array_start = current + 1;
				const char *array_end = strchr(array_start, ']');
				if (array_end) {
					size_t array_len = array_end - array_start;
					char *array_spec = malloc(array_len + 1);
					if (array_spec) {
						strncpy(array_spec, array_start, array_len);
						array_spec[array_len] = '\0';
						
						placeholder_t result = resolve_array(ctx, array_spec);
						if (result.value && result.value[0] != '\0') {
							builder_append(&builder, "%s", result.value);
						}
						if (result.allocated) {
							free(result.value);
						}
						free(array_spec);
					}
					current = array_end + 1;
					continue;
				}
			}
			
			/* Handle regular single-character placeholders */
			if (*current) {
				placeholder_t result = {.value = NULL};
				switch (*current) {
					case 'p': result = resolve_path(ctx); break;
					case 'n': result = resolve_basename(ctx); break;
					case 'd': result = resolve_dirname(ctx); break;
					case 'b': result = resolve_watch_path(ctx); break;
					case 'w': result = resolve_watch_name(ctx); break;
					case 'r': result = resolve_relative_path(ctx); break;
					case 't': result = resolve_time(ctx); break;
					case 'u': result = resolve_user(ctx); break;
					case 'e': result = resolve_event_type(ctx); break;
					case 'h': result = resolve_size(ctx); break;
					case 'H': result = resolve_human_size(ctx); break;
					case 'x': result = resolve_exclusion(ctx); break;
					case 'l': result = resolve_diff(ctx, "changed", true); break;
					case 'L': result = resolve_diff(ctx, "changed", false); break;
					default: {
						const char* diff_type = NULL;
						size_t len = 0;
					
						if (strncmp(current, "created", 7) == 0) {
							len = 7;
							diff_type = "created";
						} else if (strncmp(current, "deleted", 7) == 0) {
							len = 7;
							diff_type = "deleted";
						} else if (strncmp(current, "renamed", 7) == 0) {
							len = 7;
							diff_type = "renamed";
						} else if (strncmp(current, "modified", 8) == 0) {
							len = 8;
							diff_type = "modified";
						}
					
						/* Ensure we matched a whole word placeholder */
						if (diff_type && isalnum(current[len])) {
							diff_type = NULL;
						}
					
						if (diff_type) {
							result = resolve_diff(ctx, diff_type, true);
							current += len - 1; /* Will be incremented again at end */
						} else {
							/* Unknown placeholder - copy as literal */
							builder_append(&builder, "%c%c", placeholder_start[0], *current);
							current++;
							continue;
						}
						break;
					}
				}
				
				/* Handle the result based on its metadata */
				if (result.value && result.value[0] != '\0') {
					if (result.pre_formatted) {
						/* Pre-formatted value, use as-is */
						builder_append(&builder, "%s", result.value);
					} else {
						/* Raw value that needs escaping */
						char *escaped = string_escape_list(result.value);
						if (escaped) {
							builder_append(&builder, "%s", escaped);
							free(escaped);
						}
					}
				}
				
				/* Clean up allocated result */
				if (result.allocated && result.value) {
					free(result.value);
				}
				current++;
			} else {
				/* Trailing % at end of string */
				builder_append(&builder, "%%");
			}
		} else {
			/* Regular character - append as is */
			builder_append(&builder, "%c", *current);
			current++;
		}
	}
	
	return builder_string(&builder);
}

/* Set environment variables for command execution */
void binder_environment(binder_t *ctx) {
	if (!ctx) {
		log_message(WARNING, "Invalid context in binder_environment");
		return;
	}
	
	char buffer[1024];
	
	/* Helper macros to reduce repetitive environment variable setting */
	#define SET_ENV(key, value) \
		if (value) { setenv(key, value, 1); }
	
	#define SET_ENV_ESCAPED(key, value) \
		if (value) { \
			char *escaped = string_escape(value); \
			if (escaped) { \
				setenv(key, escaped, 1); \
				free(escaped); \
			} \
		}
	
	#define SET_ENV_LIST(key, list_value) \
		if (list_value) { \
			char *escaped_list = string_escape_list(list_value); \
			if (escaped_list) { \
				setenv(key, escaped_list, 1); \
				free(escaped_list); \
			} \
		}
	
	#define SET_ENV_DIFF_LIST(key, diff_func) \
		{ char *list = diff_func(ctx->event->diff, true); \
		  SET_ENV_LIST(key, list); \
		  if (list) free(list); }
	
	/* KQ_EVENT_TYPE */
	SET_ENV("KQ_EVENT_TYPE", filter_to_string(ctx->event->type));
	
	/* KQ_TRIGGER_PATH */
	SET_ENV_ESCAPED("KQ_TRIGGER_PATH", ctx->event->path);
	
	/* KQ_WATCH_NAME */
	SET_ENV_ESCAPED("KQ_WATCH_NAME", ctx->watch->name);
	
	/* KQ_WATCH_PATH */
	SET_ENV_ESCAPED("KQ_WATCH_PATH", ctx->watch->path);
	
	/* KQ_RELATIVE_PATH */
	if (ctx->event->path && ctx->watch->path && strlen(ctx->event->path) > strlen(ctx->watch->path)) {
		const char *relative_path = ctx->event->path + strlen(ctx->watch->path);
		if (*relative_path == '/') {
			relative_path++;
		}
		char *escaped_rel_path = string_escape(relative_path);
		if (escaped_rel_path) {
			setenv("KQ_RELATIVE_PATH", escaped_rel_path, 1);
			free(escaped_rel_path);
		}
	}
	
	/* KQ_TRIGGER_DIR */
	if (ctx->event->path) {
		char *path_copy = strdup(ctx->event->path);
		if (path_copy) {
			char *dir_result = dirname(path_copy);
			if (dir_result) {
				char *escaped_dir = string_escape(dir_result);
				if (escaped_dir) {
					setenv("KQ_TRIGGER_DIR", escaped_dir, 1);
					free(escaped_dir);
				}
			}
			free(path_copy);
		}
	}
	
	/* KQ_USER_ID */
	snprintf(buffer, sizeof(buffer), "%d", ctx->event->user_id);
	SET_ENV("KQ_USER_ID", buffer);
	
	/* KQ_USERNAME */
	struct passwd pwd;
	struct passwd *result;
	char pw_buf[1024];
	int ret = getpwuid_r(ctx->event->user_id, &pwd, pw_buf, sizeof(pw_buf), &result);
	if (ret == 0 && result != NULL) {
		SET_ENV_ESCAPED("KQ_USERNAME", pwd.pw_name);
	} else {
		snprintf(buffer, sizeof(buffer), "%d", ctx->event->user_id);
		SET_ENV("KQ_USERNAME", buffer);
	}
	
	/* KQ_TIMESTAMP */
	struct tm tm;
	if (localtime_r(&ctx->event->wall_time.tv_sec, &tm)) {
		strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", &tm);
		SET_ENV("KQ_TIMESTAMP", buffer);
	}
	
	/* Directory watch diff-based environment variables */
	if (ctx->watch->target == WATCH_DIRECTORY && ctx->event->diff) {
		SET_ENV_DIFF_LIST("KQ_CHANGED", diff_changed);
		SET_ENV_DIFF_LIST("KQ_CREATED", diff_created);
		SET_ENV_DIFF_LIST("KQ_DELETED", diff_deleted);
		SET_ENV_DIFF_LIST("KQ_RENAMED", diff_renamed);
		SET_ENV_DIFF_LIST("KQ_MODIFIED", diff_modified);
	}
	
	/* Global variables from config */
	const config_t *config = ctx->monitor->config;
	if (config && config->num_variables > 0) {
		for (int i = 0; i < config->num_variables; i++) {
			const char *prefix = "KQ_VAR_";
			const char *key = config->variables[i].key;
			const char *value = config->variables[i].value;
			
			size_t env_name_len = strlen(prefix) + strlen(key);
			char *env_name = malloc(env_name_len + 1);
			
			if (env_name) {
				snprintf(env_name, env_name_len + 1, "%s%s", prefix, key);
				setenv(env_name, value, 1);
				free(env_name);
			} else {
				log_message(WARNING, "Failed to allocate memory for environment variable: %s%s", prefix, key);
			}
		}
		log_message(DEBUG, "Set %d global variables as environment variables", config->num_variables);
	}
	
	/* KQ_EXCLUDE */
	char *escaped_exclusions = (ctx->watch->exclude && ctx->watch->num_exclude > 0) ?
								   format_array((const char *const *)ctx->watch->exclude, ctx->watch->num_exclude, "'%s'", ",") :
								   strdup("");
	SET_ENV("KQ_EXCLUDE", escaped_exclusions);
	if (escaped_exclusions) {
		free(escaped_exclusions);
	}
	
	/* Clean up helper macros */
	#undef SET_ENV
	#undef SET_ENV_ESCAPED
	#undef SET_ENV_LIST
	#undef SET_ENV_DIFF_LIST
}
