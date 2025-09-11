#include "binder.h"

#include <ctype.h>
#include <errno.h>
#include <libgen.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

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
	return (placeholder_t) {
		.value = ctx->escaped_path ? ctx->escaped_path : "",
		.allocated = false,	  /* Don't free - it's cached in context */
		.pre_formatted = true /* Already escaped, use as-is */
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

	return (placeholder_t) {
		.value = ctx->escaped_basename ? ctx->escaped_basename : "",
		.allocated = false, /* Don't free - it's cached in context */
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

	return (placeholder_t) {
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
	return (placeholder_t) {
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
	return (placeholder_t) {
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

	return (placeholder_t) {
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
	return (placeholder_t) {
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
	return (placeholder_t) {
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
	return (placeholder_t) {
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

	return (placeholder_t) {
		.value = ctx->size_string ? ctx->size_string : "0",
		.allocated = false,
		.pre_formatted = true};
}

/* Human-readable size placeholder */
static placeholder_t resolve_human_size(binder_t *ctx) {
	if (!ctx->size_calculated) {
		/* Trigger size calculation */
		resolve_size(ctx);
	}

	if (!ctx->human_size_string) {
		const char *human_size = format_size((ssize_t) ctx->file_size, false);
		ctx->human_size_string = strdup(human_size);
	}

	return (placeholder_t) {
		.value = ctx->human_size_string ? ctx->human_size_string : "0 B",
		.allocated = false,
		.pre_formatted = true
	};
}

/* Exclusion patterns placeholder */
static placeholder_t resolve_exclusion(binder_t *ctx) {
	if (!ctx->watch->exclude || ctx->watch->num_exclude == 0) {
		return (placeholder_t) {.value = "", .allocated = false, .pre_formatted = true};
	}

	char *result = format_array((const char *const *) ctx->watch->exclude, ctx->watch->num_exclude, "'%s'", ",");
	return (placeholder_t) {
		.value = result ? result : "",
		.allocated = result != NULL, /* format_array() returns allocated memory */
		.pre_formatted = true		 /* Pre-formatted, no additional escaping needed */
	};
}

/* Array placeholder resolver using direct diff list access for efficiency */
static placeholder_t resolve_array(binder_t *ctx, const char *array_spec) {
	char *spec_copy = strdup(array_spec);
	if (!spec_copy) {
		return (placeholder_t) {.value = "", .allocated = false, .pre_formatted = true};
	}

	char *colon = strchr(spec_copy, ':');
	if (!colon) {
		free(spec_copy);
		return (placeholder_t) {.value = "", .allocated = false, .pre_formatted = true};
	}

	*colon = '\0';
	const char *array_name = spec_copy;
	const char *template = colon + 1;

	char *result = NULL;

	/* Handle exclusion patterns */
	if (strcmp(array_name, "excluded") == 0) {
		if (ctx->watch->exclude && ctx->watch->num_exclude > 0) {
			result = format_array((const char *const *) ctx->watch->exclude, ctx->watch->num_exclude, template, " ");
		}
	} else if (ctx->watch->target == WATCH_DIRECTORY && ctx->event->diff) {
		/* Handle diff-based arrays using direct array access */
		bool basename_only = true; /* Default to basenames */
		char *base_name = strdup(array_name);

		if (base_name) {
			/* Check for _path suffix to get full paths */
			char *path_suffix = strstr(base_name, "_path");
			if (path_suffix) {
				*path_suffix = '\0';
				basename_only = false;
			}

			/* Get list view using the new direct access function */
			diff_list_t list = diff_list(ctx->event->diff, base_name);
			if (list.count > 0) {
				/* Use the new efficient path array formatter */
				result = format_path_array(list.paths, list.count, template, " ", basename_only);
			}
			free(base_name);
		}
	}

	free(spec_copy);
	return (placeholder_t) {
		.value = result ? result : "",
		.allocated = result != NULL,
		.pre_formatted = true /* Pre-formatted, no additional escaping needed */
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
 *   - modified, modified_path: modified items (basenames by default, or full paths with _path)
 *   - renamed, renamed_path: renamed items (basenames by default, or full paths with _path)
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
	const char *next_placeholder;

	while ((next_placeholder = strchr(current, '%')) != NULL) {
		/* Append text before the placeholder */
		if (next_placeholder > current) {
			builder_append(&builder, "%.*s", (int) (next_placeholder - current), current);
		}

		const char *placeholder_start = next_placeholder + 1;
		const char *placeholder_end = placeholder_start;
		placeholder_t result = {.value = NULL};

		if (*placeholder_start == '%') { /* Escaped percent "%%" */
			builder_append(&builder, "%%");
			placeholder_end = placeholder_start + 1;

		/* Handle template array format placeholders %[array:template] */
		} else if (*placeholder_start == '[') {
			const char *array_end = strchr(placeholder_start, ']');
			if (array_end) {
				size_t array_len = array_end - placeholder_start - 1;
				char *array_spec = malloc(array_len + 1);
				if (array_spec) {
					strncpy(array_spec, placeholder_start + 1, array_len);
					array_spec[array_len] = '\0';
					result = resolve_array(ctx, array_spec);
					free(array_spec);
				}

				placeholder_end = array_end + 1;
			}

		/* Handle regular single-character placeholders */
		} else if (isalpha(*placeholder_start)) {
			const char *name_end = placeholder_start;
			while (isalpha(*name_end)) name_end++;
			size_t name_len = name_end - placeholder_start;
			char name_buffer[32];

			if (name_len > 0 && name_len < sizeof(name_buffer)) {
				strncpy(name_buffer, placeholder_start, name_len);
				name_buffer[name_len] = '\0';
				placeholder_end = name_end;

				if (strcmp(name_buffer, "p") == 0)
					result = resolve_path(ctx);
				else if (strcmp(name_buffer, "n") == 0)
					result = resolve_basename(ctx);
				else if (strcmp(name_buffer, "d") == 0)
					result = resolve_dirname(ctx);
				else if (strcmp(name_buffer, "b") == 0)
					result = resolve_watch_path(ctx);
				else if (strcmp(name_buffer, "w") == 0)
					result = resolve_watch_name(ctx);
				else if (strcmp(name_buffer, "r") == 0)
					result = resolve_relative_path(ctx);
				else if (strcmp(name_buffer, "t") == 0)
					result = resolve_time(ctx);
				else if (strcmp(name_buffer, "u") == 0)
					result = resolve_user(ctx);
				else if (strcmp(name_buffer, "e") == 0)
					result = resolve_event_type(ctx);
				else if (strcmp(name_buffer, "h") == 0)
					result = resolve_size(ctx);
				else if (strcmp(name_buffer, "H") == 0)
					result = resolve_human_size(ctx);
				else if (strcmp(name_buffer, "x") == 0)
					result = resolve_exclusion(ctx);
				else if (strcmp(name_buffer, "l") == 0 || strcmp(name_buffer, "L") == 0) {
					bool basename_only = (strcmp(name_buffer, "l") == 0);
					if (ctx->watch->target == WATCH_DIRECTORY && ctx->event->diff) {
						builder_t list_builder;
						builder_init(&list_builder, 1024);
						const char *types[] = {"created", "deleted", "modified", "renamed"};
						for (int i = 0; i < 4; i++) {
							diff_list_t list = diff_list(ctx->event->diff, types[i]);
							if (list.count > 0) {
								bool use_basename = basename_only && (strcmp(types[i], "renamed") != 0);
								char *value = format_escaped_path_array(list.paths, list.count, "\n", use_basename);
								if (value && *value) {
									if (list_builder.length > 0) {
										builder_append(&list_builder, "\n");
									}
									builder_append(&list_builder, "%s", value);
								}
								free(value);
							}
						}
						char *final_value = builder_string(&list_builder);
						result = (placeholder_t) {
							.value = final_value ? final_value : "",
							.allocated = true,
							.pre_formatted = true};
					}
				} else if (strcmp(name_buffer, "created") == 0 ||
						   strcmp(name_buffer, "deleted") == 0 ||
						   strcmp(name_buffer, "renamed") == 0 ||
						   strcmp(name_buffer, "modified") == 0) {
					if (ctx->watch->target == WATCH_DIRECTORY && ctx->event->diff) {
						diff_list_t list = diff_list(ctx->event->diff, name_buffer);
						if (list.count > 0) {
							char *value = format_escaped_path_array(list.paths, list.count, "\n", true);
							result = (placeholder_t) {
								.value = value,
								.allocated = true,
								.pre_formatted = true
							};
						}
					}
				}
			}
		}

		/* Handle the result from the resolver */
		if (result.value) {
			// All resolvers now return pre-formatted or pre-escaped values.
			if (result.pre_formatted) {
				builder_append(&builder, "%s", result.value);
			} else {
				// This path is for raw values that need simple escaping.
				char *escaped = string_escape(result.value);
				if (escaped) {
					builder_append(&builder, "%s", escaped);
					free(escaped);
				}
			}
			if (result.allocated) {
				free(result.value);
			}
		} else {
			/* Unknown or malformed placeholder, append literally */
			builder_append(&builder, "%.*s", (int) (placeholder_end - next_placeholder), next_placeholder);
		}
		current = placeholder_end;
	}

	/* Append any remaining text after the last placeholder */
	if (*current) {
		builder_append(&builder, "%s", current);
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

	/* Helper macro for setting env vars - ensures value is not NULL or empty */
	#define SET_ENV(key, value) do { if (value && *value) { setenv(key, value, 1); } } while (0)

	/* Ensure all values are populated by calling resolvers */
	resolve_event_type(ctx);	/* Caches event type */
	resolve_path(ctx);			/* Caches escaped_path, but we'll use raw event->path */
	resolve_basename(ctx);		/* Caches basename */
	resolve_dirname(ctx);		/* Caches dirname */
	resolve_relative_path(ctx); /* Caches relative_path */
	resolve_user(ctx);			/* Caches user_string */
	resolve_time(ctx);			/* Caches time_string */

	/* Set simple environment variables with raw data */
	SET_ENV("KQ_EVENT_TYPE", ctx->event_string);
	SET_ENV("KQ_TRIGGER_PATH", ctx->event->path);		 // Use raw path from event
	SET_ENV("KQ_WATCH_NAME", (char *) ctx->watch->name); // Use raw name from watch
	SET_ENV("KQ_WATCH_PATH", (char *) ctx->watch->path); // Use raw path from watch
	SET_ENV("KQ_RELATIVE_PATH", ctx->relative_path);
	SET_ENV("KQ_TRIGGER_DIR", ctx->dirname);
	SET_ENV("KQ_USERNAME", ctx->user_string);
	SET_ENV("KQ_TIMESTAMP", ctx->time_string);

	snprintf(buffer, sizeof(buffer), "%d", ctx->event->user_id);
	SET_ENV("KQ_USER_ID", buffer);

	/* Handle list-based variables */
	if (ctx->watch->target == WATCH_DIRECTORY && ctx->event->diff) {
		const char *types[] = {"created", "deleted", "renamed", "modified"};
		builder_t changed_builder;
		bool builder_inited = builder_init(&changed_builder, 1024);

		for (int i = 0; i < 4; i++) {
			diff_list_t list = diff_list(ctx->event->diff, types[i]);
			if (list.count > 0) {
				bool basename_only = (strcmp(types[i], "renamed") != 0);
				char *value = format_path_array(list.paths, list.count, "%s", " ", basename_only);

				if (value) {
					if (strcmp(types[i], "created") == 0) {
						SET_ENV("KQ_CREATED", value);
					} else if (strcmp(types[i], "deleted") == 0) {
						SET_ENV("KQ_DELETED", value);
					} else if (strcmp(types[i], "renamed") == 0) {
						SET_ENV("KQ_RENAMED", value);
					} else if (strcmp(types[i], "modified") == 0) {
						SET_ENV("KQ_MODIFIED", value);
					}

					if (builder_inited && *value) {
						if (changed_builder.length > 0) {
							builder_append(&changed_builder, " ");
						}
						builder_append(&changed_builder, "%s", value);
					}
					free(value);
				}
			}
		}

		if (builder_inited) {
			char *changed_value = builder_string(&changed_builder);
			if (changed_value && *changed_value) {
				SET_ENV("KQ_CHANGED", changed_value);
			}
			free(changed_value);
		}
	}

	/* KQ_EXCLUDE environment variable */
	if (ctx->watch->exclude && ctx->watch->num_exclude > 0) {
		char *exclusions = format_array((const char *const *) ctx->watch->exclude, ctx->watch->num_exclude, "'%s'", ",");
		if (exclusions) {
			SET_ENV("KQ_EXCLUDE", exclusions);
			free(exclusions);
		}
	}

	/* Global KQ_VAR_* variables from config */
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
				SET_ENV(env_name, value);
				free(env_name);
			}
		}
	}

	#undef SET_ENV
}
