#include "protocol.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "control.h"
#include "logger.h"
#include "monitor.h"
#include "registry.h"

/* Initialize a new string builder */
static bool builder_init(builder_t *b, size_t initial_capacity) {
	if (!b) return false;
	b->data = malloc(initial_capacity);
	if (!b->data) {
		log_message(ERROR, "Failed to allocate memory");
		return false;
	}

	b->data[0] = '\0';
	b->capacity = initial_capacity;
	b->length = 0;
	return true;
}

/* Free the memory used by a string builder */
static void builder_free(builder_t *b) {
	if (b) {
		free(b->data);
		b->data = NULL;
		b->capacity = 0;
		b->length = 0;
	}
}

/* Ensure the builder has enough capacity for additional data */
static bool builder_capacity(builder_t *b, size_t additional_needed) {
	if (!b) return false;
	if (b->length + additional_needed < b->capacity) {
		return true; /* Enough space */
	}

	size_t new_capacity = b->capacity;
	while (b->length + additional_needed >= new_capacity) {
		new_capacity = (new_capacity == 0) ? 128 : new_capacity * 2;
	}

	char *new_data = realloc(b->data, new_capacity);
	if (!new_data) {
		log_message(ERROR, "Failed to reallocate memory");
		return false;
	}

	b->data = new_data;
	b->capacity = new_capacity;
	return true;
}

/* Append a formatted string to the builder */
static bool builder_append(builder_t *b, const char *format, ...) {
	if (!b || !format) return false;

	va_list args1, args2;
	va_start(args1, format);
	va_copy(args2, args1);

	/* Determine required size */
	int required_size = vsnprintf(NULL, 0, format, args1);
	va_end(args1);

	if (required_size < 0) {
		log_message(ERROR, "vsnprintf encoding error");
		va_end(args2);
		return false;
	}

	/* Ensure capacity (including null terminator) */
	if (!builder_capacity(b, required_size + 1)) {
		va_end(args2);
		return false;
	}

	/* Append the formatted string */
	int written = vsnprintf(b->data + b->length, b->capacity - b->length, format, args2);
	va_end(args2);

	if (written > 0) {
		b->length += written;
	}

	return true;
}

/* Finalize the string and transfer ownership to the caller */
static char *builder_string(builder_t *b) {
	if (!b) return NULL;
	char *result = b->data;
	b->data = NULL;
	b->capacity = 0;
	b->length = 0;
	return result;
}

/* Initialize a new dynamic string array */
static array_t *array_init(int initial_capacity) {
	array_t *a = calloc(1, sizeof(array_t));
	if (!a) {
		log_message(ERROR, "Failed to allocate memory for array struct");
		return NULL;
	}

	a->capacity = (initial_capacity > 0) ? initial_capacity : 4;
	a->items = malloc(a->capacity * sizeof(char *));
	if (!a->items) {
		log_message(ERROR, "Failed to allocate memory for items");
		free(a);
		return NULL;
	}

	return a;
}

/* Add a string to the dynamic array */
static bool array_add(array_t *a, char *item) {
	if (!a || !item) return false;

	if (a->count >= a->capacity) {
		int new_capacity = a->capacity * 2;
		char **new_items = realloc(a->items, new_capacity * sizeof(char *));
		if (!new_items) {
			log_message(ERROR, "Failed to reallocate memory for items");
			return false;
		}
		a->items = new_items;
		a->capacity = new_capacity;
	}

	a->items[a->count++] = item;
	return true;
}

/* Free a dynamic array and all the strings it contains */
static void array_free(array_t *a) {
	if (!a) return;
	for (int i = 0; i < a->count; i++) {
		free(a->items[i]);
	}
	free(a->items);
	free(a);
}

/* Check if a string item exists in a dynamic array */
static bool array_has(array_t *a, const char *item) {
	if (!a || !item) return false;
	for (int i = 0; i < a->count; i++) {
		if (strcmp(a->items[i], item) == 0) {
			return true;
		}
	}
	return false;
}

/* Parse key=value pairs line by line, returning allocated value string */
char *kv_value(const char *text, const char *key) {
	if (!text || !key) return NULL;

	const char *line_start = text;
	size_t key_len = strlen(key);

	/* Parse each line looking for exact key match */
	while (*line_start) {
		/* Find end of current line */
		const char *line_end = strchr(line_start, '\n');
		if (!line_end) {
			line_end = line_start + strlen(line_start);
		}

		/* Skip empty lines */
		if (line_end > line_start) {
			/* Find '=' separator in this line */
			const char *equals = memchr(line_start, '=', line_end - line_start);
			if (equals) {
				/* Check if key matches exactly */
				size_t line_key_len = equals - line_start;
				if (line_key_len == key_len && memcmp(line_start, key, key_len) == 0) {
					/* Found matching key - extract value */
					size_t value_len = line_end - equals - 1;
					if (value_len > 0) {
						char *value = malloc(value_len + 1);
						if (value) {
							memcpy(value, equals + 1, value_len);
							value[value_len] = '\0';
						}
						return value;
					} else {
						/* Empty value */
						return strdup("");
					}
				}
			}
		}

		/* Move to next line */
		if (*line_end == '\n') {
			line_start = line_end + 1;
		} else {
			break; /* End of text */
		}
	}

	return NULL;
}

/* Split a string by a delimiter into a dynamic array */
array_t *kv_split(const char *value, const char *delimiter) {
	if (!value || !delimiter) return NULL;

	array_t *result = array_init(4);
	if (!result) return NULL;

	char *value_copy = strdup(value);
	if (!value_copy) {
		array_free(result);
		return NULL;
	}

	char *token;
	char *rest = value_copy;
	while ((token = strtok_r(rest, delimiter, &rest))) {
		/* Trim whitespace from the beginning */
		while (*token == ' ' || *token == '\t') {
			token++;
		}

		/* Trim whitespace from the end */
		char *end = token + strlen(token) - 1;
		while (end > token && (*end == ' ' || *end == '\t')) {
			*end-- = '\0';
		}

		/* Duplicate token and check for allocation failure */
		char *duplicated_token = strdup(token);
		if (!duplicated_token) {
			log_message(ERROR, "Failed to duplicate token");
			array_free(result);
			free(value_copy);
			return NULL;
		}

		/* Add to array and handle failure properly */
		if (!array_add(result, duplicated_token)) {
			log_message(ERROR, "Failed to add token to array");
			free(duplicated_token); /* Free the just-allocated token */
			array_free(result);
			free(value_copy);
			return NULL;
		}
	}

	free(value_copy);
	return result;
}

/* Initialize protocol result structure */
static void protocol_init(protocol_t *result) {
	memset(result, 0, sizeof(protocol_t));
}

/* Clean up protocol result structure */
void protocol_cleanup(protocol_t *result) {
	if (!result) return;

	free(result->message);

	for (int i = 0; i < result->data_count; i++) {
		free(result->data_keys[i]);
		free(result->data_values[i]);
	}
	free(result->data_keys);
	free(result->data_values);

	memset(result, 0, sizeof(protocol_t));
}

/* Add a key-value pair to the protocol result data */
static bool protocol_data(protocol_t *result, const char *key, const char *value) {
	if (!result || !key || !value) return false;

	/* Expand arrays if needed using amortized doubling strategy */
	if (result->data_count >= result->data_capacity) {
		int new_capacity = (result->data_capacity == 0) ? 4 : result->data_capacity * 2;

		/* Reallocate keys array */
		char **new_keys = realloc(result->data_keys, new_capacity * sizeof(char *));
		if (!new_keys) {
			log_message(ERROR, "Failed to expand data keys array");
			return false;
		}
		result->data_keys = new_keys;

		/* Reallocate values array */
		char **new_values = realloc(result->data_values, new_capacity * sizeof(char *));
		if (!new_values) {
			log_message(ERROR, "Failed to expand data values array");
			return false;
		}
		result->data_values = new_values;

		result->data_capacity = new_capacity;
	}

	/* Add the key-value pair */
	result->data_keys[result->data_count] = strdup(key);
	result->data_values[result->data_count] = strdup(value);

	if (!result->data_keys[result->data_count] || !result->data_values[result->data_count]) {
		log_message(ERROR, "Failed to duplicate key or value");
		free(result->data_keys[result->data_count]);
		free(result->data_values[result->data_count]);
		return false;
	}

	result->data_count++;
	return true;
}

/* Parse comma-separated watch names and attempt to disable each */
static protocol_t protocol_disable(monitor_t *monitor, const char *command_text) {
	protocol_t result;
	protocol_init(&result);

	/* Extract comma-separated list of watch names */
	char *watches_value = kv_value(command_text, "watches");
	if (!watches_value) {
		result.success = false;
		result.message = strdup("Missing 'watches' parameter for disable command");
		return result;
	}

	array_t *watch_names = kv_split(watches_value, ",");
	free(watches_value); /* No longer needed */

	if (!watch_names) {
		result.success = false;
		result.message = strdup("Failed to parse 'watches' parameter");
		return result;
	}

	/* Track successful disables and errors */
	array_t *disabled_names = array_init(watch_names->count);
	array_t *error_watches = array_init(watch_names->count);
	array_t *error_messages = array_init(watch_names->count);

	/* Process each watch name */
	for (int i = 0; i < watch_names->count; i++) {
		watchref_t watchref = registry_find(monitor->registry, watch_names->items[i]);

		if (!watchref_valid(watchref)) {
			array_add(error_watches, strdup(watch_names->items[i]));
			array_add(error_messages, strdup("not found"));
			continue;
		}

		/* Check current state before attempting to disable */
		watch_t *watch = registry_get(monitor->registry, watchref);
		bool was_enabled = (watch && watch->enabled);

		if (!was_enabled) {
			array_add(error_watches, strdup(watch_names->items[i]));
			array_add(error_messages, strdup("already disabled"));
		} else if (monitor_disable(monitor, watchref)) {
			array_add(disabled_names, strdup(watch_names->items[i]));
		} else {
			array_add(error_watches, strdup(watch_names->items[i]));
			array_add(error_messages, strdup("disable failed"));
		}
	}

	array_free(watch_names);

	/* Build structured response */
	result.success = (error_watches->count == 0);

	char disabled_counter[16];
	snprintf(disabled_counter, sizeof(disabled_counter), "%d", disabled_names->count);
	protocol_data(&result, "disabled_count", disabled_counter);

	if (disabled_names->count > 0) {
		builder_t disabled_list;
		builder_init(&disabled_list, 256);
		for (int i = 0; i < disabled_names->count; i++) {
			if (i > 0) builder_append(&disabled_list, ", ");
			builder_append(&disabled_list, "%s", disabled_names->items[i]);
		}
		protocol_data(&result, "disabled_names", disabled_list.data);
		builder_free(&disabled_list);
	}

	char error_count_str[16];
	snprintf(error_count_str, sizeof(error_count_str), "%d", error_watches->count);
	protocol_data(&result, "error_count", error_count_str);

	if (error_watches->count > 0) {
		for (int i = 0; i < error_watches->count; i++) {
			char error_key[64];
			snprintf(error_key, sizeof(error_key), "error_%d_watch", i);
			protocol_data(&result, error_key, error_watches->items[i]);

			snprintf(error_key, sizeof(error_key), "error_%d_message", i);
			protocol_data(&result, error_key, error_messages->items[i]);
		}
	}

	/* Add response type for structured data */
	protocol_data(&result, "response_type", "disable");

	array_free(disabled_names);
	array_free(error_watches);
	array_free(error_messages);

	return result;
}

/* Parse comma-separated watch names and attempt to enable each */
static protocol_t protocol_enable(monitor_t *monitor, const char *command_text) {
	protocol_t result;
	protocol_init(&result);

	/* Extract comma-separated list of watch names */
	char *watches_value = kv_value(command_text, "watches");
	if (!watches_value) {
		result.success = false;
		result.message = strdup("Missing 'watches' parameter for enable command");
		return result;
	}

	array_t *watch_names = kv_split(watches_value, ",");
	free(watches_value); /* No longer needed */

	if (!watch_names) {
		result.success = false;
		result.message = strdup("Failed to parse 'watches' parameter");
		return result;
	}

	/* Track successful enables and errors */
	array_t *enabled_names = array_init(watch_names->count);
	array_t *error_watches = array_init(watch_names->count);
	array_t *error_messages = array_init(watch_names->count);

	for (int i = 0; i < watch_names->count; i++) {
		/* Find the watch by name regardless of state */
		watchref_t watchref = registry_find(monitor->registry, watch_names->items[i]);

		if (!watchref_valid(watchref)) {
			array_add(error_watches, strdup(watch_names->items[i]));
			array_add(error_messages, strdup("not found"));
			continue;
		}

		/* Check current state before attempting to activate */
		watch_t *watch = registry_get(monitor->registry, watchref);
		bool was_enabled = (watch && watch->enabled);

		if (was_enabled) {
			array_add(error_watches, strdup(watch_names->items[i]));
			array_add(error_messages, strdup("already enabled"));
		} else if (monitor_activate(monitor, watchref)) {
			array_add(enabled_names, strdup(watch_names->items[i]));
		} else {
			array_add(error_watches, strdup(watch_names->items[i]));
			array_add(error_messages, strdup("enable failed"));
		}
	}
	array_free(watch_names);

	/* Build structured response */
	result.success = (error_watches->count == 0);

	char enabled_count_str[16];
	snprintf(enabled_count_str, sizeof(enabled_count_str), "%d", enabled_names->count);
	protocol_data(&result, "enabled_count", enabled_count_str);

	if (enabled_names->count > 0) {
		builder_t enabled_list;
		builder_init(&enabled_list, 256);
		for (int i = 0; i < enabled_names->count; i++) {
			if (i > 0) builder_append(&enabled_list, ", ");
			builder_append(&enabled_list, "%s", enabled_names->items[i]);
		}
		protocol_data(&result, "enabled_names", enabled_list.data);
		builder_free(&enabled_list);
	}

	char error_count_str[16];
	snprintf(error_count_str, sizeof(error_count_str), "%d", error_watches->count);
	protocol_data(&result, "error_count", error_count_str);

	if (error_watches->count > 0) {
		for (int i = 0; i < error_watches->count; i++) {
			char error_key[64];
			snprintf(error_key, sizeof(error_key), "error_%d_watch", i);
			protocol_data(&result, error_key, error_watches->items[i]);

			snprintf(error_key, sizeof(error_key), "error_%d_message", i);
			protocol_data(&result, error_key, error_messages->items[i]);
		}
	}

	/* Add response type for structured data */
	protocol_data(&result, "response_type", "enable");

	array_free(enabled_names);
	array_free(error_watches);
	array_free(error_messages);

	return result;
}

/* Report enhanced status with multi-line message format */
static protocol_t protocol_status(monitor_t *monitor, const char *command_text) {
	protocol_t result;
	protocol_init(&result);

	(void) command_text; /* Unused parameter */

	/* Get all registered watches and categorize them */
	uint32_t num_watches = 0;
	watchref_t *watchrefs = registry_active(monitor->registry, &num_watches);

	array_t *active_names = array_init(8);
	array_t *disabled_names = array_init(8);
	array_t *pending_names = array_init(4);
	int pending_count = monitor->num_pending;

	/* Categorize watches by their state, excluding internal watches */
	for (uint32_t i = 0; i < num_watches; i++) {
		watch_t *watch = registry_get(monitor->registry, watchrefs[i]);
		if (!watch || !watch->name) {
			continue;
		}

		/* Skip all internal watches (those starting with "__") */
		if (strncmp(watch->name, "__", 2) == 0) {
			continue;
		}

		/* Check if this watch corresponds to a pending item */
		bool is_pending = false;
		for (int j = 0; j < pending_count; j++) {
			pending_t *pending = monitor->pending[j];
			if (pending && pending->watchref.watch_id == watchrefs[i].watch_id &&
				pending->watchref.generation == watchrefs[i].generation) {
				is_pending = true;
				break;
			}
		}

		/* Only count non-pending watches in active/disabled */
		if (!is_pending) {
			array_t *target_array = watch->enabled ? active_names : disabled_names;
			if (!array_has(target_array, watch->name)) {
				array_add(target_array, strdup(watch->name));
			}
		}
	}

	/* Collect source patterns of all dynamic watches that have been created */
	array_t *resolved_patterns = array_init(8);
	for (uint32_t i = 0; i < num_watches; i++) {
		watch_t *watch = registry_get(monitor->registry, watchrefs[i]);
		if (watch && watch->is_dynamic && watch->source_pattern) {
			if (!array_has(resolved_patterns, watch->source_pattern)) {
				array_add(resolved_patterns, strdup(watch->source_pattern));
			}
		}
	}

	/* Collect truly pending paths (not resolved ones) */
	for (int i = 0; i < pending_count; i++) {
		pending_t *pending = monitor->pending[i];
		if (pending && pending->target_path) {
			if (pending->is_glob) {
				/* For globs, consider it pending only if no dynamic watches have been created from it yet */
				if (pending->glob_pattern && !array_has(resolved_patterns, pending->glob_pattern)) {
					if (!array_has(pending_names, pending->target_path)) {
						array_add(pending_names, strdup(pending->target_path));
					}
				}
			} else {
				/* For exact paths, its presence in the pending list means it doesn't exist yet */
				if (!array_has(pending_names, pending->target_path)) {
					array_add(pending_names, strdup(pending->target_path));
				}
			}
		}
	}
	array_free(resolved_patterns);

	result.success = true;

	/* Provide structured data */
	char active_counter[16], disabled_counter[16], pending_counter[16];
	snprintf(active_counter, sizeof(active_counter), "%d", active_names->count);
	snprintf(disabled_counter, sizeof(disabled_counter), "%d", disabled_names->count);
	snprintf(pending_counter, sizeof(pending_counter), "%d", pending_names->count);

	protocol_data(&result, "active_count", active_counter);
	protocol_data(&result, "disabled_count", disabled_counter);
	protocol_data(&result, "pending_count", pending_counter);

	/* Build comma-separated lists for names and paths */
	if (active_names->count > 0) {
		builder_t active_list;
		builder_init(&active_list, 256);
		for (int i = 0; i < active_names->count; i++) {
			if (i > 0) builder_append(&active_list, ", ");
			builder_append(&active_list, "%s", active_names->items[i]);
		}
		protocol_data(&result, "active_names", active_list.data);
		builder_free(&active_list);
	}

	if (disabled_names->count > 0) {
		builder_t disabled_list;
		builder_init(&disabled_list, 256);
		for (int i = 0; i < disabled_names->count; i++) {
			if (i > 0) builder_append(&disabled_list, ", ");
			builder_append(&disabled_list, "%s", disabled_names->items[i]);
		}
		protocol_data(&result, "disabled_names", disabled_list.data);
		builder_free(&disabled_list);
	}

	if (pending_names->count > 0) {
		builder_t pending_list;
		builder_init(&pending_list, 256);
		for (int i = 0; i < pending_names->count; i++) {
			if (i > 0) builder_append(&pending_list, ", ");
			builder_append(&pending_list, "%s", pending_names->items[i]);
		}
		protocol_data(&result, "pending_paths", pending_list.data);
		builder_free(&pending_list);
	}

	/* Add response type for explicit protocol handling */
	protocol_data(&result, "response_type", "status");
	free(watchrefs);
	array_free(active_names);
	array_free(disabled_names);
	array_free(pending_names);

	return result;
}

/* Process list command */
static protocol_t protocol_list(monitor_t *monitor, const char *command_text) {
	protocol_t result;
	protocol_init(&result);

	(void) command_text; /* Unused parameter */

	registry_t *registry = monitor->registry;
	if (!registry) {
		result.success = false;
		result.message = strdup("Invalid registry");
		return result;
	}

	uint32_t num_watches = 0;
	watchref_t *watchrefs = registry_active(monitor->registry, &num_watches);
	array_t *processed_names = array_init(16);
	int watch_index = 0;

	/* Collect unique watches and add structured data for each */
	for (uint32_t i = 0; i < num_watches; i++) {
		watch_t *watch = registry_get(monitor->registry, watchrefs[i]);
		/* Skip internal watches and invalid entries */
		if (!watch || !watch->name || strncmp(watch->name, "__", 2) == 0) {
			continue;
		}

		/* Avoid duplicate entries for same watch name */
		if (array_has(processed_names, watch->name)) {
			continue;
		}
		array_add(processed_names, strdup(watch->name));

		/* Extract watch information */
		const char *status = watch->enabled ? "Active" : "Disabled";
		const char *events_str = filter_to_string(watch->filter);
		const char *path = watch->path ? watch->path : "N/A";

		/* Add structured data for this watch using formatted keys */
		char key_name[32], key_path[32], key_events[32], key_status[32];
		snprintf(key_name, sizeof(key_name), "watch_%d_name", watch_index);
		snprintf(key_path, sizeof(key_path), "watch_%d_path", watch_index);
		snprintf(key_events, sizeof(key_events), "watch_%d_events", watch_index);
		snprintf(key_status, sizeof(key_status), "watch_%d_status", watch_index);

		protocol_data(&result, key_name, watch->name);
		protocol_data(&result, key_path, path);
		protocol_data(&result, key_events, events_str);
		protocol_data(&result, key_status, status);

		watch_index++;
	}

	/* Add watch count for easy client parsing */
	char watch_count_str[16];
	snprintf(watch_count_str, sizeof(watch_count_str), "%d", watch_index);
	protocol_data(&result, "watch_count", watch_count_str);

	/* Add response type for explicit protocol handling */
	protocol_data(&result, "response_type", "list");

	/* Free resources */
	free(watchrefs);
	array_free(processed_names);

	result.success = true;

	return result;
}

/* Process reload command */
static protocol_t protocol_reload(monitor_t *monitor, const char *command_text) {
	protocol_t result;
	protocol_init(&result);

	(void) command_text; /* Unused parameter */

	/* Try to acquire reload mutex (non-blocking) to check if reload is already in progress */
	if (pthread_mutex_trylock(&monitor->reload_mutex) != 0) {
		result.success = false;
		protocol_data(&result, "error", "Reload already in progress");
		protocol_data(&result, "response_type", "reload");
		return result;
	}

	/* Release the mutex immediately since monitor_reload will acquire it */
	pthread_mutex_unlock(&monitor->reload_mutex);

	/* Trigger reload by setting flag */
	monitor->reload = true;

	result.success = true;

	/* Add structured data for reload operation */
	protocol_data(&result, "reload_requested", "true");
	protocol_data(&result, "response_type", "reload");

	return result;
}

/* Parse incoming KV protocol text and route to appropriate handler */
protocol_t protocol_process(monitor_t *monitor, const char *command_text) {
	protocol_t result;
	protocol_init(&result);

	if (!monitor || !command_text) {
		result.success = false;
		result.message = strdup("Invalid monitor or command");
		return result;
	}

	/* Extract command type from protocol text */
	char *command = kv_value(command_text, "command");
	if (!command) {
		result.success = false;
		result.message = strdup("Missing 'command' parameter");
		return result;
	}

	/* Route to appropriate command handler */
	if (strcmp(command, "disable") == 0) {
		result = protocol_disable(monitor, command_text);
	} else if (strcmp(command, "enable") == 0) {
		result = protocol_enable(monitor, command_text);
	} else if (strcmp(command, "status") == 0) {
		result = protocol_status(monitor, command_text);
	} else if (strcmp(command, "list") == 0) {
		result = protocol_list(monitor, command_text);
	} else if (strcmp(command, "reload") == 0) {
		result = protocol_reload(monitor, command_text);
	} else {
		result.success = false;
		size_t msg_len = strlen("Unknown command: ") + strlen(command) + 1;
		result.message = malloc(msg_len);
		if (result.message) {
			snprintf(result.message, msg_len, "Unknown command: %s", command);
		}
		protocol_data(&result, "response_type", "error");
	}

	free(command);
	return result;
}

/* Convert protocol_t structure to key=value formatted text */
char *protocol_format(const protocol_t *result) {
	if (!result) return NULL;

	builder_t b;
	if (!builder_init(&b, 1024)) {
		return NULL;
	}

	/* Always include status line first */
	builder_append(&b, "status=%s\n", result->success ? "success" : "error");

	/* Include structured data fields */
	for (int i = 0; i < result->data_count; i++) {
		builder_append(&b, "%s=%s\n", result->data_keys[i], result->data_values[i]);
	}

	/* Include message only for protocol-level errors */
	if (!result->success && result->message) {
		builder_append(&b, "message=%s", result->message);
		/* Ensure message ends with a newline */
		if (b.length > 0 && b.data[b.length - 1] != '\n') {
			builder_append(&b, "\n");
		}
	}

	builder_append(&b, "\n");

	return builder_string(&b);
}
