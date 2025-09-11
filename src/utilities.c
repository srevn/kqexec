#include "utilities.h"

#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "logger.h"

/* Initialize a new string builder */
bool builder_init(builder_t *b, size_t initial_capacity) {
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
void builder_free(builder_t *b) {
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
bool builder_append(builder_t *b, const char *format, ...) {
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
char *builder_string(builder_t *b) {
	if (!b) return NULL;
	char *result = b->data;
	b->data = NULL;
	b->capacity = 0;
	b->length = 0;
	return result;
}

/* Initialize a new dynamic string array */
array_t *array_init(int initial_capacity) {
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
bool array_add(array_t *a, char *item) {
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
void array_free(array_t *a) {
	if (!a) return;
	for (int i = 0; i < a->count; i++) {
		free(a->items[i]);
	}
	free(a->items);
	free(a);
}

/* Check if a string item exists in a dynamic array */
bool array_has(array_t *a, const char *item) {
	if (!a || !item) return false;
	for (int i = 0; i < a->count; i++) {
		if (strcmp(a->items[i], item) == 0) {
			return true;
		}
	}
	return false;
}

/* Add milliseconds to a timespec */
void timespec_add(struct timespec *ts, int milliseconds) {
	ts->tv_sec += milliseconds / 1000;
	ts->tv_nsec += (milliseconds % 1000) * 1000000;

	/* Normalize nsec */
	if (ts->tv_nsec >= 1000000000) {
		ts->tv_sec++;
		ts->tv_nsec -= 1000000000;
	}
}

/* Check if timespec a is after timespec b */
bool timespec_after(const struct timespec *a, const struct timespec *b) {
	if (a->tv_sec > b->tv_sec) return true;
	if (a->tv_sec == b->tv_sec && a->tv_nsec > b->tv_nsec) return true;
	return false;
}

/* Check if timespec a is before timespec b */
bool timespec_before(const struct timespec *a, const struct timespec *b) {
	if (a->tv_sec < b->tv_sec) return true;
	if (a->tv_sec == b->tv_sec && a->tv_nsec < b->tv_nsec) return true;
	return false;
}

/* Calculate difference between two timespecs in milliseconds (a - b) */
long timespec_diff(const struct timespec *a, const struct timespec *b) {
	long sec_diff = a->tv_sec - b->tv_sec;
	long nsec_diff = a->tv_nsec - b->tv_nsec;
	return sec_diff * 1000 + nsec_diff / 1000000;
}

/* Calculate batch timeout threshold factor based on complexity (0.1-1.0 range)
 * Higher complexity = higher threshold (more patient with ongoing activity)
 * Baseline: complexity 1.0 = factor 0.5 */
double complexity_batch(double complexity) {
	if (complexity <= 0.0) complexity = 1.0;

	double factor;
	if (complexity <= 1.0) {
		/* For complexity <= 1.0, scale linearly from 0.1 to 0.5 (baseline) */
		factor = 0.1 + 0.4 * complexity;
	} else {
		/* For complexity > 1.0, use logarithmic scaling from 0.5 to 1.0 (max at 5.0) */
		factor = 0.5 + 0.5 * (log(complexity) / log(5.0));
	}

	/* Clamp to valid range */
	if (factor < 0.1) factor = 0.1;
	if (factor > 1.0) factor = 1.0;

	return factor;
}

/* Calculate responsiveness factor for complexity drops (0.1-1.0 range)
 * Higher complexity = higher factor = higher threshold = less willing to drop quiet periods
 * Baseline: complexity 1.0 = factor 0.75 */
double complexity_responsiveness(double complexity) {
	if (complexity <= 0.0) complexity = 1.0;

	double factor;
	if (complexity <= 1.0) {
		/* For complexity <= 1.0, scale linearly from 0.25 to 0.75 (baseline) */
		factor = 0.25 + 0.5 * complexity;
	} else {
		/* For complexity > 1.0, use logarithmic growth from 0.75 to 1.0 (max at 5.0) */
		factor = 0.75 + 0.25 * (log(complexity) / log(5.0));
	}

	/* Clamp to valid range */
	if (factor < 0.25) factor = 0.25;
	if (factor > 1.0) factor = 1.0;

	return factor;
}

/* Calculate backoff intensity multiplier based on complexity (1.0-2.5 range)
 * Higher complexity = more aggressive backoff
 * Baseline: complexity 1.0 = factor 1.25 */
double complexity_backoff(double complexity) {
	if (complexity <= 0.0) complexity = 1.0;

	double factor;
	if (complexity <= 1.0) {
		/* For complexity <= 1.0, scale linearly from 1.0 to 1.25 (baseline) */
		factor = 1.0 + 0.25 * complexity;
	} else {
		/* For complexity > 1.0, use logarithmic growth from 1.25 to 2.5 (max at 5.0) */
		factor = 1.25 + 1.25 * (log(complexity) / log(5.0));
	}

	/* Clamp to valid range */
	if (factor < 1.0) factor = 1.0;
	if (factor > 2.5) factor = 2.5;

	return factor;
}

/* Calculate stability factor for quiet period scaling (1.0-3.0 range)
 * Higher complexity = longer quiet periods */
double complexity_stability(double complexity) {
	if (complexity <= 0.0) complexity = 1.0;

	/* Use logarithmic growth for smooth scaling */
	double factor;
	if (complexity <= 1.0) {
		/* For complexity < 1.0, scale down from 1.0 */
		factor = complexity;
	} else {
		/* For complexity > 1.0, use logarithmic growth */
		factor = 1.0 + 1.4 * log(complexity);
	}

	/* Clamp to valid range */
	if (factor < 0.1) factor = 0.1; /* Allow very low complexity to go below 1.0 */
	if (factor > 3.0) factor = 3.0;

	return factor;
}

/* Calculate sensitivity factor based on complexity and change level
 * Higher complexity = higher factor = longer delays = less responsive
 * Baseline: complexity 1.0 = factor 1.0 (no change) */
double complexity_sensitivity(double complexity, int change_level) {
	if (complexity <= 0.0) complexity = 1.0;

	/* Base factor increases with complexity (higher complexity = less responsive) */
	double base_factor;
	if (complexity <= 1.0) {
		/* For complexity <= 1.0, scale linearly from 0.5 to 1.0 (baseline) */
		base_factor = 0.5 + 0.5 * complexity;
	} else {
		/* For complexity > 1.0, use logarithmic growth from 1.0 to 2.5 (max at 5.0) */
		base_factor = 1.0 + 1.5 * (log(complexity) / log(5.0));
	}

	/* Adjust based on change level:
	 * change_level 0: small changes - apply full complexity scaling
	 * change_level 1: medium changes - apply moderate complexity scaling
	 * change_level 2+: large changes - apply minimal complexity scaling */
	double factor;
	switch (change_level) {
		case 0: /* Small changes - full complexity effect */
			factor = base_factor;
			break;
		case 1: /* Medium changes - moderate complexity effect */
			factor = 0.7 + 0.3 * base_factor;
			break;
		default: /* Large changes - minimal complexity effect */
			factor = 0.8 + 0.2 * base_factor;
			break;
	}

	/* Clamp to reasonable range */
	if (factor < 0.5) factor = 0.5;
	if (factor > 2.5) factor = 2.5;

	return factor;
}

/* Calculate temporary file threshold based on complexity (0.2s-5.0s range)
 * Higher complexity = higher threshold = more patient with recent file changes
 * Baseline: complexity 1.0 = threshold 1.0s (current default) */
double complexity_temporary(double complexity) {
	if (complexity <= 0.0) complexity = 1.0;

	double threshold;
	if (complexity <= 1.0) {
		/* For complexity <= 1.0, scale linearly from 0.25s to 1.0s (baseline) */
		threshold = 0.2 + 0.75 * complexity;
	} else {
		/* For complexity > 1.0, use logarithmic growth from 1.0s to 5.0s */
		threshold = 1.0 + 4.0 * (log(complexity) / log(5.0));
	}

	/* Clamp to valid range */
	if (threshold < 0.2) threshold = 0.2;
	if (threshold > 5.0) threshold = 5.0;

	return threshold;
}

/* Shell-escape a single path by wrapping in single quotes */
char *string_escape(const char *str) {
	if (!str) return NULL;

	/* Calculate required buffer size */
	size_t len = strlen(str);
	size_t quotes = len + 8;
	for (const char *p = str; *p; p++) {
		/* Escape internal quotes 'x' becomes '\''x'\'' */
		if (*p == '\'') quotes += 4;
	}

	char *escaped = malloc(quotes);
	if (!escaped) return NULL;

	char *out = escaped;
	*out++ = '\''; /* Opening quote */

	for (const char *in = str; *in; in++) {
		if (*in == '\'') {
			/* Replace ' with '\'' */
			*out++ = '\'';
			*out++ = '\\';
			*out++ = '\'';
			*out++ = '\'';
		} else {
			*out++ = *in;
		}
	}

	*out++ = '\''; /* Closing quote */
	*out = '\0';

	return escaped;
}

/* Shell-escape a newline-separated list of paths */
char *format_escaped_path_array(const char *const *paths, int count, const char *separator, bool basename_only) {
    if (!paths || count == 0) {
        return strdup("");
    }

    builder_t builder;
    if (!builder_init(&builder, 4096)) {
        return NULL;
    }

    for (int i = 0; i < count; i++) {
        const char *path = paths[i];
        if (!path) continue;

        const char *path_to_use = path;
        if (basename_only) {
            const char *basename = strrchr(path, '/');
            if (basename) {
                path_to_use = basename + 1;
            }
        }

        char *escaped = string_escape(path_to_use);
        if (escaped) {
            if (i > 0 && separator) {
                builder_append(&builder, "%%s", separator);
            }
            builder_append(&builder, "%%s", escaped);
            free(escaped);
        }
    }

    return builder_string(&builder);
}

/* Helper function to substitute a placeholder in a string with dynamic allocation */
char *string_substitute(const char *input, const char *placeholder, const char *value) {
	if (!input || !placeholder || !value) return input ? strdup(input) : NULL;

	const char *current_pos = strstr(input, placeholder);
	if (!current_pos) {
		return strdup(input); /* No substitution needed */
	}

	size_t placeholder_len = strlen(placeholder);
	size_t value_len = strlen(value);
	size_t input_len = strlen(input);

	/* Calculate new length after all substitutions */
	size_t new_len = input_len;
	const char *search_pos = input;
	while ((search_pos = strstr(search_pos, placeholder)) != NULL) {
		new_len = new_len - placeholder_len + value_len;
		search_pos += placeholder_len;
	}

	/* Allocate result buffer */
	char *result = malloc(new_len + 1);
	if (!result) return NULL;

	/* Perform substitutions */
	const char *src = input;
	char *dst = result;

	while ((current_pos = strstr(src, placeholder)) != NULL) {
		/* Copy text before placeholder */
		size_t prefix_len = current_pos - src;
		memcpy(dst, src, prefix_len);
		dst += prefix_len;

		/* Copy replacement value */
		memcpy(dst, value, value_len);
		dst += value_len;

		/* Move past placeholder */
		src = current_pos + placeholder_len;
	}

	/* Copy remaining text */
	strcpy(dst, src);

	return result;
}

/* Format string array by applying a template to each item with optional separator */
char *format_array(const char *const *strings, int count, const char *template, const char *separator) {
	if (!strings || count == 0) return strdup("");

	/* Start with a reasonable buffer size */
	size_t result_capacity = 4096;
	char *result = malloc(result_capacity);
	if (!result) return NULL;

	result[0] = '\0';
	size_t result_len = 0;
	size_t separator_len = separator ? strlen(separator) : 0;
	int items_added = 0;

	for (int i = 0; i < count; i++) {
		if (!strings[i]) continue;

		/* Substitute the raw item into the template - template handles escaping */
		char *formatted_item = string_substitute(template, "%s", strings[i]);

		if (!formatted_item) {
			free(result);
			return NULL;
		}

		size_t formatted_len = strlen(formatted_item);
		/* +separator_len if not first, +1 for null terminator */
		size_t needed = result_len + (items_added > 0 ? separator_len : 0) + formatted_len + 1;

		/* Grow buffer if needed */
		if (needed > result_capacity) {
			size_t new_capacity = needed * 2;
			char *new_result = realloc(result, new_capacity);
			if (!new_result) {
				free(formatted_item);
				free(result);
				return NULL;
			}
			result = new_result;
			result_capacity = new_capacity;
		}

		/* Add separator if not first and separator is specified */
		if (items_added > 0 && separator) {
			memcpy(result + result_len, separator, separator_len);
			result_len += separator_len;
		}

		/* Copy formatted item */
		strcpy(result + result_len, formatted_item);
		result_len += formatted_len;

		free(formatted_item);
		items_added++;
	}

	return result;
}

/* Format a path array by applying a template to each item with an optional separator */
char *format_path_array(const char *const *paths, int count, const char *template, const char *separator, bool basename_only) {
    if (!paths || count == 0) {
        return strdup("");
    }

    builder_t builder;
    if (!builder_init(&builder, 4096)) {
        return NULL;
    }

    /* Efficiently pre-calculate prefix and suffix of the template */
    const char *ph = "%s";
    const char *template_start = strstr(template, ph);
    size_t template_ph_len = strlen(ph);

    char *prefix = NULL;
    size_t prefix_len = 0;
    const char *suffix = NULL;
    size_t suffix_len = 0;

    if (template_start) {
        prefix_len = template_start - template;
        if (prefix_len > 0) {
            prefix = malloc(prefix_len + 1);
            if (prefix) {
                strncpy(prefix, template, prefix_len);
                prefix[prefix_len] = '\0';
            }
        }
        suffix = template_start + template_ph_len;
        suffix_len = strlen(suffix);
    } else {
        /* If no placeholder, the template is static and repeated for each item */
        for (int i = 0; i < count; i++) {
            if (i > 0 && separator) {
                builder_append(&builder, "%s", separator);
            }
            builder_append(&builder, "%s", template);
        }
        char *result = builder_string(&builder);
        free(prefix);
        return result;
    }

    for (int i = 0; i < count; i++) {
        const char *path = paths[i];
        if (!path) continue;

        const char *path_to_use = path;
        if (basename_only) {
            const char *basename = strrchr(path, '/');
            if (basename) {
                path_to_use = basename + 1;
            }
        }

        if (i > 0 && separator) {
            builder_append(&builder, "%s", separator);
        }

        /* Append prefix, value, and suffix for efficiency */
        if (prefix_len > 0 && prefix) builder_append(&builder, "%s", prefix);
        builder_append(&builder, "%s", path_to_use);
        if (suffix_len > 0 && suffix) builder_append(&builder, "%s", suffix);
    }

    free(prefix);
    return builder_string(&builder);
}

/* Format size in bytes to a human-readable string */
const char *format_size(ssize_t size, bool show_sign) {
	static __thread char buf[32];
	const char *suffixes[] = {"B", "KB", "MB", "GB", "TB"};
	size_t i = 0;
	double d_size;
	bool negative = false;

	if (size == 0) {
		return "0 B";
	}

	/* Handle negative sizes for size deltas */
	if (size < 0) {
		negative = true;
		d_size = (double) (-size);
	} else {
		d_size = (double) size;
	}

	/* Determine the appropriate suffix */
	while (d_size >= 1024 && i < (sizeof(suffixes) / sizeof(suffixes[0])) - 1) {
		d_size /= 1024;
		i++;
	}

	/* Format the string with proper sign handling */
	if (show_sign && size > 0) {
		snprintf(buf, sizeof(buf), "+%.2f %s", d_size, suffixes[i]);
	} else {
		snprintf(buf, sizeof(buf), "%s%.2f %s", negative ? "-" : "", d_size, suffixes[i]);
	}
	return buf;
}
