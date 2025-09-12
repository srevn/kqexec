#ifndef UTILITIES_H
#define UTILITIES_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <time.h>

/* Dynamic array for managing lists of strings */
typedef struct array {
	char **items;                          /* Array of string pointers */
	int count;                             /* Number of items currently in the array */
	int capacity;                          /* Allocated capacity of the items array */
} array_t;

/* Dynamic string builder for string concatenation */
typedef struct builder {
	char *data;                            /* The character buffer */
	size_t capacity;                       /* The allocated capacity of the buffer */
	size_t length;                         /* The current length of the string in the buffer*/
} builder_t;

/* String builder utilities */
bool builder_init(builder_t *b, size_t initial_capacity);
void builder_free(builder_t *b);
bool builder_append(builder_t *b, const char *format, ...);
char *builder_string(builder_t *b);

/* Dynamic array utilities */
array_t *array_init(int initial_capacity);
void array_free(array_t *a);
bool array_add(array_t *a, char *item);
bool array_has(array_t *a, const char *item);

/* Timespec utilities functions */
void timespec_add(struct timespec *ts, int milliseconds);
bool timespec_after(const struct timespec *a, const struct timespec *b);
bool timespec_before(const struct timespec *a, const struct timespec *b);
long timespec_diff(const struct timespec *a, const struct timespec *b);

/* Complexity-based scaling functions */
double complexity_batch(double complexity);
double complexity_responsiveness(double complexity);
double complexity_backoff(double complexity);
double complexity_stability(double complexity);
double complexity_sensitivity(double complexity, int change_level);
double complexity_temporary(double complexity);

/* Shell escape utilities */
char *escape_string(const char *str);
char *escape_array(const char *const *paths, int count, const char *separator, bool basename_only);

/* Formatting utilities */
const char *format_size(ssize_t size, bool show_sign);
char *format_array(const char *const *strings, int count, const char *template, const char *separator, bool basename_only);

/* String utilities */
char *string_substitute(const char *input, const char *placeholder, const char *value);

#endif /* UTILITIES_H */
