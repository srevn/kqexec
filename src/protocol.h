#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdbool.h>
#include <stddef.h>

#include "control.h"

/* Dynamic array for managing lists of strings */
typedef struct array {
	char **items;                          /*Array of string pointers */
	int count;                             /*Number of items currently in the array */
	int capacity;                          /*Allocated capacity of the items array */
} array_t;

/* Dynamic string builder for efficient string concatenation */
typedef struct builder {
	char *data;                            /*The character buffer */
	size_t capacity;                       /*The allocated capacity of the buffer */
	size_t length;                         /*The current length of the string in the buffer*/
} builder_t;

/* Protocol result for key-value protocol responses */
typedef struct protocol {
	/* Status information */
	bool success;                          /* Command success status */
	char *message;                         /* Result message */
	
	/* Data payload */
	int data_count;                        /* Number of key-value pairs in response */
	char **data_keys;                      /* Array of response data keys */
	char **data_values;                    /* Array of corresponding data values */
} protocol_t;

/* Command processing */
protocol_t protocol_process(monitor_t *monitor, const char *command_text);
char *protocol_format(const protocol_t *result);
void protocol_cleanup(protocol_t *result);

/* KV protocol utilities */
char *kv_value(const char *text, const char *key);
array_t *kv_split(const char *value, const char *delimiter);

#endif /* PROTOCOL_H */
