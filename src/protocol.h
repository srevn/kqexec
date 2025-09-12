#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdbool.h>

#include "control.h"
#include "utilities.h"

/* Protocol result for key-value protocol responses */
typedef struct protocol {
	/* Status information */
	bool success;                          /* Command success status */
	char *message;                         /* Result message */

	/* Data payload */
	int data_count;                        /* Number of key-value pairs in response */
	int data_capacity;                     /* Allocated capacity for data arrays */
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
