#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>
#include "logger.h"

/* Global log level */
static loglevel_t current_log_level = NOTICE;

/* Flag indicating whether syslog is initialized */
static int syslog_initialized = 0;

/* Flag indicating whether to use console output */
static int console_output = 0;

/* Mutex for thread-safe logging */
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Initialize logging */
void log_init(const char *ident, int facility, loglevel_t level, int use_console) {
	current_log_level = level;
	console_output = use_console;

	/* Open syslog connection */
	openlog(ident, LOG_PID, facility);
	syslog_initialized = 1;
}

/* Close logging */
void log_close(void) {
	if (syslog_initialized) {
		closelog();
		syslog_initialized = 0;
	}
}

/* Log a message */
void log_message(loglevel_t level, const char *format, ...) {
	va_list args;

	/* Check if we should log this message */
	if (level > current_log_level) {
		return;
	}

	/* Lock for thread-safe logging */
	pthread_mutex_lock(&log_mutex);

	va_start(args, format);

	/* Always log to syslog if initialized */
	if (syslog_initialized) {
		va_list syslog_args;
		va_copy(syslog_args, args);
		vsyslog(level, format, syslog_args);
		va_end(syslog_args);
	}

	/* Also log to console if requested */
	if (console_output || !syslog_initialized) {
		char timestamp[32];
		time_t current_time;
		struct tm tm_now;

		/* Get current time */
		time(&current_time);
		localtime_r(&current_time, &tm_now);
		strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_now);

		/* Print to stderr */
		fprintf(stderr, "[%s] ", timestamp);

		/* Print log level */
		switch (level) {
			case EMERG:
				fprintf(stderr, "[EMERG] ");
				break;
			case ALERT:
				fprintf(stderr, "[ALERT] ");
				break;
			case CRITICAL:
				fprintf(stderr, "[CRIT] ");
				break;
			case ERROR:
				fprintf(stderr, "[ERROR] ");
				break;
			case WARNING:
				fprintf(stderr, "[WARNING] ");
				break;
			case NOTICE:
				fprintf(stderr, "[NOTICE] ");
				break;
			case INFO:
				fprintf(stderr, "[INFO] ");
				break;
			case DEBUG:
				fprintf(stderr, "[DEBUG] ");
				break;
			default:
				fprintf(stderr, "[UNKNOWN] ");
				break;
		}

		/* Print message */
		vfprintf(stderr, format, args);
		fprintf(stderr, "\n");
	}

	va_end(args);

	/* Unlock after logging */
	pthread_mutex_unlock(&log_mutex);
}

/* Format size in bytes to a human-readable string */
const char *format_size(ssize_t size, bool show_sign) {
    static char buf[32];
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
        d_size = (double)(-size);
    } else {
        d_size = (double)size;
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
