#ifndef LOGGER_H
#define LOGGER_H

#include <syslog.h>
#include <string.h>
#include <sys/select.h>

/* Log levels (matching syslog levels) */
typedef enum loglevel {
	EMERG = LOG_EMERG,                     /* System is unusable */
	ALERT = LOG_ALERT,                     /* Action must be taken immediately */
	CRITICAL = LOG_CRIT,                   /* Critical conditions */
	ERROR = LOG_ERR,                       /* Error conditions */
	WARNING = LOG_WARNING,                 /* Warning conditions */
	NOTICE = LOG_NOTICE,                   /* Normal but significant condition */
	INFO = LOG_INFO,                       /* Informational */
	DEBUG = LOG_DEBUG                      /* Debug-level messages */
} loglevel_t;

/* Function prototypes */
void log_init(const char *ident, int facility, loglevel_t level, int use_console);
void log_close(void);
void log_message(loglevel_t level, const char *format, ...);
const char *format_size(ssize_t size, bool show_sign);

#endif /* LOGGER_H */
