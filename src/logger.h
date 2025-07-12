#ifndef LOG_H
#define LOG_H

#include <syslog.h>
#include <sys/select.h>

/* Log levels (matching syslog levels) */
typedef enum {
	EMERG = LOG_EMERG,       /* System is unusable */
	ALERT = LOG_ALERT,       /* Action must be taken immediately */
	CRITICAL = LOG_CRIT,     /* Critical conditions */
	ERROR = LOG_ERR,         /* Error conditions */
	WARNING = LOG_WARNING,   /* Warning conditions */
	NOTICE = LOG_NOTICE,     /* Normal but significant condition */
	INFO = LOG_INFO,         /* Informational */
	DEBUG = LOG_DEBUG        /* Debug-level messages */
} log_level_t;

/* Function prototypes */
void log_init(const char *ident, int facility, log_level_t level, int use_console);
void log_close(void);
void log_message(log_level_t level, const char *format, ...);

#endif /* LOG_H */
