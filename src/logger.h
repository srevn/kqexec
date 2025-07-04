#ifndef LOG_H
#define LOG_H

#include <stdarg.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/select.h>

/* Log levels (matching syslog levels) */
typedef enum {
	LOG_LEVEL_EMERG = LOG_EMERG,     /* System is unusable */
	LOG_LEVEL_ALERT = LOG_ALERT,     /* Action must be taken immediately */
	LOG_LEVEL_CRIT = LOG_CRIT,       /* Critical conditions */
	LOG_LEVEL_ERR = LOG_ERR,         /* Error conditions */
	LOG_LEVEL_WARNING = LOG_WARNING, /* Warning conditions */
	LOG_LEVEL_NOTICE = LOG_NOTICE,   /* Normal but significant condition */
	LOG_LEVEL_INFO = LOG_INFO,       /* Informational */
	LOG_LEVEL_DEBUG = LOG_DEBUG      /* Debug-level messages */
} log_level_t;

/* Function prototypes */
void log_init(const char *ident, int facility, log_level_t level, int use_console);
void log_close(void);
void log_message(log_level_t level, const char *format, ...);

#endif /* LOG_H */
