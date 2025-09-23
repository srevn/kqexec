#include "daemon.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "logger.h"
#include "monitor.h"

static monitor_t *g_monitor = NULL;          /* Global monitor reference for signal handler */
static volatile sig_atomic_t running = 1;    /* Flag indicating daemon should continue running */
static volatile sig_atomic_t reload = 0;     /* Flag indicating configuration should be reloaded */

/* Signal handler */
static void signal_handler(int sig) {
	switch (sig) {
		case SIGINT:
		case SIGTERM:
			running = 0;
			/* Stop the monitor if available */
			if (g_monitor != NULL) {
				log_message(INFO, "Received signal %d, stopping monitor", sig);
				monitor_stop(g_monitor);
			} else {
				log_message(WARNING, "Received signal %d but monitor is not available", sig);
			}
			break;
		case SIGHUP:
			reload = 1;
			/* Request reload if monitor is available */
			if (g_monitor != NULL) {
				log_message(INFO, "Received SIGHUP, requesting configuration reload");
				g_monitor->reload = true;
				log_message(DEBUG, "Configuration reload requested");
			} else {
				log_message(WARNING, "Received SIGHUP but monitor is not available");
			}
			break;
		default:
			break;
	}
}

/* Set up signal handlers */
bool daemon_signals(void) {
	struct sigaction sa;

	/* Set up signal handlers */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;

	if (sigaction(SIGINT, &sa, NULL) == -1) {
		log_message(ERROR, "Failed to set up SIGINT handler: %s", strerror(errno));
		return false;
	}
	if (sigaction(SIGTERM, &sa, NULL) == -1) {
		log_message(ERROR, "Failed to set up SIGTERM handler: %s", strerror(errno));
		return false;
	}
	if (sigaction(SIGHUP, &sa, NULL) == -1) {
		log_message(ERROR, "Failed to set up SIGHUP handler: %s", strerror(errno));
		return false;
	}

	/* Ignore SIGPIPE */
	signal(SIGPIPE, SIG_IGN);

	return true;
}

/* Set monitor reference for signal handler */
void daemon_monitor(monitor_t *monitor) {
	g_monitor = monitor;
	if (monitor != NULL) {
		log_message(DEBUG, "Daemon: monitor reference updated");
	} else {
		log_message(DEBUG, "Daemon: monitor reference cleared");
	}
}

/* Start daemon */
bool daemon_start(config_t *config) {
	pid_t pid, sid;

	if (config == NULL) {
		log_message(ERROR, "Invalid configuration for daemon");
		return false;
	}

	/* Fork the parent process */
	pid = fork();
	if (pid < 0) {
		log_message(ERROR, "Failed to fork: %s", strerror(errno));
		return false;
	}

	/* Exit the parent process */
	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	/* Create a new session ID for the child process */
	sid = setsid();
	if (sid < 0) {
		log_message(ERROR, "Failed to create new session: %s", strerror(errno));
		return false;
	}

	/* Change the current working directory to root */
	if (chdir("/") < 0) {
		log_message(ERROR, "Failed to change directory: %s", strerror(errno));
		return false;
	}

	/* Close standard file descriptors */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	/* Open null device */
	int fd = open("/dev/null", O_RDWR);
	if (fd != -1) {
		/* Redirect standard file descriptors to /dev/null */
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);

		if (fd > STDERR_FILENO) {
			close(fd);
		}
	}

	/* Set file creation mask */
	umask(0);

	log_message(INFO, "Started daemon with PID %d", getpid());

	return true;
}
