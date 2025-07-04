#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>

#include "monitor.h"
#include "daemon.h"
#include "logger.h"

/* Global monitor reference for signal handler */
static monitor_t *g_monitor = NULL;

/* Signal handling state */
static volatile sig_atomic_t running = 1;
static volatile sig_atomic_t reload_requested = 0;

/* Signal handler */
static void signal_handler(int sig) {
	switch (sig) {
		case SIGINT:
		case SIGTERM:
			running = 0;
			/* Stop the monitor if available */
			if (g_monitor != NULL) {
				log_message(LOG_LEVEL_INFO, "Received signal %d, stopping monitor", sig);
				monitor_stop(g_monitor);
			} else {
				log_message(LOG_LEVEL_WARNING, "Received signal %d but monitor is not available", sig);
			}
			break;
		case SIGHUP:
			reload_requested = 1;
			/* Request reload if monitor is available */
			if (g_monitor != NULL) {
				log_message(LOG_LEVEL_INFO, "Received SIGHUP, requesting configuration reload");
				monitor_request_reload(g_monitor);
			} else {
				log_message(LOG_LEVEL_WARNING, "Received SIGHUP but monitor is not available");
			}
			break;
		default:
			break;
	}
}

/* Check if the daemon is still running */
bool daemon_is_running(void) {
	return running != 0;
}

/* Check if reload is requested */
bool daemon_reload_requested(void) {
	if (reload_requested) {
		reload_requested = 0;
		return true;
	}
	return false;
}

/* Set up signal handlers */
bool daemon_setup_signals(void) {
	struct sigaction sa;
	
	/* Set up signal handlers */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		log_message(LOG_LEVEL_ERR, "Failed to set up SIGINT handler: %s", strerror(errno));
		return false;
	}
	if (sigaction(SIGTERM, &sa, NULL) == -1) {
		log_message(LOG_LEVEL_ERR, "Failed to set up SIGTERM handler: %s", strerror(errno));
		return false;
	}
	if (sigaction(SIGHUP, &sa, NULL) == -1) {
		log_message(LOG_LEVEL_ERR, "Failed to set up SIGHUP handler: %s", strerror(errno));
		return false;
	}
	
	/* Ignore SIGPIPE */
	signal(SIGPIPE, SIG_IGN);
	
	return true;
}

/* Set monitor reference for signal handler */
void daemon_set_monitor(monitor_t *monitor) {
	g_monitor = monitor;
	if (monitor != NULL) {
		log_message(LOG_LEVEL_DEBUG, "Daemon: monitor reference updated");
	} else {
		log_message(LOG_LEVEL_DEBUG, "Daemon: monitor reference cleared");
	}
}

/* Start daemon */
bool daemon_start(config_t *config) {
	pid_t pid, sid;
	
	if (config == NULL) {
		log_message(LOG_LEVEL_ERR, "Invalid configuration for daemon");
		return false;
	}
	
	/* Fork the parent process */
	pid = fork();
	if (pid < 0) {
		log_message(LOG_LEVEL_ERR, "Failed to fork: %s", strerror(errno));
		return false;
	}
	
	/* Exit the parent process */
	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}
	
	/* Create a new session ID for the child process */
	sid = setsid();
	if (sid < 0) {
		log_message(LOG_LEVEL_ERR, "Failed to create new session: %s", strerror(errno));
		return false;
	}
	
	/* Change the current working directory to root */
	if (chdir("/") < 0) {
		log_message(LOG_LEVEL_ERR, "Failed to change directory: %s", strerror(errno));
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
	
	log_message(LOG_LEVEL_INFO, "Started daemon with PID %d", getpid());
	
	return true;
}
