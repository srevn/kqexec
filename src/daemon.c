#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include "daemon.h"
#include "log.h"

/* Global flag for signal handling */
static volatile sig_atomic_t running = 1;

/* Signal handler */
static void signal_handler(int sig) {
	switch (sig) {
		case SIGINT:
		case SIGTERM:
			running = 0;
			break;
		default:
			break;
	}
}

/* Set up signal handlers */
void daemon_setup_signals(void) {
	struct sigaction sa;
	
	/* Set up signal handlers */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);
	
	/* Ignore SIGPIPE */
	signal(SIGPIPE, SIG_IGN);
}

/* Check if the daemon is still running */
bool daemon_is_running(void) {
	return running != 0;
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
	
	/* Set up signal handlers */
	daemon_setup_signals();
	
	log_message(LOG_LEVEL_NOTICE, "Started daemon with PID %d", getpid());
	
	return true;
}
