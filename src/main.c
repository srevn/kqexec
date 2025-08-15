#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "command.h"
#include "config.h"
#include "daemon.h"
#include "logger.h"
#include "monitor.h"
#include "registry.h"
#include "threads.h"

/* Default configuration file */
#define DEFAULT_CONFIG_FILE "/usr/local/etc/kqexec.conf"

/* Program name */
static const char *program_name;

/* Print usage */
static void print_usage(void) {
	fprintf(stderr, "Usage: %s [options]\n", program_name);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -c, --config=FILE      Configuration file (default: %s)\n", DEFAULT_CONFIG_FILE);
	fprintf(stderr, "  -d, --daemon           Run as daemon\n");
	fprintf(stderr, "  -l, --loglevel=LEVEL   Set log level (0-7, default: 5)\n");
	fprintf(stderr, "  -b, --debounce=MS      Set command debounce time in milliseconds (default: 500)\n");
	fprintf(stderr, "  -h, --help             Print this help message\n");
}

/* Main function */
int main(int argc, char *argv[]) {
	config_t *config;
	monitor_t *monitor;
	threads_t *threads;
	int c;
	int daemon_mode = 0;
	int option_index = 0;
	int loglevel = NOTICE;
	const char *config_path = NULL;

	/* Get program name */
	program_name = strrchr(argv[0], '/');
	if (program_name == NULL) {
		program_name = argv[0];
	} else {
		program_name++;
	}

	/* Set up signal handlers */
	if (!daemon_signals()) {
		log_message(ERROR, "Failed to set up signal handlers");
		log_close();
		return EXIT_FAILURE;
	}

	/* Parse command line options */
	static struct option long_options[] = {
		{"config", required_argument, 0, 'c'},
		{"daemon", no_argument, 0, 'd'},
		{"loglevel", required_argument, 0, 'l'},
		{"debounce", required_argument, 0, 'b'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}};

	while ((c = getopt_long(argc, argv, "c:dl:b:h", long_options, &option_index)) != -1) {
		switch (c) {
			case 'c':
				config_path = optarg;
				break;
			case 'd':
				daemon_mode = 1;
				break;
			case 'l':
				loglevel = atoi(optarg);
				if (loglevel < 0 || loglevel > 7) {
					fprintf(stderr, "Invalid log level: %d (valid range: 0-7)\n", loglevel);
					return EXIT_FAILURE;
				}
				break;
			case 'b':
				command_debounce_time(atoi(optarg));
				break;
			case 'h':
				print_usage();
				return EXIT_SUCCESS;
			case '?':
				print_usage();
				return EXIT_FAILURE;
			default:
				abort();
		}
	}

	/* Use default config file if not specified */
	if (config_path == NULL) {
		config_path = DEFAULT_CONFIG_FILE;
	}

	/* Initialize logging */
	log_init(program_name, LOG_DAEMON, loglevel, !daemon_mode);

	/* Create watch registry */
	registry_t *registry = registry_create(0); /* Use default capacity */
	if (registry == NULL) {
		log_message(ERROR, "Failed to create watch registry");
		log_close();
		return EXIT_FAILURE;
	}

	/* Create configuration */
	config = config_create();
	if (config == NULL) {
		log_message(ERROR, "Failed to create configuration");
		registry_destroy(registry);
		log_close();
		return EXIT_FAILURE;
	}

	/* Set daemon mode */
	config->daemon_mode = daemon_mode;
	config->syslog_level = loglevel;

	/* Parse configuration file */
	if (!config_parse(config, registry, config_path)) {
		log_message(ERROR, "Failed to parse configuration file: %s", config_path);
		config_destroy(config);
		registry_destroy(registry);
		log_close();
		return EXIT_FAILURE;
	}

	/* Start daemon if requested */
	if (config->daemon_mode) {
		if (!daemon_start(config)) {
			log_message(ERROR, "Failed to start daemon");
			config_destroy(config);
			registry_destroy(registry);
			log_close();
			return EXIT_FAILURE;
		}

		/* Re-initialize logging without console output after daemonizing */
		log_close();
		log_init(program_name, LOG_DAEMON, loglevel, 0);
	}

	/* Create thread pool */
	threads = threads_create();
	if (threads == NULL) {
		log_message(ERROR, "Failed to create thread pool");
		config_destroy(config);
		registry_destroy(registry);
		log_close();
		return EXIT_FAILURE;
	}

	/* Initialize command subsystem */
	if (!command_init(threads)) {
		log_message(ERROR, "Failed to initialize command subsystem");
		threads_destroy(threads);
		config_destroy(config);
		registry_destroy(registry);
		log_close();
		return EXIT_FAILURE;
	}

	/* Create monitor */
	monitor = monitor_create(config, registry);
	if (monitor == NULL) {
		log_message(ERROR, "Failed to create monitor");
		command_cleanup(threads);
		threads_destroy(threads);
		config_destroy(config);
		registry_destroy(registry);
		log_close();
		return EXIT_FAILURE;
	}

	/* Set up monitor */
	if (!monitor_setup(monitor)) {
		log_message(ERROR, "Failed to set up monitor");
		monitor_destroy(monitor);
		command_cleanup(threads);
		threads_destroy(threads);
		log_close();
		return EXIT_FAILURE;
	}

	/* Set monitor reference for daemon signal handler */
	daemon_monitor(monitor);

	/* Start monitor */
	if (!monitor_start(monitor)) {
		log_message(ERROR, "Failed to start monitor");
		monitor_destroy(monitor);
		command_cleanup(threads);
		threads_destroy(threads);
		log_close();
		return EXIT_FAILURE;
	}

	/* Clean up */
	daemon_monitor(NULL);
	monitor_destroy(monitor);
	command_cleanup(threads);
	threads_destroy(threads);
	log_close();

	return EXIT_SUCCESS;
}
