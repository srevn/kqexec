#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <syslog.h>

#include "config.h"
#include "monitor.h"
#include "command.h"
#include "states.h"
#include "daemon.h"
#include "logger.h"

/* Default configuration file */
#define DEFAULT_CONFIG_FILE "/usr/local/etc/kqexec.conf"

/* Program name */
static const char *program_name;

/* Global monitor pointer */
monitor_t *g_monitor = NULL;

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
	int c;
	int option_index = 0;
	int log_level = LOG_LEVEL_NOTICE;
	char *config_file = NULL;
	int daemon_mode = 0;
	
	/* Get program name */
	program_name = strrchr(argv[0], '/');
	if (program_name == NULL) {
		program_name = argv[0];
	} else {
		program_name++;
	}
	
	/* Set up signal handlers */
	if (!daemon_setup_signals()) {
		log_message(LOG_LEVEL_ERR, "Failed to set up signal handlers");
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
		{0, 0, 0, 0}
	};
	
	while ((c = getopt_long(argc, argv, "c:dl:b:h", long_options, &option_index)) != -1) {
		switch (c) {
			case 'c':
				config_file = optarg;
				break;
			case 'd':
				daemon_mode = 1;
				break;
			case 'l':
				log_level = atoi(optarg);
				if (log_level < 0 || log_level > 7) {
					fprintf(stderr, "Invalid log level: %d (valid range: 0-7)\n", log_level);
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
	if (config_file == NULL) {
		config_file = DEFAULT_CONFIG_FILE;
	}
	
	/* Initialize logging */
	log_init(program_name, LOG_DAEMON, log_level, !daemon_mode);
	
	/* Create configuration */
	config = config_create();
	if (config == NULL) {
		log_message(LOG_LEVEL_ERR, "Failed to create configuration");
		log_close();
		return EXIT_FAILURE;
	}
	
	/* Set daemon mode */
	config->daemon_mode = daemon_mode;
	config->syslog_level = log_level;
	
	/* Parse configuration file */
	if (!config_parse_file(config, config_file)) {
		log_message(LOG_LEVEL_ERR, "Failed to parse configuration file: %s", config_file);
		config_destroy(config);
		log_close();
		return EXIT_FAILURE;
	}
	
	/* Start daemon if requested */
	if (config->daemon_mode) {
		if (!daemon_start(config)) {
			log_message(LOG_LEVEL_ERR, "Failed to start daemon");
			config_destroy(config);
			log_close();
			return EXIT_FAILURE;
		}
		
		/* Re-initialize logging without console output after daemonizing */
		log_close();
		log_init(program_name, LOG_DAEMON, log_level, 0);
	}
	
	/* Initialize command subsystem */
	if (!command_init()) {
		log_message(LOG_LEVEL_ERR, "Failed to initialize command subsystem");
		config_destroy(config);
		log_close();
		return EXIT_FAILURE;
	}
	
	/* Initialize entity states */
	if (!entity_state_init()) {
		log_message(LOG_LEVEL_ERR, "Failed to initialize entity states");
		command_cleanup();
		config_destroy(config);
		log_close();
		return EXIT_FAILURE;
	}
	
	/* Create monitor */
	monitor = monitor_create(config);
	if (monitor == NULL) {
		log_message(LOG_LEVEL_ERR, "Failed to create monitor");
		entity_state_cleanup();
		command_cleanup();
		config_destroy(config);
		log_close();
		return EXIT_FAILURE;
	}
	
	/* Set up monitor */
	if (!monitor_setup(monitor)) {
		log_message(LOG_LEVEL_ERR, "Failed to set up monitor");
		monitor_destroy(monitor);
		entity_state_cleanup();
		command_cleanup();
		config_destroy(config);
		log_close();
		return EXIT_FAILURE;
	}
	
	/* Store global reference for signal handler */
	g_monitor = monitor;
	
	/* Set monitor reference for daemon signal handler */
	daemon_set_monitor(monitor);
	
	/* Start monitor */
	if (!monitor_start(monitor)) {
		log_message(LOG_LEVEL_ERR, "Failed to start monitor");
		monitor_destroy(monitor);
		entity_state_cleanup();
		command_cleanup();
		config_destroy(config);
		log_close();
		return EXIT_FAILURE;
	}
	
	/* Clean up */
	daemon_set_monitor(NULL);
	monitor_destroy(monitor);
	entity_state_cleanup();
	command_cleanup();
	config_destroy(config);
	log_close();
	
	return EXIT_SUCCESS;
}
