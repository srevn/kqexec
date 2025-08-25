#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "client.h"
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

/* Application operation modes */
typedef enum operation_mode {
	MODE_DAEMON,                           /* Run as background daemon monitoring files */
	MODE_CLIENT                            /* Run as client sending commands to daemon */
} operation_t;

/* Print usage */
static void print_usage(void) {
	fprintf(stderr, "Usage: %s [daemon options] | [client options]\n", program_name);
	fprintf(stderr, "\nDaemon mode options:\n");
	fprintf(stderr, "  -c, --config=FILE      Configuration file (default: %s)\n", DEFAULT_CONFIG_FILE);
	fprintf(stderr, "  -d, --daemon           Run as daemon\n");
	fprintf(stderr, "  -l, --loglevel=LEVEL   Set log level (0-7, default: 5)\n");
	fprintf(stderr, "  -r, --cooldown=MS      Set command cooldown time in milliseconds (default: 500)\n");
	fprintf(stderr, "  -h, --help             Print this help message\n");
	fprintf(stderr, "\nClient mode options:\n");
	fprintf(stderr, "  --disable=WATCHES      Disable specific watches (comma-separated)\n");
	fprintf(stderr, "  --enable=WATCHES       Enable specific watches (comma-separated)\n");
	fprintf(stderr, "  --status               Show status of watches\n");
	fprintf(stderr, "  --list                 List all configured watches\n");
	fprintf(stderr, "  --reload               Reload configuration\n");
	fprintf(stderr, "  --socket=PATH          Socket path to connect to (default: /tmp/kqexec.sock)\n");
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
		/* Daemon options */
		{"config", required_argument, 0, 'c'},
		{"daemon", no_argument, 0, 'd'},
		{"loglevel", required_argument, 0, 'l'},
		{"cooldown", required_argument, 0, 'r'},
		{"help", no_argument, 0, 'h'},

		/* Client options */
		{"disable", required_argument, 0, 1000},
		{"enable", required_argument, 0, 1001},
		{"status", no_argument, 0, 1002},
		{"list", no_argument, 0, 1003},
		{"reload", no_argument, 0, 1004},
		{"socket", required_argument, 0, 1005},
		{0, 0, 0, 0}};

	/* Client options */
	operation_t mode = MODE_DAEMON;
	options_t options = {0};

	while ((c = getopt_long(argc, argv, "c:dl:r:h", long_options, &option_index)) != -1) {
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
			case 'r':
				command_cooldown_time(atoi(optarg));
				break;
			case 'h':
				print_usage();
				return EXIT_SUCCESS;

			/* Client options */
			case 1000: /* --disable */
				mode = MODE_CLIENT;
				options.command = CMD_DISABLE;
				options.watch_names = client_parse(optarg);
				if (options.watch_names) {
					/* Count watches */
					int count = 0;
					while (options.watch_names[count]) count++;
					options.num_watches = count;
				}
				break;
			case 1001: /* --enable */
				mode = MODE_CLIENT;
				options.command = CMD_ENABLE;
				options.watch_names = client_parse(optarg);
				if (options.watch_names) {
					/* Count watches */
					int count = 0;
					while (options.watch_names[count]) count++;
					options.num_watches = count;
				}
				break;
			case 1002: /* --status */
				mode = MODE_CLIENT;
				options.command = CMD_STATUS;
				break;
			case 1003: /* --list */
				mode = MODE_CLIENT;
				options.command = CMD_LIST;
				break;
			case 1004: /* --reload */
				mode = MODE_CLIENT;
				options.command = CMD_RELOAD;
				break;
			case 1005: /* --socket */
				options.socket_path = strdup(optarg);
				break;

			case '?':
				print_usage();
				return EXIT_FAILURE;
			default:
				abort();
		}
	}

	/* Route to appropriate mode */
	if (mode == MODE_CLIENT) {
		int result = client_main(&options);
		client_cleanup(&options);
		return result;
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
