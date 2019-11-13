/*
 * Copyright (C) 2014-2019 fdns Authors
 *
 * This file is part of fdns project
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
#include "fdns.h"
int arg_debug = 0;
int arg_workers = WORKERS_DEFAULT;
int arg_id = -1;
int arg_fd = -1;
int arg_nofilter = 0;
int arg_ipv6 = 0;
int arg_daemonize = 0;
int arg_allow_all_queries = 0;
char *arg_server = NULL;
char *arg_proxy_addr = NULL;
int arg_proxy_addr_any = 0;
char *arg_certfile = NULL;

Stats stats;

static void usage(void) {
	printf("fdns - DNS over HTTPS proxy server\n\n");
	printf("Usage:\n");
 	printf("    start the server:     fdns [options]\n");
	printf("    monitor the server:   fdns --monitor\n");
	printf("Options:\n");
	printf("    --allow-all-queries - allow all DNS query types; by default only\n"
		"\tA and AAA are allowed.\n");
	printf("    --certfile=filename - SSL certificate file in PEM format.\n");
	printf("    --daemonize - detach from the controlling terminal and run as a Unix\n"
		"\tdaemon.\n");
	printf("    --debug - print debug messages.\n");
	printf("    --help, -? - this help screen.\n");
	printf("    --ipv6 - allow AAAA requests.\n");
	printf("    --list - list all available DoH service providers.\n");
	printf("    --monitor - monitor statistics.\n");
	printf("    --nofilter - no DNS request filtering.\n");
	printf("    --proxy-addr=address - configure the IP address the proxy listens for\n"
		"\tDNS queries coming from the local clients. The default is 127.1.1.1.\n");
	printf("    --proxy-addr-any - listen on all available interfaces.\n");
	printf("    --server=server-name - configure the DoH service provider. Use --list\n"
		"\tto print the list of available providers.\n");
	printf("    --test-url=URL - check if URL is dropped.\n");
	printf("    --version - print program version and exit.\n");
	printf("    --workers=number - the number of worker threads, between %d and %d,\n"
		"\tdefault %d.\n",
		WORKERS_MIN, WORKERS_MAX, WORKERS_DEFAULT);
	printf("\n");
}

int main(int argc, char **argv) {
	// init
	memset(&stats, 0, sizeof(stats));
	memset(encrypted, 0, sizeof(encrypted));
	dnsfilter_init();
	cache_init();

	// process --daemonize before any other option
	if (argc != 1) {
		int i;
		for (i = 1; i < argc; i++) {
			if (strcmp(argv[i], "--daemonize") == 0) {
		 		daemonize();
			 	arg_daemonize = 1;
			 }
		}
	}


	// parse command line arguments
	if (argc != 1) {
		// parse arguments
		int i;
		for (i = 1; i < argc; i++) {
			if (strcmp(argv[i], "--help") == 0 ||
			    strcmp(argv[i], "-?") == 0) {
			 	usage();
			 	return 0;
			 }
			 else if (strcmp(argv[i], "--version") == 0) {
			 	printf("fdns version %s\n", VERSION);
			 	return 0;
			 }
			 else if (strcmp(argv[i], "--debug") == 0)
			 	arg_debug = 1;
			else if (strcmp(argv[i], "--daemonize") == 0)
				;
			 else if (strncmp(argv[i], "--test-url=", 11) == 0) {
			 	dnsfilter_load_list(PATH_ETC_TRACKERS_LIST);
			 	dnsfilter_load_list(PATH_ETC_ADBLOCKER_LIST);
			 	dnsfilter_load_list(PATH_ETC_HOST_LIST);
			 	dnsfilter_test(argv[i] + 11);
			 	return 0;
			 }
			 else if (strncmp(argv[i], "--certfile=", 11) == 0)
			 	arg_certfile = argv[i] + 11;
			 else if (strcmp(argv[i], "--allow-all-queries") == 0)
			 	arg_allow_all_queries = 1;
			 else if (strcmp(argv[i], "--nofilter") == 0)
			 	arg_nofilter = 1;
			 else if (strcmp(argv[i], "--ipv6") == 0)
			 	arg_ipv6 = 1;
			 else if (strncmp(argv[i], "--workers=", 10) == 0) {
			 	arg_workers = atoi(argv[i] + 10);
			 	if (arg_workers < WORKERS_MIN || arg_workers >WORKERS_MAX) {
			 		fprintf(stderr, "Error: the number of worker threads should be between %d and %d\n",
			 			WORKERS_MIN, WORKERS_MAX);
			 		return 1;
			 	}
			 }
			 else if (strncmp(argv[i], "--id=", 5) == 0)
			 	arg_id = atoi(argv[i] + 5);
			 else if (strncmp(argv[i], "--fd=", 5) == 0)
			 	arg_fd = atoi(argv[i] + 5);
			 else if (strncmp(argv[i], "--server=", 9) == 0) {
			 	dns_set_server(argv[i] + 9);
			 	arg_server = argv[i] + 9;
			 }
			 else if (strcmp(argv[i], "--list") == 0) {
			 	dns_list();
			 	return 0;
			 }
			 else if (strncmp(argv[i], "--proxy-addr=", 13) == 0) {
			 	net_check_proxy_addr(argv[i] + 13); // will exit if error
			 	arg_proxy_addr = argv[i] + 13;
			 }
			 else if (strcmp(argv[i], "--proxy-addr-any") == 0)
			 	arg_proxy_addr_any = 1;
			 else if (strcmp(argv[i], "--monitor") == 0) {
			 	shmem_monitor_stats();
			 	return 0;
			 }
			 else {
			 	fprintf(stderr, "Error: invalid command line argument %s\n", argv[i]);
			 	return 1;
			 }
		}
	}

	if (getuid() != 0) {
		fprintf(stderr, "Error: you need to be root to run this program\n");
		exit(1);
	}

	// check command line arguments
	if (arg_proxy_addr && arg_proxy_addr_any) {
		fprintf(stderr, "Error: --proxy-addr and --proxy-addr-any are mutually exclusive\n");
		exit(1);
	}

	// start the monitor or the worker
	if (arg_id != -1) {
		assert(arg_fd != -1);
		worker();
	}
	else {
		assert(arg_fd == -1);
		monitor();
	}

	return 0;
}
