/*
 * Copyright (C) 2019-2021 FDNS Authors
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
#include "timetrace.h"
#include <time.h>
#include <signal.h>
#include <openssl/opensslv.h>

int arg_argc = 0;
int arg_debug = 0;
int arg_debug_transport = 0;
int arg_resolvers = RESOLVERS_CNT_DEFAULT;
int arg_id = -1;
int arg_fd = -1;
int arg_nofilter = 0;
int arg_ipv6 = 0;
int arg_daemonize = 0;
int arg_allow_all_queries = 0;
char *arg_server = NULL;
char *arg_test_server = NULL;
char *arg_proxy_addr = NULL;
char *arg_certfile = NULL;
char *arg_blocklist_file[MAX_BLOCKLIST_FILE] = {NULL};
char *arg_server_list = PATH_ETC_SERVER_LIST;
int arg_keepalive = 0;
int arg_details = 0;
int arg_allow_self_signed_certs = 0;
int arg_allow_expired_certs = 0;
char *arg_fallback_server = NULL;

Stats stats;

// clear /run/fdns/#pid# file
static void my_handler(int s) {
	(void) s;
	procs_exit();
}

static void install_handler(void) {
	struct sigaction sga;

	// block SIGTERM while handling SIGINT
	sigemptyset(&sga.sa_mask);
	sigaddset(&sga.sa_mask, SIGTERM);
	sga.sa_handler = my_handler;
	sga.sa_flags = 0;
	sigaction(SIGINT, &sga, NULL);

	// block SIGINT while handling SIGTERM
	sigemptyset(&sga.sa_mask);
	sigaddset(&sga.sa_mask, SIGINT);
	sga.sa_handler = my_handler;
	sga.sa_flags = 0;
	sigaction(SIGTERM, &sga, NULL);
}

void restart_program(void) {
	// extract command line
	char *fname;
	if (asprintf(&fname, "/proc/%d/cmdline", getpid()) == -1)
		errExit("asprintf");
	FILE *fp = fopen(fname, "r");
	if (!fp) {
		fprintf(stderr, "Error: cannot open %s file, the proxy was not restarted\n", fname);
		return;
	}

#define MAXARG 2048
	char *arg[MAXARG];
	int cnt = 0;
	size_t size = 0;
	while(getdelim(&arg[cnt], &size, 0, fp) != -1) {
		cnt++;
		if (cnt >=  MAXARG) {
			fprintf(stderr, "Error: maximum number of program arguments reached, the proxy was not restarted\n");
			fclose(fp);
			return;
		}
	}

	fclose(fp);
	arg[cnt] = NULL;
	int rv = execv(PATH_FDNS, arg);
	(void) rv;
}

static void usage(void) {
	printf("fdns - DNS over HTTPS proxy server\n\n");
	printf("Usage:\n");
	printf("    start the server:     fdns [options]\n");
	printf("    monitor the server:   fdns --monitor\n");
	printf("\n");
	printf("Options:\n");
	printf("    --allow-all-queries - allow all DNS query types; by default only\n"
	       "\tA queries are allowed.\n");
	printf("    --allow-expired-certs - allow expired SSL certificates.\n");
	printf("    --allow-self-signed-certs - allow self-signed SSL certificates.\n");
	printf("    --blocklist-file=filename - block the domains in the file\n");
	printf("    --certfile=filename - SSL certificate file in PEM format.\n");
	printf("    --daemonize - detach from the controlling terminal and run as a Unix\n"
	       "\tdaemon.\n");
	printf("    --debug - print all debug messages.\n");
	printf("    --debug-transport - print transport protocol debug messages.\n");
	printf("    --details - SSL connection information, HTTP headers and network traces are\n"
	       "\tprinted on the screen during the testing phase.\n");
	printf("    --fallback-server=address - fallback server IP address.\n");
	printf("    --forwarder=domain@address - conditional forwarding to a different DNS\n"
	       "\tserver.\n");
	printf("    --help, -?, -h - show this help screen.\n");
	printf("    --ipv6 - allow AAAA requests.\n");
	printf("    --keepalive=number - use this session keepalive value instead of the one in\n"
	       "\tservers file.\n");
	printf("    --list - list DoH servers for your geographical zone.\n");
	printf("    --list=server-name|tag|all - list DoH servers.\n");
	printf("    --monitor - monitor statistics for the default instance.\n");
	printf("    --monitor=proxy-address - monitor statistics for a specific instance\n"
	       "\tof FDNS.\n");
	printf("    --nofilter - no DNS request filtering.\n");
	printf("    --proxies - list all running instances of FDNS\n");
	printf("    --proxy-addr=address - configure the IP address the proxy listens on for\n"
	       "\tDNS queries coming from the local clients. The default is 127.1.1.1.\n");
	printf("    --resolvers=number - the number of resolver processes, between %d and %d,\n"
	       "\tdefault %d.\n",
	       RESOLVERS_CNT_MIN, RESOLVERS_CNT_MAX, RESOLVERS_CNT_DEFAULT);
	printf("    --restart - restart default proxy\n");
	printf("    --server=server-name|tag|all - DoH server to connect to.\n");
	printf("    --server-list=filename - file with the list of servers. \n"
	       "\tThe default is %s.\n", PATH_ETC_SERVER_LIST);
	printf("    --test-server - test the DoH servers in your current zone.\n");
	printf("    --test-server=server-name|tag|all - test DoH servers.\n");
	printf("    --test-url=URL - check if URL is dropped.\n");
	printf("    --test-url-list - check all URLs form stdin.\n");
	printf("    --version - print program version and exit.\n");
	printf("    --whitelist=domain - whitelist domain.\n");
	printf("    --whitelist-file=filename - whitelist the domains in the file.\n");
	printf("\n");
}

int main(int argc, char **argv) {
	// init
	init_time_delta();
	arg_argc = argc;
	memset(&stats, 0, sizeof(stats));
	filter_init();
	cache_init();
	srand(time(NULL) + getpid());

	// first pass: extracting data
	if (argc != 1) {
		int i;
		for (i = 1; i < argc; i++) {
			if (strcmp(argv[i], "--help") == 0 ||
			    strcmp(argv[i], "-?") == 0 ||
			    strcmp(argv[i], "-h") == 0) {
				usage();
				return 0;
			}
			else if (strcmp(argv[i], "--version") == 0) {
				printf("FDNS version %s. ", VERSION);
				printf("The software was compiled against OpenSSL %s\n", OPENSSL_VERSION_STR);
				printf("QUIC support: %s\n", (OPENSSL_VERSION_NUMBER >= 0x30500000)? "enabled": "disabled");
				if (OPENSSL_VERSION_NUMBER < 0x30500000)
					printf("Note: to add quic support you need an OpenSSL version 3.5 or up at compile time.\n");
				return 0;
			}

			else if (strcmp(argv[i], "--daemonize") == 0) {
				daemonize();
				arg_daemonize = 1;
			}
			else if (strcmp(argv[i], "--debug") == 0)
				arg_debug = 1;
			else if (strcmp(argv[i], "--debug-transport") == 0)
				arg_debug_transport = 1;
			else if (strncmp(argv[i], "--keepalive=", 12) == 0) {
				arg_keepalive = atoi(argv[i] + 12);
				if (arg_keepalive < DNS_CONFIG_KEEPALIVE_MIN) {
					fprintf(stderr, "Error: keepalive value too small. Minimum allowed value is %d\n", DNS_CONFIG_KEEPALIVE_MIN);
					exit(1);
				}
			}
			else if (strcmp(argv[i], "--allow-self-signed-certs") == 0)
				arg_allow_self_signed_certs = 1;
			else if (strcmp(argv[i], "--allow-expired-certs") == 0)
				arg_allow_expired_certs = 1;
			else if (strncmp(argv[i], "--certfile=", 11) == 0)
				arg_certfile = argv[i] + 11;
			else if (strcmp(argv[i], "--allow-all-queries") == 0)
				arg_allow_all_queries = 1;
			else if (strcmp(argv[i], "--nofilter") == 0)
				arg_nofilter = 1;
			else if (strcmp(argv[i], "--ipv6") == 0)
				arg_ipv6 = 1;
			else if (strncmp(argv[i], "--resolvers=", 12) == 0) {
				arg_resolvers = atoi(argv[i] + 12);
				if (arg_resolvers < RESOLVERS_CNT_MIN || arg_resolvers > RESOLVERS_CNT_MAX) {
					fprintf(stderr, "Error: the number of resolver processes should be between %d and %d\n",
						RESOLVERS_CNT_MIN, RESOLVERS_CNT_MAX);
					return 1;
				}
			}
			else if (strncmp(argv[i], "--id=", 5) == 0)
				arg_id = atoi(argv[i] + 5);
			else if (strncmp(argv[i], "--fd=", 5) == 0)
				arg_fd = atoi(argv[i] + 5);
			else if (strncmp(argv[i], "--server=", 9) == 0) {
				if (strncmp(argv[i] + 9, "https://", 8) == 0 ||
				    strncmp(argv[i] + 9, "dot://", 6)  == 0 ||
				    strncmp(argv[i] + 9, "quic://", 7)  == 0)
					server_set_custom(argv[i] + 9);
				arg_server = strdup(argv[i] + 9);
				if (!arg_server)
					errExit("strdup");
			}
			else if (strncmp(argv[i], "--fallback-server=", 18) == 0) {
				uint32_t ip;
				if (atoip(argv[i] + 18, &ip)) {
					fprintf(stderr, "Error: invalid fallback server IP address\n");
					exit(1);
				}
				arg_fallback_server = argv[i] + 18;
			}
			else if (strncmp(argv[i], "--server-list=", 14) == 0) {
				arg_server_list = argv[i] + 14;
				if (access(arg_server_list, R_OK) != 0) {
					fprintf(stderr, "Error: unable to access %s \n", arg_server_list);
					exit(1);
				};
			}
			else if (strncmp(argv[i], "--proxy-addr=", 13) == 0) {
				net_check_proxy_addr(argv[i] + 13); // will exit if error
				arg_proxy_addr = argv[i] + 13;
			}
			else if (strncmp(argv[i], "--forwarder=", 12) == 0)
				forwarder_set(argv[i] + 12);
			else if (strncmp(argv[i], "--whitelist=", 12) == 0)
				whitelist_add(argv[i] + 12);
			else if (strncmp(argv[i], "--whitelist-file=", 17) == 0)
				whitelist_load_file(argv[i] + 17);
			else if (strncmp(argv[i], "--blocklist-file=", 17) == 0) {
				int j = 0;
				for (j = 0; j < MAX_BLOCKLIST_FILE; j++)
					if (arg_blocklist_file[j] == NULL)
						break;
				if (j == MAX_BLOCKLIST_FILE) {
					fprintf(stderr, "Error: number of --blocklist-file commands exceeded\n");
					exit(1);
				}

				arg_blocklist_file[j] = strdup(argv[i] + 17);
				if (!arg_blocklist_file[j])
					errExit("strdup");
			}
			else if (strcmp(argv[i], "--details") == 0)
				arg_details = 1;

			// handled in second pass
			else if (strcmp(argv[i], "--restart") == 0);
			else if (strcmp(argv[i], "--list") == 0);
			else if (strncmp(argv[i], "--list=", 7) == 0);
			else if (strcmp(argv[i], "--proxies") == 0);
			else if (strcmp(argv[i], "--monitor") == 0);
			else if (strncmp(argv[i], "--monitor=", 10) == 0);
			else if (strcmp(argv[i], "--test-url-list") == 0);
			else if (strncmp(argv[i], "--test-url=", 11) == 0);
			else if (strcmp(argv[i], "--test-server") == 0);
			else if (strncmp(argv[i], "--test-server=", 14) == 0);
			else if (strcmp(argv[i], "--details") == 0);

			// errors
			else {
				fprintf(stderr, "Error: invalid command line argument %s\n", argv[i]);
				return 1;
			}

		}
	}

	// second pass
	if (argc != 1) {
		int i;
		for (i = 1; i < argc; i++) {
			if (strcmp(argv[i], "--restart") == 0) {
				restart();
				return 0;
			}
			if (strcmp(argv[i], "--list") == 0) {
				server_print_servers = 1;
				server_list(NULL);
				return 0;
			}
			else if (strncmp(argv[i], "--list=", 7) == 0) {
				server_print_servers = 1;
				server_list(argv[i] + 7);
				return 0;
			}
			else if (strcmp(argv[i], "--proxies") == 0) {
				char *rv = procs_list(NULL);
				free(rv);
				return 0;
			}
			else if (strcmp(argv[i], "--monitor") == 0) {
				shmem_monitor_stats(NULL);
				return 0;
			}
			else if (strncmp(argv[i], "--monitor=", 10) == 0) {
				net_check_proxy_addr(argv[i] + 10); // will exit if error
				shmem_monitor_stats(argv[i] + 10);
				return 0;
			}

			// test options
			else if (strcmp(argv[i], "--test-url-list") == 0) {
				server_print_unlist = 0;
				server_list("any");
				filter_load_all_lists();
				filter_test_list();
				return 0;
			}
			else if (strncmp(argv[i], "--test-url=", 11) == 0) {
				server_print_unlist = 0;
				server_list("any");
				filter_load_all_lists();
				filter_test(argv[i] + 11);
				return 0;
			}
			else if (strcmp(argv[i], "--test-server") == 0) {
				arg_test_server = "test all local servers";
				server_test_tag(NULL);
				return 0;
			}
			else if (strncmp(argv[i], "--test-server=", 14) == 0) {
				arg_test_server = strdup(argv[i] + 14);
				if (!arg_test_server)
					errExit("strdup");
				if (strncmp(argv[i] + 14, "https://", 8) == 0 ||
				    strncmp(argv[i] + 14, "dot://", 6) == 0 ||
				    strncmp(argv[i] + 14, "quic://", 7) == 0) {
					server_set_custom(argv[i] + 14);
					server_test_tag(argv[i] + 14);
				}
				else
					server_test_tag(arg_test_server);
				return 0;
			}
		}
	}

	if (getuid() != 0) {
		fprintf(stderr, "Error: you need to be root to run this program\n");
		exit(1);
	}

	// initialize the active server structure
	DnsServer *s = server_get();
	if (s == NULL) {
		// sleep and try again
		fprintf(stderr, "... retrying in 60 seconds ...\n");
		sleep(60);
		restart_program();
		assert(0); // it should not get here!
	}

	assert(s);
	assert(arg_server);
	if (arg_keepalive)
		s->keepalive = arg_keepalive;

	// start the frontend or the resolver
	if (arg_id != -1) {
		// reinitialize random number generator
		srand(time(NULL) + arg_id);

		assert(arg_fd != -1);
		resolver();
	}
	else {
		// init fallback server
		if (arg_fallback_server == NULL) {
			printf("\n");
			DnsServer *srv = server_fallback_get();
			assert(srv);
			arg_fallback_server = strdup(srv->address);
			if (!arg_fallback_server)
				errExit("strdup");
			printf("\n");
		}
		logprintf("fdns starting\n");
		logprintf("connecting to %s\n", s->name);

		install_handler();
		frontend();
	}

	return 0;
}
