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
#ifndef FDNS_H
#define FDNS_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define errExit(msg)    do { char msgout[500]; snprintf(msgout, 500, "Error %s: %s:%d %s", msg, __FILE__, __LINE__, __FUNCTION__); perror(msgout); exit(1);} while (0)

// macro to print ip addresses in a printf statement
#define PRINT_IP(A) \
((int) (((A) >> 24) & 0xFF)),  ((int) (((A) >> 16) & 0xFF)), ((int) (((A) >> 8) & 0xFF)), ((int) ( (A) & 0xFF))

// check ip:port
// return -1 if error
static inline int check_addr_port(const char *str) {
	unsigned a, b, c, d, e;

	// extract ip
	int rv = sscanf(str, "%u.%u.%u.%u:%u", &a, &b, &c, &d, &e);
	if (rv != 5 || a > 255 || b > 255 || c > 255 || d > 255 || e > 0xffffffff)
		return -1;
	return 0;
}

// all timers are in seconds
#define WORKER_KEEPALIVE_TIMER 10 // keepalive messages sent by worker processes
#define WORKER_KEEPALIVE_SHUTDOWN (WORKER_KEEPALIVE_TIMER * 3) // timer to detect a dead worker process
#define WORKER_KEEPALIVE_AFTER_SLEEP (WORKER_KEEPALIVE_TIMER * 1.2) // after sleep detection
#define MONITOR_WAIT_TIMER 2	// wait for this number of seconds before restarting a failed child process
#define CONSOLE_PRINTOUT_TIMER 10	// transfer stats from worker to monitor
#define SSL_REOPEN_TIMER 5	// try to reopen a failed SSL connection after this time
#define OUT_OF_SLEEP 20	// detect computer going out of sleep/hibernation, reinitialize SSL connections

// number of worker processes
#define WORKERS_MIN 1	// number of worker threads
#define WORKERS_MAX 10
#define WORKERS_DEFAULT 3
#define UNIX_ADDRESS "fdns"	// internal UNIX socket address for communication between monitor and child processes
#define DEFAULT_PROXY_ADDR "127.1.1.1"

// filesystem paths
#define PATH_FDNS (PREFIX "/bin/fdns")
#define PATH_RUN_FDNS "/run/fdns"
#define PATH_ETC_TRACKERS_LIST (SYSCONFDIR "/trackers")
#define PATH_ETC_ADBLOCKER_LIST (SYSCONFDIR "/adblocker")
#define PATH_ETC_HOSTS_LIST (SYSCONFDIR "/hosts")
#define PATH_ETC_SERVER_LIST (SYSCONFDIR "/servers")
#define PATH_ETC_WORKER_SECCOMP (SYSCONFDIR "/worker.seccomp")
#define PATH_LOG_FILE "/var/log/fdns.log"
#define PATH_STATS_FILE "/fdns-stats"	// the actual path is /dev/shm/fdns-stats


#define MAXBUF 2048
typedef struct stats_t {
	int changed;
	// packet counts
	unsigned rx;
	unsigned fallback;
	unsigned drop;
	unsigned cached;
} Stats;

typedef struct dnsserver_t {
	char *name;	// name
	char *website;	// website
	char *description;	// description
	char *address;	// IP address
	char *request1;	// POST request first line
	char *request2;	// POST request second line
	char *request;	// full POST request
	int ssl_keepalive;	// keepalive in seconds
} DnsServer;

static inline void ansi_topleft(void) {
	char str[] = {0x1b, '[', '1', ';',  '1', 'H', '\0'};
	printf("%s", str);
	fflush(0);
}

static inline void ansi_clrscr(void) {
	ansi_topleft();
	char str[] = {0x1b, '[', '0', 'J', '\0'};
	printf("%s", str);
	fflush(0);
}

static inline void print_mem(unsigned char *msg, int len) {
	int i;
	for (i = 0; i < len; i++, msg++) {
		printf("%02x ", *msg);
		if (i % 16 == 15)
			printf("\n");
	}
	printf("\n");
}


// main.c
extern int arg_debug;
extern int arg_workers;
extern int arg_id;
extern int arg_fd;
extern int arg_nofilter;
extern int arg_ipv6;
extern int arg_daemonize;
extern int arg_allow_all_queries;
extern char *arg_server;
extern char *arg_proxy_addr;
extern int arg_proxy_addr_any;
extern char *arg_certfile;
extern Stats stats;

// dnsdb.c
void dnsdb_init(void);
void dnsdb_store(uint8_t *buf, struct sockaddr_in *addr);
struct sockaddr_in *dnsdb_retrieve(uint8_t *buf);
void dnsdb_timeout(void);

// ssl.c
typedef enum {
	SSL_CLOSED = 0,
	SSL_OPEN
} SSLState;
extern SSLState ssl_state;

void ssl_init(void);
void ssl_open(void);
void ssl_close(void);
int ssl_dns(uint8_t *msg, int cnt);
void ssl_keepalive(void);
int ssl_status_check(void);

// monitor.c
int encrypted[WORKERS_MAX];
void monitor(void);

// security.c
void daemonize(void);
void chroot_drop_privs(const char *username);
int seccomp_load_filter_list(void);
void seccomp_worker(void);

// dns.c
uint8_t *dns_parser(uint8_t *buf, ssize_t *len);

// dnsfilter.c
void dnsfilter_init(void);
void dnsfilter_load_list(const char *fname);
int dnsfilter_blocked(const char *str, int verbose);
void dnsfilter_test(char *url);

// log.c
typedef struct logmsgheader_t {
	uint16_t len; // packet length
} LogMsgHeader; // 24 bytes

typedef struct logmsg_t {
	LogMsgHeader h;
#define MAXMSG (1024 * 2)
	char buf[MAXMSG]; // text content ending in \0
} LogMsg;

// remote logging (worker processes)
void rlogprintf(const char *format, ...);
// local logging (monitor process)
void logprintf(const char *format, ...);

// util.c
int copy_file(const char *src, const char * dest);

// shmem.c
void shmem_open(int create);
void shmem_store_stats(void);
void shmem_store_log(const char *str);
void shmem_print_stats(void);
void shmem_monitor_stats(void);

// dnsserver.c
DnsServer *dns_set_server(const char *srv);
DnsServer *dns_get_server(void);
void dns_list(void);
char *dns_get_random_server(void);

// cache.c
void cache_set_name(const char *name, int ipv6);
void cache_set_reply(uint8_t *reply, ssize_t len);
uint8_t *cache_check(uint8_t id0, uint8_t id1, const char *name, ssize_t *lenptr, int ipv6);
void cache_timeout(void);
void cache_init(void);

// worker.c
void worker(void);

// net.c
void net_check_proxy_addr(const char *str);
int net_local_dns_socket(void);
int net_remote_dns_socket(struct sockaddr_in *addr);
void net_local_unix_socket(void);

#endif
