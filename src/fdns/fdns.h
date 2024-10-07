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
#include <time.h>
#include <ctype.h>

#define errExit(msg)    do { char msgout[500]; snprintf(msgout, 500, "Error %s: %s:%d %s", msg, __FILE__, __LINE__, __FUNCTION__); perror(msgout); exit(1);} while (0)

// macro to print ip addresses in a printf statement
#define PRINT_IP(A) \
	((int) (((A) >> 24) & 0xFF)),  ((int) (((A) >> 16) & 0xFF)), ((int) (((A) >> 8) & 0xFF)), ((int) ( (A) & 0xFF))

// read an IPv4 address and convert it to uint32_t
static inline int atoip(const char *str, uint32_t *ip) {
	unsigned a, b, c, d;

	if (sscanf(str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4 || a > 255 || b > 255 || c > 255 || d > 255)
		return 1;

	*ip = a * 0x1000000 + b * 0x10000 + c * 0x100 + d;
	return 0;
}

// check ip:port
// return -1 if error
static inline int check_addr_port(const char *str) {
	unsigned a, b, c, d;
	int e;

	// extract ip
	int rv = sscanf(str, "%u.%u.%u.%u:%d", &a, &b, &c, &d, &e);
	if (rv != 5 || a > 255 || b > 255 || c > 255 || d > 255 || e < 0 || e > 0xffff)
		return -1;
	return 0;
}

// random value from a range
static inline int rand_range(int min, int max) {
	if (min == max)
		return min;

	assert(min <= max);
	int delta = rand() % (max + 1 - min);
	return min + delta;
}

// resolvers/frontend timers in seconds
#define RESOLVER_KEEPALIVE_TIMER 10 // keepalive messages sent by resolver processes
#define RESOLVER_KEEPALIVE_SHUTDOWN (RESOLVER_KEEPALIVE_TIMER * 3) // timer to detect a dead resolver process
#define FRONTEND_KEEPALIVE_TIMER 10 // keepalive messages sent by frontend processes
#define FRONTEND_KEEPALIVE_SHUTDOWN (FRONTEND_KEEPALIVE_TIMER * 3) // timer to detect the dead frontend process
#define MONITOR_WAIT_TIMER 2	// wait for this number of seconds before restarting a failed resolver process
#define CONSOLE_PRINTOUT_TIMER 5	// transfer stats from resolver to frontend
#define OUT_OF_SLEEP 10 // attempting to detect the computer coming out of sleep mode

// transport protocol timeout
#define DOT_TIMEOUT 5 // wait time for DoT answer - will close the connection
#define H11_TIMEOUT 5 // wait time for HTTP1 (DoH) answer - will close the connection
#define H2_TIMEOUT 5 // wait time for HTTP2 (DoH) answer - will close the connection

// transport  keealive autodetection
#define DNS_CONFIG_KEEPALIVE_MIN 5 // transport keepalive (PING) min value in seconds for --keepalive option
#define DNS_KEEPALIVE_DEFAULT 25
#define DNS_MAX_AUTODETECT_KEEPALIVE 65

#define FALLBACK_TIMEOUT 10 // wait time for DNS responses from the server in fallback
	// for NAT traversal, this value should be smaller than 30 seconds - the default is in /proc/sys/net/netfilter/nf_conntrack_udp_timeout

// logging
#define LOG_TIMEOUT_DEFAULT 10		// amount of time to keep the log entries in shared memory in minutes

// cache
#define CACHE_TTL_DEFAULT (40 * 60)	// default DNS cache ttl in seconds
#define CACHE_TTL_MIN (1 * 60)
#define CACHE_TTL_MAX (60 * 60)
#define CACHE_TTL_ERROR 120	// cache ttl for error message (such as NXDOMAIN) returned by the server
#define CACHE_PRINT_TIMEOUT	60	// list the domain in the cache

// number of resolver processes
#define RESOLVERS_CNT_MIN 1	// number of resolver processes
#define RESOLVERS_CNT_MAX 10
#define RESOLVERS_CNT_DEFAULT 2
#define DEFAULT_PROXY_ADDR "127.1.1.1"
#define MAX_FALLBACK_POOL 8	// fallback socket pool size

// filesystem paths
#define PATH_FDNS (PREFIX "/bin/fdns")
#define PATH_RUN_FDNS "/run/fdns"
#define PATH_ETC_TRACKERS_LIST (SYSCONFDIR "/list.trackers")
#define PATH_ETC_ADBLOCKER_LIST (SYSCONFDIR "/list.adblocker")
#define PATH_ETC_COINBLOCKER_LIST (SYSCONFDIR "/list.coinblocker")
#define PATH_ETC_PHISHING_LIST (SYSCONFDIR "/list.phishing")
#define PATH_ETC_TLD_LIST (SYSCONFDIR "/list.tld-blacklist")
#define PATH_ETC_DYNDNS_LIST (SYSCONFDIR "/list.dyndns")
#define PATH_ETC_MALWARE_LIST (SYSCONFDIR "/list.malware")
#define PATH_ETC_HOSTS_LIST (SYSCONFDIR "/hosts")
#define PATH_ETC_SERVER_LIST (SYSCONFDIR "/servers")
#define PATH_ETC_SERVER_LOCAL_LIST (SYSCONFDIR "/servers.local")
#define PATH_ETC_RESOLVER_SECCOMP (SYSCONFDIR "/resolver.seccomp")
#define PATH_LOG_FILE "/var/log/fdns.log"
#define PATH_STATS_FILE "/fdns-stats"	// the actual path is /dev/shm/fdns-stats
#define PATH_CHROOT PATH_RUN_FDNS "/empty"	// chroot directory for resolver procs

#define MAXBUF 2048
typedef struct stats_t {
	int changed;

	// packet counts
	unsigned rx;
	unsigned fallback;
	unsigned drop;
	unsigned cached;
	unsigned fwd;

	// average time
	double query_time;

	// per-resolver stats
	int encrypted[RESOLVERS_CNT_MAX];
	uint32_t peer_ip[RESOLVERS_CNT_MAX];
} Stats;

typedef struct dnsserver_t {
	struct dnsserver_t *next;// linked list
	int  active;		// flag for random purposes

	// server data
	char *name;	// name
	char *address;	// IP address
	char *website;	// website
	char *tags;		// description
	char *host;		// authority in http2
	char *path;
	char *transport;	// supported transport types
	int sni;		// 1 or 0
	int test_sni;		// not read from the config file; 1 only when the server is specified by url with --server or --test-server
	int keepalive;	// keepalive in seconds
} DnsServer;

typedef struct dnstransport_t {
	const char *name;	// ALPN transport name
	const char *dns_type;	// dns type (DoH, DoT etc.

	// connect
	void (*init)(void);
	void (*close)(void);
	int (*connect)(void);

	// traffic
	int (*send_exampledotcom)(uint8_t *req);
	int (*send_query)(uint8_t *req, int cnt);
	int (*send_ping)(void);
	int (*exchange)(uint8_t *response, uint32_t stream);

	// stats
	void (*header_stats)(void);
	double (*bandwidth)(void);
	void (*print_url)(void);
} DnsTransport;


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



// memory printout
static inline void mem_ascii(const unsigned char *ptr, ssize_t sz) {
	printf("   ");
	int j;
	unsigned char *ptr2 = (unsigned char *) ptr - sz + 1;
	for (j = 0; j < sz; j++, ptr2++) {
		if (isalnum(*ptr2) || ispunct(*ptr2)) {
			char str[2];
			str[0] = *ptr2;
			str[1] = '\0';
			printf("%s", str);
		}
		else
			printf(".");
	}
	printf("\n");
}


static inline void print_mem(void *ptr, ssize_t len) {
	const uint8_t *ptr2 = (uint8_t *) ptr;
	ssize_t i;
	for ( i = 0; i < len; i++) {
		if (i % 16 == 0)
			printf("%04lx: ", i);
		if ((i + 8) % 16 == 0)
			printf("- ");
		printf("%02x ", ptr2[i]);
		if (i % 16 == 15)
			mem_ascii(ptr2 + i, 16);
	}

	ssize_t rm = 16 - (i % 16);
	ssize_t j;
	for (j = 0; j < rm; j++)
		printf("   ");
	mem_ascii(ptr2 + i - 1, (i % 16));
	printf("\n");
}



// main.c
extern int arg_argc;
extern int arg_debug;
extern int arg_debug_transport;
extern int arg_resolvers;
extern int arg_id;
extern int arg_fd;
extern int arg_nofilter;
extern int arg_ipv6;
extern int arg_daemonize;
extern int arg_allow_all_queries;
extern char *arg_server;
extern char *arg_test_server;
extern char *arg_server_list;
extern char *arg_proxy_addr;
extern char *arg_certfile;
extern char *arg_forwarder;
extern char *arg_whitelist_file;
#define MAX_BLOCKLIST_FILE 8
extern char *arg_blocklist_file[MAX_BLOCKLIST_FILE];
extern int arg_keepalive;
extern int arg_details;
extern int arg_allow_self_signed_certs;
extern int arg_allow_expired_certs;
extern char *arg_fallback_server;
extern Stats stats;

// dnsdb.c
void dnsdb_init(void);
void dnsdb_store(int pool_index, uint8_t *buf, struct sockaddr_in *addr);
struct sockaddr_in *dnsdb_retrieve(int pool_index, uint8_t *buf);
int dnsdb_timeout(void);

// ssl.c
typedef enum {
	SSL_CLOSED = 0,
	SSL_OPEN
} SSLState;
extern SSLState ssl_state;

int ssl_test_open(void);
void ssl_init(void);
void ssl_open(void);
void ssl_close(void);
int ssl_status_check(void);
int ssl_rx(uint8_t *buf, int size);
int ssl_rx_timeout(uint8_t *buf, int size, int timeout);
int ssl_tx(uint8_t *buf, int len);
int ssl_get_socket(void);

// frontend.c
void frontend(void);

// security.c
void daemonize(void);
void chroot_drop_privs(const char *username, const char *dir);
int seccomp_load_filter_list(void);
void seccomp_resolver(void);

// dns.c
extern DnsTransport *transport;
typedef enum {
	DEST_DROP = 0,	// drop the packet
	DEST_SSL,		// send the packet over SSL
	DEST_LOCAL,	// local cache or filtered out
	DEST_FORWARDING,	// forwarding
	DEST_MAX // always the last one
} DnsDestination;

void dns_set_transport(const char *tname);
const char *dns_get_transport(void);
uint8_t *dns_parser(uint8_t *buf, ssize_t *len, DnsDestination *dest);
int dns_get_current_keepalive(void);
void dns_send_keepalive(void);
int dns_query(uint8_t *msg, int cnt);

// filter.c
void filter_init(void);
void filter_load_all_lists(void);
void filter_load_list(const char *fname);
int filter_blocked(const char *str, int verbose);
void filter_test(char *url);
void filter_test_list(void);

// log.c
typedef struct logmsgheader_t {
	uint16_t len;	// packet length
} LogMsgHeader; // 24 bytes

typedef struct logmsg_t {
	LogMsgHeader h;
#define MAXMSG (1024 * 2)
	char buf[MAXMSG]; // text content ending in \0
} LogMsg;

// disable logging for testing purposes
void log_disable();
// remote logging (resolver processes)
void rlogprintf(const char *format, ...);
// local logging (monitor process)
void logprintf(const char *format, ...);

// util.c
int copy_file(const char *src, const char *dest);

// shmem.c
#define SHMEM_KEEPALIVE 3
void shmem_open(int create, const char *proxy_addr);
void shmem_store_stats(const char *proxy_addr);
void shmem_store_log(const char *str);
void shmem_print_stats(void);
void shmem_monitor_stats(const char *proxy_addr);
void shmem_keepalive(void);
void shm_timeout(void);

// server.c
extern int server_print_servers;
extern int server_print_unlist;
void server_load(void);
void server_list(const char *tag);
DnsServer *server_get(void);
// return 0 if ok, 1 if failed
void server_test_tag(const char *tag);
void server_set_custom(const char *url);

// unlisted.c
void *unlisted_find(const char *name);
void unlisted_add(const char *name);

// fallback.c
DnsServer *server_fallback_get(void);

// cache.c
#define CACHE_NAME_LEN 100 // requests for domain names bigger than this value are not cached
void cache_set_name(const char *name, int qtype);
const char *cache_get_name(void);
void cache_set_reply(uint8_t *reply, ssize_t len, int ttl);
uint8_t *cache_check(uint16_t id, const char *name, ssize_t *lenptr, int qtype);
void cache_timeout(void);
void cache_init(void);
void print_cache(void);

// resolver.c
void resolver(void);

// net.c
void net_check_proxy_addr(const char *str);
int net_local_dns_socket(int reuse);
int net_remote_dns_socket(struct sockaddr_in *addr, const char *ipstr);

// forward.c
typedef struct forward_zone_t {
	struct forward_zone_t *next;

	const char *name;	// domain name
	unsigned name_len;	// length of the domain name string
	const char *ip;	// IP address

	// socket
	int sock;
	struct sockaddr_in saddr;
	socklen_t slen;
} Forwarder;

extern Forwarder *fwd_list;
extern Forwarder *fwd_active;
void forwarder_set(const char *str);
int forwarder_check(const char *domain, unsigned len);

// whitelist.c
int whitelist_cnt(void);
int whitelist_active(void);
void whitelist_add(const char *domain);
void whitelist_load_file(const char *fname);
void whitelist_command(char **argv);
int whitelist_blocked(const char *domain);

// procs.c
void procs_add(void);
void procs_exit(void);
char *procs_list(pid_t *default_proxy_pid);

// h2.c
extern DnsTransport h2_transport;

// huffman.c
char *huffman_search(uint8_t *hstr, int len);

// h11.c
extern DnsTransport h11_transport;

// dot.c
extern DnsTransport dot_transport;

// stats.c
void stats_add(const char *name, float qtime);
void stats_down(const char *name);
void stats_print(void);

// resetart.c
void restart(void);

#endif
