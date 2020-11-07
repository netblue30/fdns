/*
 * Copyright (C) 2019-2020 FDNS Authors
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
	int delta = rand() % (max - min);
	return min + delta;
}

// resolvers/frontend timers in seconds
#define RESOLVER_KEEPALIVE_TIMER 10 // keepalive messages sent by resolver processes
#define RESOLVER_KEEPALIVE_SHUTDOWN (RESOLVER_KEEPALIVE_TIMER * 3) // timer to detect a dead resolver process
#define FRONTEND_KEEPALIVE_TIMER 10 // keepalive messages sent by frontend processes
#define FRONTEND_KEEPALIVE_SHUTDOWN (FRONTEND_KEEPALIVE_TIMER * 3) // timer to detect the dead frontend process
#define RESOLVER_KEEPALIVE_AFTER_SLEEP (RESOLVER_KEEPALIVE_TIMER * 1.2) // after sleep detection
#define MONITOR_WAIT_TIMER 2	// wait for this number of seconds before restarting a failed resolver process
#define CONSOLE_PRINTOUT_TIMER 5	// transfer stats from resolver to frontend
#define SSL_REOPEN_TIMER 2	// try to reopen a failed SSL connection after this time
#define OUT_OF_SLEEP 10 // attempting to detect the computer coming out of sleep mode

// transport protocol timeout
#define DOT_TIMEOUT 5 // wait time for DoT answer - will close the connection
#define H11_TIMEOUT 5 // wait time for HTTP1 (DoH) answer - will close the connection
#define H2_TIMEOUT 5 // wait time for HTTP2 (DoH) answer - will close the connection
#define TRANSPORT_KEEPALIVE_MIN 5 // transport keepalive (PING) min value in seconds for --keepalive option
#define TRANSPORT_KEEPALIVE_MAX 600 // transport keepalive (PING) max value in seconds for --keepalive option
#define SERVER_RESPONSE_LIMIT 80 // milliseconds - try another server if the first one responds above this limit
#define SERVER_KEEPALIVE_LIMIT 110 // seconds
#define FALLBACK_TIMEOUT 10 // wait time for responses on fallback
	// for NAT traversal, this value should be smaller than 30 seconds - the default is in /proc/sys/net/netfilter/nf_conntrack_udp_timeout
#define FALLBACK_UPDATE_TIMEOUT (15 * 60)	// randomize fallback sockets every 15 minutes

// logging
#define LOG_TIMEOUT_DEFAULT 10		// amount of time to keep the log entries in shared memory in minutes
#define LOG_TIMEOUT_MAX 1140		// 1 day maximum
// cache
#define CACHE_TTL_DEFAULT (40 * 60)	// default DNS cache ttl in seconds
#define CACHE_TTL_MIN (1 * 60)
#define CACHE_TTL_MAX (60 * 60)
#define CACHE_TTL_ERROR (10 * 60)	// cache ttl for errror mesage (such as NXDOMAIN) returned by the server
#define CACHE_PRINT_TIMEOUT	60	// list the domain in the cache

// rate limitation
#define QPS_DEFAULT 10	// default queries per second limit for each resolver
#define QPS_MAX 20		// max --qps value
#define QPS_MIN 3		// min --qps value

// number of resolver processes
#define RESOLVERS_CNT_MIN 1	// number of resolver processes
#define RESOLVERS_CNT_MAX 10
#define RESOLVERS_CNT_DEFAULT 2
#define UNIX_ADDRESS "fdns"	// internal UNIX socket address for communication between frontend and resolvers
#define DEFAULT_PROXY_ADDR "127.1.1.1"
#define DEFAULT_PROXY_LOOPBACK "127.0.0.1"
#define MAX_FALLBACK_POOL 8	// fallback socket pool size

// filesystem paths
#define PATH_FDNS (PREFIX "/bin/fdns")
#define PATH_RUN_FDNS "/run/fdns"
#define PATH_ETC_TRACKERS_LIST (SYSCONFDIR "/trackers")
#define PATH_ETC_FP_TRACKERS_LIST (SYSCONFDIR "/fp-trackers")
#define PATH_ETC_ADBLOCKER_LIST (SYSCONFDIR "/adblocker")
#define PATH_ETC_COINBLOCKER_LIST (SYSCONFDIR "/coinblocker")
#define PATH_ETC_BULKMAILER_LIST (SYSCONFDIR "/bulkmailers")
#define PATH_ETC_DOH_LIST (SYSCONFDIR "/doh")
#define PATH_ETC_HOSTS_LIST (SYSCONFDIR "/hosts")
#define PATH_ETC_SERVER_LIST (SYSCONFDIR "/servers")
#define PATH_ETC_RESOLVER_SECCOMP (SYSCONFDIR "/resolver.seccomp")
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
	unsigned fwd;

	// average time
	double ssl_pkts_timetrace;
	unsigned ssl_pkts_cnt;
} Stats;

typedef struct dnsserver_t {
	struct dnsserver_t *next;// linked list
	int  active;		// flag for random purposes

	// server data
	char *name;	// name
	char *address;	// IP address
	char *website;	// website
	char *zone;		// geographical zone
	char *tags;		// description
	char *host;		// authority in http2
	char *path;
	char *transport;	// supported transport types
	int sni;		// 1 or 0
	int test_sni;		// not read from the config file; 1 only when the server is specified by url with --server or --test-server
	int keepalive_query;	// 1 or 0
	int keepalive_min;	// minimum value of keepalive in seconds
	int keepalive_max;	// maximum vallue of keepalive in seconds
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

static inline void print_mem(void *m, int len) {
	int i;
	unsigned char *msg = (unsigned char *) m;

	char buf[16 + 1];
	char *ptr = buf;
	*ptr = '\0';

	for (i = 0; i < len; i++, msg++) {
		printf("%02x ", *msg);

		if (*msg >= 0x20 && *msg <= 0x7f)
			*ptr = *msg;
		else
			*ptr = '.';
		ptr++;

		if (i % 16 == 15) {
			*ptr = '\0';
			printf("\t%s\n", buf);
			memset(buf, 0, sizeof(buf));
			ptr = buf;
		}
	}
	printf("\t%s\n", buf);
}


// main.c
extern int arg_argc;
extern int arg_debug;
extern int arg_debug_transport;
extern int arg_debug_ssl;
extern int arg_resolvers;
extern int arg_id;
extern int arg_fd;
extern int arg_nofilter;
extern int arg_ipv6;
extern int arg_daemonize;
extern int arg_allow_all_queries;
extern char *arg_server;
extern char *arg_test_server;
extern char *arg_proxy_addr;
extern int arg_proxy_addr_any;
extern char *arg_certfile;
extern char *arg_forwarder;
extern char *arg_zone;
extern int arg_cache_ttl;
extern int arg_disable_local_doh;
extern char *arg_whitelist_file;
extern int arg_fallback_only;
extern int arg_keepalive;
extern int arg_qps;
extern int arg_details;
extern char *arg_transport;
extern int arg_allow_self_signed_certs;
extern int arg_allow_expired_certs;
extern int arg_log_timeout;
char *arg_fallback_server;
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

void ssl_init(void);
void ssl_open(void);
void ssl_close(void);
int ssl_status_check(void);
int ssl_rx(uint8_t *buf, int size);
int ssl_rx_timeout(uint8_t *buf, int size, int timeout);
int ssl_tx(uint8_t *buf, int len);
int ssl_get_socket(void);

// frontend.c
extern int encrypted[RESOLVERS_CNT_MAX];
void frontend(void);

// security.c
void daemonize(void);
void chroot_drop_privs(const char *username);
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
void dns_keepalive(void);
int dns_query(uint8_t *msg, int cnt);

// filter.c
void filter_init(void);
void filter_load_all_lists(void);
void filter_add(char label, const char *domain);
const char *filter_blocked(const char *str, int verbose);
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

void log_disable(void);
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
extern int server_print_zone;
extern int server_print_servers;
void server_load(void);
void server_list(const char *tag);
DnsServer *server_get(void);
// return 0 if ok, 1 if failed
void server_test_tag(const char *tag);
void server_set_custom(const char *url);
DnsServer *server_fallback_get(void);

// cache.c
#define CACHE_NAME_LEN 100 // requests for domain names bigger than this value are not cached
void cache_set_name(const char *name, int ipv6);
const char *cache_get_name(void);
void cache_set_reply(uint8_t *reply, ssize_t len, int ttl);
uint8_t *cache_check(uint16_t id, const char *name, ssize_t *lenptr, int ipv6);
void cache_timeout(void);
void cache_init(void);
void print_cache(void);

// resolver.c
void resolver(void);

// net.c
void net_check_proxy_addr(const char *str);
int net_local_dns_socket(int reuse);
int net_remote_dns_socket(struct sockaddr_in *addr, const char *ipstr);
void net_local_unix_socket(void);

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
extern int procs_addr_default;
extern int procs_addr_loopback;
extern char *procs_addr_real;
void procs_add(void);
void procs_exit(void);
void procs_list(void);

// h2.c
extern DnsTransport h2_transport;

// huffman.c
char *huffman_search(uint8_t *hstr, int len);

// h11.c
extern DnsTransport h11_transport;

// dot.c
extern DnsTransport dot_transport;

#endif
