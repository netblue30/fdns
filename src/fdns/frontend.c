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
#ifndef  _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>	// clone
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/un.h>

// keepalive autodetect
static int restarting = 0;
static char *proxy_addr = NULL;
static int restart_cnt = 0;
#ifdef __ia64__
/* clone(2) has a different interface on ia64, as it needs to know
   the size of the stack */
int __clone2(int (*fn)(void *),
	     void *child_stack_base, size_t stack_size,
	     int flags, void *arg, ...
	     /* pid_t *ptid, struct user_desc *tls, pid_t *ctid */ );
#endif

typedef struct resolver_t {
	pid_t pid;
	int keepalive;
	int fd[2];
#define STACK_SIZE (1024 * 1024)
#define STACK_ALIGNMENT 16
	char child_stack[STACK_SIZE] __attribute__((aligned(STACK_ALIGNMENT)));; // space for child's stack
} Resolver;
static Resolver w[RESOLVERS_CNT_MAX];

static volatile sig_atomic_t got_SIGCHLD = 0;
static void child_sig_handler(int sig) {
	(void) sig;
	got_SIGCHLD = 1;
}

static void my_handler(int s) {
	logprintf("signal %d caught, shutting down all resolvers\n", s);

	int i;
	for (i = 0; i < arg_resolvers; i++) {
		kill(w[i].pid, SIGKILL);
		int status;
		waitpid(w[i].pid, &status, 0);
	}

	// attempt to remove shmem file
	char *statsfile;
	assert(proxy_addr);
	if (asprintf(&statsfile, "/dev/shm/fdns-stats-%s", proxy_addr) == -1)
		errExit("asprintf");
	int rv = unlink(statsfile);
	(void) rv;
	free(statsfile);

	if (s == SIGUSR1) {
		logprintf("restarting...\n");
		restart_cnt = 0;
		restart_program();
	}

	exit(0);
}

static int sandbox(void *sandbox_arg) {
	int id = *(int *) sandbox_arg;

	prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0); // kill this new process in case the parent died

	// mount events are not forwarded between the host the sandbox
	if (mount(NULL, "/", NULL, MS_SLAVE | MS_REC, NULL) < 0)
		errExit("mount filesystem as slave");

	char *idstr;
	if (asprintf(&idstr, "--id=%d", id) == -1)
		errExit("asprintf");
	char *fdstr;
	if (asprintf(&fdstr, "--fd=%d", w[id].fd[1]) == -1)
		errExit("asprintf");

	// start an fdns resolver process
	int wcnt = whitelist_cnt();
	char *a[arg_argc + wcnt + 20];
	a[0] = PATH_FDNS;
	a[1] = idstr;
	a[2] = fdstr;
	int last = 3;
	if (arg_debug)
		a[last++] = "--debug";
	if (arg_debug_transport)
		a[last++] = "--debug-transport";
	if (arg_nofilter)
		a[last++] = "--nofilter";
	if (arg_ipv6)
		a[last++]  = "--ipv6";
	if (arg_proxy_addr) {
		char *cmd;
		if (asprintf(&cmd, "--proxy-addr=%s", arg_proxy_addr) == -1)
			errExit("asprintf");
		a[last++] = cmd;
	}
	if (arg_allow_self_signed_certs)
		a[last++] = "--allow-self-signed-certs";
	if (arg_allow_expired_certs)
		a[last++] = "--allow-expired-certs";

	// keepalive autodetect
	DnsServer *srv = server_get();
	assert(srv);
	// keepalive autodetection
	if (restarting && !arg_keepalive) {
		if (srv->keepalive > 30 && srv->keepalive <= 35)
			srv->keepalive = 30;
		arg_keepalive = srv->keepalive - 5;
		print_time();
		printf("(%d) Keepalive reconfigured for %d seconds\n", id, arg_keepalive);
	}

	if (arg_keepalive) {
		char *cmd;
		if (asprintf(&cmd, "--keepalive=%d", arg_keepalive) == -1)
			errExit("asprintf");
		a[last++] = cmd;
	}

	if (arg_certfile) {
		char *cmd;
		if (asprintf(&cmd, "--certfile=%s", arg_certfile) == -1)
			errExit("asprintf");
		a[last++] = cmd;
	}
	if (arg_server) {
		char *cmd;
		if (asprintf(&cmd, "--server=%s", arg_server) == -1)
			errExit("asprintf");
		a[last++] = cmd;
	}

	if (arg_allow_all_queries)
		a[last++] = "--allow-all-queries";

	{
		char *cmd;
		if (asprintf(&cmd, "--fallback-server=%s", arg_fallback_server) == -1)
			errExit("asprintf");
		a[last++] = cmd;
	}

	Forwarder *f = fwd_list;
	while (f) {
		char *cmd;
		if (asprintf(&cmd, "--forwarder=%s@%s", f->name, f->ip) == -1)
			errExit("asprintf");
		a[last++] = cmd;
		f = f->next;
	}

	int i;
	for (i = 0; i < MAX_BLOCKLIST_FILE; i++) {
		if (arg_blocklist_file[i]) {
			char *cmd;
			if (asprintf(&cmd, "--blocklist-file=%s", arg_blocklist_file[i]) == -1)
				errExit("asprintf");
			a[last++] = cmd;
		}
	}

	if (wcnt) {
		whitelist_command(a + last);
		last += wcnt;
	}

	a[last] = NULL;
	assert(last < (arg_argc + wcnt + 20));

	// add a small 2 seconds sleep before restarting, just in case we are looping
	fflush(0);
	sleep(MONITOR_WAIT_TIMER);
	execv(a[0], a);
	exit(1);
}

static void start_sandbox(int id) {
	assert(id < RESOLVERS_CNT_MAX);
	stats.encrypted[id] = 0;
	stats.peer_ip[id] = 0;

	// full restart after resolvers failing repeatedly
	if (++restart_cnt > (FORCE_RESTART_CNT * arg_resolvers)) {
		my_handler(SIGUSR1);
		assert(0); // it should never get here
	}

	if (w[id].fd[0] == 0) {
		if (socketpair(AF_UNIX, SOCK_DGRAM, 0, w[id].fd) < 0)
			errExit("socketpair");
		if (arg_debug)
			printf("resolverid %d, sockpair %d, %d\n", id, w[id].fd[0], w[id].fd[1]);
	}

	int flags = CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC | SIGCHLD;
	w[id].pid = clone(sandbox,
			  w[id].child_stack + STACK_SIZE,
			  flags,
			  &id);
	w[id].keepalive = RESOLVER_KEEPALIVE_SHUTDOWN;
	if (w[id].pid == -1)
		errExit("clone");
}

static void install_signal_handler(void) {
	struct sigaction sga;

	// block SIGTERM/SIGHUP while handling SIGINT
	sigemptyset(&sga.sa_mask);
	sigaddset(&sga.sa_mask, SIGTERM);
	sigaddset(&sga.sa_mask, SIGHUP);
	sigaddset(&sga.sa_mask, SIGUSR1);
	sga.sa_handler = my_handler;
	sga.sa_flags = 0;
	sigaction(SIGINT, &sga, NULL);

	// block SIGINT/SIGHUP while handling SIGTERM
	sigemptyset(&sga.sa_mask);
	sigaddset(&sga.sa_mask, SIGINT);
	sigaddset(&sga.sa_mask, SIGHUP);
	sigaddset(&sga.sa_mask, SIGUSR1);
	sga.sa_handler = my_handler;
	sga.sa_flags = 0;
	sigaction(SIGTERM, &sga, NULL);

	// block SIGINT/SIGTERM while handling SIGHUP
	sigemptyset(&sga.sa_mask);
	sigaddset(&sga.sa_mask, SIGINT);
	sigaddset(&sga.sa_mask, SIGTERM);
	sigaddset(&sga.sa_mask, SIGUSR1);
	sga.sa_handler = my_handler;
	sga.sa_flags = 0;
	sigaction(SIGHUP, &sga, NULL);

	// block SIGINT/SIGTERM/SIGHUP while handling SIGUSR1
	sigemptyset(&sga.sa_mask);
	sigaddset(&sga.sa_mask, SIGINT);
	sigaddset(&sga.sa_mask, SIGTERM);
	sigaddset(&sga.sa_mask, SIGHUP);
	sga.sa_handler = my_handler;
	sga.sa_flags = 0;
	sigaction(SIGUSR1, &sga, NULL);
}

void frontend(void) {
	assert(arg_id == -1);
	assert(arg_resolvers <= RESOLVERS_CNT_MAX && arg_resolvers >= RESOLVERS_CNT_MIN);

	install_signal_handler();

	// check for different DNS servers running on this address:port
	proxy_addr = (arg_proxy_addr) ? arg_proxy_addr : DEFAULT_PROXY_ADDR;
	int slocal = net_local_dns_socket(0); // no address/port reuse
	if (slocal == -1) {
		fprintf(stderr, "Error: a different DNS server is already running on %s:53\n", proxy_addr);
		exit(1);
	}
	close(slocal); // close the socket
	logprintf("listening on %s\n", proxy_addr);

	// init resolver structures
	memset(w, 0, sizeof(w));

	// create the process file in /run/fdns directory
	procs_add();

	// enable /dev/shm/fdns-stats - create the file if it doesn't exist
	shmem_open(1, proxy_addr);

	int shm_keepalive_cnt = 0;

	// keepalive autodetection
	DnsServer *srv = server_get();
	assert(srv);
	if (srv->keepalive < DNS_KEEPALIVE_DEFAULT && !arg_keepalive)
		arg_keepalive = srv->keepalive;

	// start resolvers
	int i;
	for (i = 0; i < arg_resolvers; i++)
		start_sandbox(i);
	// keepalive autodetection
	restarting = 1;

	// handle SIGCHLD in pselect loop
	sigset_t sigmask, empty_mask;
	struct sigaction sa;

	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &sigmask, NULL) == -1)
		errExit("sigprocmask");

	sa.sa_flags = 0;
	sa.sa_handler = child_sig_handler;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGCHLD, &sa, NULL) == -1)
		errExit("sigaction");

	sigemptyset(&empty_mask);

	struct timespec t = { 1, 0};	// one second timeout
	time_t timestamp = time(NULL);	// detect the computer going to sleep in order to reinitialize SSL connections
	int send_keepalive_cnt = 0;
	while (1) {
		fd_set rset;
		FD_ZERO(&rset);
		int fdmax = 0;
		for (i = 0; i < arg_resolvers; i++) {
			FD_SET(w[i].fd[0], &rset);
			fdmax = (fdmax < w[i].fd[0]) ? w[i].fd[0] : fdmax;
		}
		fdmax++;

		int rv = pselect(fdmax, &rset, NULL, NULL, &t, &empty_mask);
		if (rv == -1) {
			if (errno == EINTR) {
				// select() man page reads:
				// "... the sets and  timeout become undefined, so
				// do not rely on their contents after an error. "
				t.tv_sec = 1;
				t.tv_nsec = 0;
				continue;
			}
			printf("***\n");
		}
		else if (rv == 0) {
			time_t ts = time(NULL);
			time_t delta = ts - timestamp;
			int i;

			// clean shared memory logs
			shm_timeout();

			// decrease keepalive wait when coming out of sleep/hibernation
			if (delta > OUT_OF_SLEEP) {
				for (i = 0; i < arg_resolvers; i++) {
					if (w[i].keepalive > RESOLVER_KEEPALIVE_AFTER_SLEEP)
						w[i].keepalive = RESOLVER_KEEPALIVE_AFTER_SLEEP;
				}
			}



			// restart resolvers if the keepalive time expired
			for (i = 0; i < arg_resolvers; i++) {
				if (--w[i].keepalive <= 0) {
					logprintf("Restarting resolver process %d (pid %d)\n", i, w[i].pid);
					kill(w[i].pid, SIGKILL);
					int status;
					waitpid(w[i].pid, &status, 0);
					start_sandbox(i);
				}
			}

			// send a shared memory keepalive
			if (++shm_keepalive_cnt > SHMEM_KEEPALIVE) {
				shmem_keepalive();
				shm_keepalive_cnt = 0;
			}

			if (++send_keepalive_cnt >= RESOLVER_KEEPALIVE_TIMER) {
				send_keepalive_cnt = 0;
				for (i = 0; i < arg_resolvers; i++) {
					int rv = write(w[i].fd[0], "keepalive", 10);
					(void) rv; // todo: error recovery
				}
			}

			t.tv_sec = 1;
			t.tv_nsec = 0;
			timestamp = time(NULL);
		}
		else if (got_SIGCHLD) {
			pid_t pid = -1;;
			int status;
			got_SIGCHLD = 0;

			// find a dead resolver
			int i;
			for (i = 0; i < arg_resolvers; i++) {
				pid = waitpid(w[i].pid, &status, WNOHANG);
				if (pid == w[i].pid) {
					logprintf("Error: resolver %d (pid %u) terminated, restarting...\n", i, pid);
					kill(pid, SIGTERM); // just in case
					start_sandbox(i);
				}
			}
		}
		else {
			for (i = 0; i < arg_resolvers; i++) {
				if (FD_ISSET(w[i].fd[0], &rset)) {
					LogMsg msg;
					ssize_t len = read(w[i].fd[0], &msg, sizeof(LogMsg));
					if (len == -1) // todo: parse EINTR
						errExit("read");

					// check length
					if (len != msg.h.len) {
						logprintf("Error: log message with an invalid length\n");
						continue;
					}

					// parse the incoming message
					msg.buf[len - sizeof(LogMsgHeader)] = '\0';

					// parse incoming message
					if (strncmp(msg.buf, "Stats: ", 7) == 0) {
						Stats s;
						int k;
						sscanf(msg.buf, "Stats: rx %u, dropped %u, fallback %u, cached %u, fwd %u, qps %u, %lf %d",
						       &s.rx,
						       &s.drop,
						       &s.fallback,
						       &s.cached,
						       &s.fwd,
						       &s.qps_drop,
						       &s.query_time,
						       &k);
						// keepalive autodetection
						srv->keepalive = (k > srv->keepalive)? k: srv->keepalive;

						// calculate global stats
						stats.rx += s.rx;
						stats.drop += s.drop;
						stats.fallback += s.fallback;
						stats.cached += s.cached;
						stats.fwd += s.fwd;
						stats.qps_drop += s.qps_drop;
						if (s.query_time && stats.query_time == 0)
							stats.query_time = s.query_time;
						else if (s.query_time) {
							// exponantial moving average (EMA) for a window of 10 successive queries
							// multiplier = 2 / (window + 1) = 2 / [10 + 1] = 0.18
							// EMA = last_query x multiplier +  (previous_EMA) x (1 - multiplier)
							stats.query_time = (s.query_time * 0.18) + (stats.query_time * 0.82);
						}
						stats.restart_cnt = restart_cnt;
						shmem_store_stats(proxy_addr);
					}
					else if (strncmp(msg.buf, "Request: ", 9) == 0) {
						print_time();
						printf("(%d) %s", i, msg.buf + 9);
						shmem_store_log(msg.buf + 9);
					}
					else if (strncmp(msg.buf, "resolver keepalive", 16) == 0)
						w[i].keepalive = RESOLVER_KEEPALIVE_SHUTDOWN;
					else {
						if (strncmp(msg.buf, "SSL connection opened", 21) == 0) {
							stats.encrypted[i] = 1;
							// extract ip address
							if (strncmp(msg.buf + 21, " to ", 4) == 0) {
								uint32_t ip = 0;
								if (0 == atoip(msg.buf + 25, &ip))
									stats.peer_ip[i] = ip;
							}
							stats.restart_cnt = restart_cnt;
							shmem_store_stats(proxy_addr);
						}
						else if (strncmp(msg.buf, "SSL connection closed", 21) == 0) {
							stats.encrypted[i] = 0;;
							stats.peer_ip[i] = 0;
							stats.restart_cnt = restart_cnt;
							shmem_store_stats(proxy_addr);
						}

						char *tmp;
						if (asprintf(&tmp, "(%d) %s", i, msg.buf) == -1)
							errExit("asprintf");
						shmem_store_log(tmp);

						// trick logprintf in printing the timestamp
						arg_id = i;
						logprintf("%s", tmp);
						arg_id = -1;
						free(tmp);
					}

					// respond with a keepalive
					int rv = write(w[i].fd[0], "keepalive", 10);
					(void) rv; // todo: error recovery

					fflush(0);
				}
			}
		}
		fflush(0);
	}
}
