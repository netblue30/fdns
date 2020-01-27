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
#include "fdns.h"
#include "timetrace.h"
#include <sys/time.h>
#include <sys/prctl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>

static uint8_t buf[MAXBUF];

void worker(void) {
	// we get a SIGPIPE if we write to a socket closed by the other end;
	// ignoring it - standard practice for TCP servers
	signal(SIGPIPE, SIG_IGN);

	// load the drop list
	if (!arg_nofilter)
		filter_load_all_lists();

	// connect SSL/DNS server
	ssl_init();
	ssl_open();
	ssl_keepalive();

	// start the local DNS server on 127.0.0.1 only
	// in order to mitigate DDoS amplification attacks
	int slocal = net_local_dns_socket();
	assert(slocal > 0);

	// security
	int rv = seccomp_load_filter_list();
	chroot_drop_privs("nobody");
	if (rv)
		seccomp_worker();

	// Remote dns server fallback server
	struct sockaddr_in addr_fallback;
	int sremote = net_remote_dns_socket(&addr_fallback, "9.9.9.9");
	socklen_t addr_fallback_len = sizeof(addr_fallback);

	// initialize database - we use this database for the fallback server
	// in order to match DNS responses and DNS requests
	dnsdb_init();

	fflush(0);
	int worker_keepalive_cnt = (WORKER_KEEPALIVE_TIMER * arg_id) / arg_workers;
	DnsServer *srv = server_get();
	assert(srv);
	int ssl_keepalive_timer = srv->ssl_keepalive;
	int ssl_keepalive_cnt = ssl_keepalive_timer;
	int console_printout_cnt = CONSOLE_PRINTOUT_TIMER;
	int ssl_reopen_cnt = SSL_REOPEN_TIMER;

	console_printout_cnt = (CONSOLE_PRINTOUT_TIMER * arg_id) / arg_workers;
	int dns_over_udp = 0;

	struct timeval t = { 1, 0};	// one second timeout
	time_t timestamp = time(NULL);	// detect the computer going to sleep in order to reinitialize SSL connections
	int parent_keepalive_cnt = 0;
	while (1) {
		fd_set fds;
		FD_ZERO(&fds);
		// UDP sockets
		FD_SET(slocal, &fds);
		FD_SET(sremote, &fds);
		int nfds = ((slocal > sremote) ? slocal : sremote);
		// forwarding sockets
		Forwarder *f = fwd;
		while (f) {
			FD_SET(f->sock, &fds);
			nfds = (f->sock > nfds) ? f->sock : nfds;
			f = f->next;
		}
		// communication with parent
		FD_SET(arg_fd, &fds);
		nfds = (arg_fd > nfds) ? arg_fd : nfds;
		nfds += 1;

		errno = 0;
		int rv = select(nfds, &fds, NULL, NULL, &t);
		if (rv == -1) {
			if (errno == EINTR) {
				// select() man page reads:
				// "... the sets and  timeout become undefined, so
				// do not rely on their contents after an error. "
				t.tv_sec = 1;
				t.tv_usec = 0;
				continue;
			}
			errExit("select");
		}

		//***********************************************
		// one second timeout
		//***********************************************
		else if (rv == 0) {
			time_t ts = time(NULL);
			if (ts - timestamp > OUT_OF_SLEEP) {
				rlogprintf("Suspend detected, restarting SSL connection\n");
				cache_init();
				ssl_close();
				ssl_open();
			}
			timestamp = ts;

			// processing stats
			if (--console_printout_cnt <= 0) {
				if (stats.changed) {
					if (stats.ssl_pkts_cnt == 0)
						stats.ssl_pkts_cnt = 1;
					rlogprintf("Stats: rx %u, dropped %u, fallback %u, cached %u, fwd %u, %.02lf\n",
						   stats.rx, stats.drop, stats.fallback, stats.cached, stats.fwd,
						   stats.ssl_pkts_timetrace / stats.ssl_pkts_cnt);
					stats.changed = 0;
					memset(&stats, 0, sizeof(stats));
				}
				console_printout_cnt = CONSOLE_PRINTOUT_TIMER;
			}

			// reopen SSL connection
			if (ssl_state == SSL_CLOSED) {
				if (--ssl_reopen_cnt <= 0) {
					ssl_open();
					ssl_reopen_cnt = SSL_REOPEN_TIMER;
				}
			}

			// ssl keepalive:
			// if any incoming data, probably is the session going down - force a keepalive
			if (ssl_status_check())
				ssl_keepalive_cnt = 0;
			if (--ssl_keepalive_cnt <= 0)  {
				ssl_keepalive();
				ssl_keepalive_cnt = ssl_keepalive_timer;
			}

			// send worker keepalive
			if (--worker_keepalive_cnt <= 0)  {
				rlogprintf("worker keepalive\n");
				worker_keepalive_cnt = WORKER_KEEPALIVE_TIMER;
			}

			// check parent keepalive
			if (++parent_keepalive_cnt >= PARENT_KEEPALIVE_SHUTDOWN) {
				fprintf(stderr, "Error: worker process going down, parent keepalive failed\n");
				exit(1);
			}

			// database cleanup
			dnsdb_timeout();
			cache_timeout();
			t.tv_sec = 1;
			t.tv_usec = 0;
			continue;
		}

		//***********************************************
		// parent keepalive
		//***********************************************
		if (FD_ISSET(arg_fd, &fds)) {
			int sz = read(arg_fd, buf, MAXBUF);
			(void) sz; // todo: error recovery
			parent_keepalive_cnt = 0;
			continue;
		}

		//***********************************************
		// data coming from remote DNS fallback server
		//***********************************************
		if (FD_ISSET(sremote, &fds)) {
			struct sockaddr_in remote;
			memset(&remote, 0, sizeof(remote));
			socklen_t remote_len = sizeof(struct sockaddr_in);
			ssize_t len = recvfrom(sremote, buf, MAXBUF, 0, (struct sockaddr *) &remote, &remote_len);
			if (len == -1) // todo: parse errno - EINTR
				errExit("recvfrom");
			if(arg_debug)
				printf("rx remote packet len %ld\n", len);

			// check remote ip address - RFC 5452 (todo - more matches)
			if (remote.sin_addr.s_addr != addr_fallback.sin_addr.s_addr) {
				rlogprintf("Error: wrong IP address for fallback response: %d.%d.%d.%d\n",
					   PRINT_IP(ntohs(remote.sin_addr.s_addr)));
				continue;
			}
			if (remote.sin_port != addr_fallback.sin_port) {
				rlogprintf("Error: wrong UDP port for fallback response: %d\n",
					   PRINT_IP(ntohs(remote.sin_port)));
				continue;
			}

			struct sockaddr_in *addr_client = dnsdb_retrieve(buf);
			if (!addr_client) {
				rlogprintf("Warning: DNS over UDP request timeout\n");
				continue;
			}
			socklen_t addr_client_len = sizeof(struct sockaddr_in);

			// send the data to the local client
			errno = 0;
			len = sendto(slocal, buf, len, 0, (struct sockaddr *) addr_client, addr_client_len);
			if(arg_debug)
				printf("len %ld, errno %d\n", len, errno);
			if (len == -1) // todo: parse errno - EAGAIN
				errExit("sendto");
			continue;
		}


		//***********************************************
		// data coming from the local network
		//***********************************************
		if (FD_ISSET(slocal, &fds)) {
			struct sockaddr_in addr_client;
			socklen_t addr_client_len = sizeof(struct sockaddr_in);

			ssize_t len = recvfrom(slocal, buf, MAXBUF, 0, (struct sockaddr *) &addr_client, &addr_client_len);
			if (len == -1) // todo: parse errno - EAGAIN
				errExit("recvfrom");
			if(arg_debug)
				printf("rx local packet len %ld\n", len);
			stats.rx++;
			stats.changed = 1;

			// filter incoming requests
			DnsDestination dest;
			uint8_t *r = dns_parser(buf, &len, &dest);

			assert(dest < DEST_MAX);
			if (dest == DEST_DROP) {
				stats.drop++;
				continue;
			}

			else if (dest == DEST_LOCAL) {
				assert(r);

				// send the loopback response
				len = sendto(slocal, r, len, 0, (struct sockaddr *) &addr_client, addr_client_len);
				if(arg_debug)
					printf("len %ld, errno %d\n", len, errno);
				if (len == -1) // todo: parse errno - EAGAIN
					errExit("sendto");

				continue;
			}

			else if (dest == DEST_FORWARDING) {
				assert(fwd_active);
				errno = 0;
				len = sendto(fwd_active->sock, buf, len, 0, (struct sockaddr *) &fwd_active->saddr, fwd_active->slen);
				if(arg_debug)
					printf("len %ld, errno %d\n", len, errno);
				if (len == -1) // todo: parse errno - EAGAIN
					errExit("sendto");

				// store the incoming request in the database
				dnsdb_store(buf, &addr_client);
				fwd_active = NULL;
				continue;
			}

			// attempt to send the data over SSL; the request is not stored in the database
			assert(dest == DEST_SSL);
			int ssl_len;
			timetrace_start();
			if (ssl_state == SSL_OPEN)
				ssl_len = ssl_dns(buf, len);

			// a HTTP error from SSL, with no DNS data comming back
			if (ssl_state == SSL_OPEN && ssl_len == 0)
				continue;	// drop the packet
			// good packet from SSL
			else if (ssl_state == SSL_OPEN && ssl_len > 0) {
				stats.ssl_pkts_timetrace += timetrace_end();
				stats.ssl_pkts_cnt++;
				dns_over_udp = 0;

				// we got a response, send the data back to the client
				len = ssl_len;
				errno = 0;
				len = sendto(slocal, buf, len, 0, (struct sockaddr *) &addr_client, addr_client_len);
				if(arg_debug)
					printf("len %ld, errno %d\n", len, errno);
				if (len == -1) // todo: parse errno - EAGAIN
					errExit("sendto");
				else
					ssl_keepalive_cnt = ssl_keepalive_timer;
			}
			// send the data to the remote fallback server; store the request in the database
			else {
				stats.fallback++;
				stats.changed = 1;
				if (!dns_over_udp)
					rlogprintf("Warning: sending requests in clear\n");
				dns_over_udp = 1;
				errno = 0;
				len = sendto(sremote, buf, len, 0, (struct sockaddr *) &addr_fallback, addr_fallback_len);
				if(arg_debug)
					printf("len %ld, errno %d\n", len, errno);
				if (len == -1) // todo: parse errno - EAGAIN
					errExit("sendto");

				// store the incoming request in the database
				dnsdb_store(buf, &addr_client);
			}
			continue;
		}

		//***********************************************
		// data coming from a forwarding DNS server
		//***********************************************
		if (fwd) {
			Forwarder *f = fwd;
			while (f) {
				if (FD_ISSET(f->sock, &fds)) {
					struct sockaddr_in remote;
					memset(&remote, 0, sizeof(remote));
					socklen_t remote_len = sizeof(struct sockaddr_in);
					ssize_t len = recvfrom(f->sock, buf, MAXBUF, 0, (struct sockaddr *) &remote, &remote_len);
					if (len == -1) // todo: parse errno - EINTR
						errExit("recvfrom");
					if(arg_debug)
						printf("rx remote packet len %ld\n", len);

					// check remote ip address
					if (remote.sin_addr.s_addr != f->saddr.sin_addr.s_addr) {
						rlogprintf("Warning: wrong IP address for fwd response: %d.%d.%d.%d\n",
							   PRINT_IP(ntohl(remote.sin_addr.s_addr)));
						continue;
					}

					struct sockaddr_in *addr_client = dnsdb_retrieve(buf);
					if (!addr_client) {
						rlogprintf("Warning: fwd DNS over UDP request timeout\n");
						continue;
					}
					socklen_t addr_client_len = sizeof(struct sockaddr_in);

					// send the data to the local client
					errno = 0;
					len = sendto(slocal, buf, len, 0, (struct sockaddr *) addr_client, addr_client_len);
					if(arg_debug)
						printf("len %ld, errno %d\n", len, errno);
					if (len == -1) // todo: parse errno - EAGAIN
						errExit("sendto");
				}

				f = f->next;
			}
			continue;
		}

	}
}

