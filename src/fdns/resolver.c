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
#include <sys/time.h>
#include <sys/prctl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>

static uint8_t buf[MAXBUF];

void resolver(void) {
	// we get a SIGPIPE if we write to a socket closed by the other end;
	// ignoring it - standard practice for TCP servers
	signal(SIGPIPE, SIG_IGN);

	// load the drop list
	if (!arg_nofilter)
		filter_load_all_lists();

	// connect SSL/DNS server
	ssl_init();
	if (ssl_test_open())
		ssl_open();
	else
		rlogprintf("Warning: resolver starting in fallback mode\n");

	// start the local DNS server on 127.0.0.1 only
	// in order to mitigate DDoS amplification attacks
	int slocal = net_local_dns_socket(1);
	if (slocal == -1) {
		fprintf(stderr, "Error: cannot bind to port 53\n");
		exit(1);
	}

	// security
#ifdef HAVE_GCOV
	__gcov_flush();
#else
	int rv = seccomp_load_filter_list();
	chroot_drop_privs("nobody");
	if (rv)
		seccomp_resolver();
#endif

	// Remote dns server fallback server
	int sfallback[MAX_FALLBACK_POOL] = {0};
	struct sockaddr_in addr_fallback;
	int i;
	for (i = 0; i < MAX_FALLBACK_POOL; i++)
		sfallback[i] = net_remote_dns_socket(&addr_fallback, arg_fallback_server);
	socklen_t addr_fallback_len = sizeof(addr_fallback);

	// initialize database - we use this database for the fallback server
	// in order to match DNS responses and DNS requests
	dnsdb_init();

	fflush(0);
	int resolver_keepalive_cnt = (RESOLVER_KEEPALIVE_TIMER * arg_id) / arg_resolvers;
	DnsServer *srv = server_get();
	assert(srv);
	int dns_keepalive_cnt = dns_current_keepalive();
	int console_printout_cnt = CONSOLE_PRINTOUT_TIMER;

	console_printout_cnt = (CONSOLE_PRINTOUT_TIMER * arg_id) / arg_resolvers;
	int dns_over_udp = 0;

	struct timeval t = { 1, 0};	// one second timeout
	time_t timestamp = time(NULL);	// detect the computer going to sleep in order to reinitialize SSL connections
	int frontend_keepalive_cnt = 0;
	int query_second = 0;
	while (1) {
#ifdef HAVE_GCOV
		__gcov_flush();
#endif
		fd_set fds;
		FD_ZERO(&fds);
		// UDP sockets
		FD_SET(slocal, &fds);
		int nfds = slocal;
		for (i = 0; i < MAX_FALLBACK_POOL; i++) {
			FD_SET(sfallback[i], &fds);
			nfds = ((nfds > sfallback[i]) ? nfds : sfallback[i]);
		}
		// forwarding sockets
		Forwarder *f = fwd_list;
		while (f) {
			FD_SET(f->sock, &fds);
			nfds = (f->sock > nfds) ? f->sock : nfds;
			f = f->next;
		}

		// communication with the frontend process
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
			// attempting to detect the computer coming out of sleep mode
			time_t ts = time(NULL);
			if (ts - timestamp > OUT_OF_SLEEP) {
				// send a keepalive to frontend in order not to get killed
				rlogprintf("resolver keepalive\n");
				resolver_keepalive_cnt = RESOLVER_KEEPALIVE_TIMER;
				// assume the frontend is still alive
				frontend_keepalive_cnt = 0;
				// clear DNS cache
				cache_init();
				// force a HTTP2 PING - if the connection is already down, it will close SSL
				dns_keepalive();
			}
			timestamp = ts;
			query_second = 0;

			// processing stats
			if (--console_printout_cnt <= 0) {
				if (stats.changed) {
					if (stats.ssl_pkts_cnt == 0)
						stats.ssl_pkts_cnt = 1;
					rlogprintf("Stats: rx %u, dropped %u, fallback %u, cached %u, fwd %u, %.02lf %d\n",
						   stats.rx, stats.drop, stats.fallback, stats.cached, stats.fwd,
						   stats.ssl_pkts_timetrace / stats.ssl_pkts_cnt,
						   dns_current_keepalive());
					stats.changed = 0;
					memset(&stats, 0, sizeof(stats));
				}
				console_printout_cnt = CONSOLE_PRINTOUT_TIMER;
			}

			// ssl keepalive:
			// if any incoming data, probably is the session going down
			if (ssl_status_check())
				transport->exchange(buf, 0);

			if (--dns_keepalive_cnt <= 0)  {
				dns_keepalive();
				dns_keepalive_cnt = dns_current_keepalive();
				print_time();
				printf("(%d) keepalive %d\n", arg_id, dns_keepalive_cnt);
				stats.changed = 1;
			}

			// send resolver keepalive
			if (--resolver_keepalive_cnt <= 0)  {
				if (ssl_state == SSL_OPEN)
					rlogprintf("resolver keepalive\n");
				resolver_keepalive_cnt = RESOLVER_KEEPALIVE_TIMER;
			}

			// check frontend keepalive
			if (++frontend_keepalive_cnt >= FRONTEND_KEEPALIVE_SHUTDOWN) {
				fprintf(stderr, "Error: resolver process going down, frontend keepalive failed\n");
				exit(1);
			}

			cache_timeout();
			print_cache();
			t.tv_sec = 1;
			t.tv_usec = 0;
			continue;
		}

		//***********************************************
		// frontend keepalive
		//***********************************************
		if (FD_ISSET(arg_fd, &fds)) {
			int sz = read(arg_fd, buf, MAXBUF);
			(void) sz; // todo: error recovery
			frontend_keepalive_cnt = 0;
			continue;
		}

		//***********************************************
		// data coming from remote DNS fallback server
		//***********************************************
		for (i = 0; i < MAX_FALLBACK_POOL; i++) {
			if (FD_ISSET(sfallback[i], &fds)) {
				struct sockaddr_in remote;
				memset(&remote, 0, sizeof(remote));
				socklen_t remote_len = sizeof(struct sockaddr_in);
				ssize_t len = recvfrom(sfallback[i], buf, MAXBUF, 0, (struct sockaddr *) &remote, &remote_len);
				if (len == -1) // todo: parse errno - EINTR
					errExit("recvfrom");
				if(arg_debug) {
					print_time();
					printf("(%d) rx fallback %d len %d\n", arg_id, i, (int) len);
				}

				// check remote ip address - RFC 5452 (todo - more matches)
				if (remote.sin_addr.s_addr != addr_fallback.sin_addr.s_addr) {
					rlogprintf("Error: wrong IP address for fallback %d response: %d.%d.%d.%d\n",
						   i, PRINT_IP(ntohs(remote.sin_addr.s_addr)));
					continue;
				}
				if (remote.sin_port != addr_fallback.sin_port) {
					rlogprintf("Error: wrong UDP port for fallback %d response: %d\n",
						   i, ntohs(remote.sin_port));
					continue;
				}

				struct sockaddr_in *addr_client = dnsdb_retrieve(i, buf);
				if (!addr_client) {
					rlogprintf("Warning: DNS over UDP request timeout\n");
					continue;
				}
				socklen_t addr_client_len = sizeof(struct sockaddr_in);

				// send the data to the local client
				errno = 0;
				len = sendto(slocal, buf, len, 0, (struct sockaddr *) addr_client, addr_client_len);
				if(arg_debug) {
					print_time();
					printf("(%d) tx local len %d, errno %d\n", arg_id, (int) len, errno);
				}
				if (len == -1) // todo: parse errno - EAGAIN
					errExit("sendto");
				continue;
			}
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
			if (++query_second > arg_qps)
				continue;

			if(arg_debug) {
				print_time();
				printf("(%d) rx local packet len %d\n", arg_id, (int) len);
			}
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
				if(arg_debug) {
					print_time();
					printf("(%d) tx local len %d, errno %d\n", arg_id, (int) len, errno);
				}
				if (len == -1) // todo: parse errno - EAGAIN
					errExit("sendto");

				continue;
			}

			else if (dest == DEST_FORWARDING) {
				assert(fwd_active);
				errno = 0;
				len = sendto(fwd_active->sock, buf, len, 0, (struct sockaddr *) &fwd_active->saddr, fwd_active->slen);
				if(arg_debug) {
					print_time();
					printf("(%d) tx forwarding len %d, errno %d\n", arg_id, (int) len, errno);
				}
				if (len == -1) // todo: parse errno - EAGAIN
					errExit("sendto");

				// store the incoming request in the database
				dnsdb_store(0, buf, &addr_client);
				fwd_active = NULL;
#ifdef HAVE_GCOV
				__gcov_flush();
#endif
				continue;
			}

			// attempt to send the data over SSL; the request is not stored in the database
			assert(dest == DEST_SSL);
			int ssl_len;
			timetrace_start();
			if (ssl_state == SSL_OPEN)
				ssl_len = dns_query(buf, len);

			// a HTTP error from SSL, with no DNS data comming back
			if (ssl_state == SSL_OPEN && ssl_len == 0) {
				if (arg_debug) {
					print_time();
					printf("(%d) no data received, dropping...\n", arg_id);
				}
				continue;	// drop the packet
			}
			// good packet from SSL
			else if (ssl_state == SSL_OPEN && ssl_len > 0) {
				stats.ssl_pkts_timetrace += timetrace_end();
				stats.ssl_pkts_cnt++;
				dns_over_udp = 0;

				// we got a response, send the data back to the client
				len = ssl_len;
				errno = 0;
				len = sendto(slocal, buf, len, 0, (struct sockaddr *) &addr_client, addr_client_len);
				if(arg_debug) {
					print_time();
					printf("(%d) tx local len %d, errno %d\n", arg_id, (int) len, errno);
				}
				if (len == -1) // todo: parse errno - EAGAIN
					errExit("sendto");
				else
					dns_keepalive_cnt = dns_current_keepalive();
			}
			// send the data to the remote fallback server; store the request in the database
			else {
				stats.fallback++;
				stats.changed = 1;
				if (!dns_over_udp)
					rlogprintf("Warning: sending requests in clear\n");
				dns_over_udp = 1;
				errno = 0;
				i = rand() % MAX_FALLBACK_POOL;
				len = sendto(sfallback[i], buf, len, 0, (struct sockaddr *) &addr_fallback, addr_fallback_len);
				if(arg_debug) {
					print_time();
					printf("(%d) tx fallback %d len %d, errno %d\n", arg_id, i, (int) len, errno);
				}
				if (len == -1) // todo: parse errno - EAGAIN
					errExit("sendto");

				// store the incoming request in the database
				dnsdb_store(i, buf, &addr_client);
			}
			continue;
		}

		//***********************************************
		// data coming from a forwarding DNS server
		//***********************************************
		if (fwd_list) {
			Forwarder *f = fwd_list;
			while (f) {
				if (FD_ISSET(f->sock, &fds)) {
					struct sockaddr_in remote;
					memset(&remote, 0, sizeof(remote));
					socklen_t remote_len = sizeof(struct sockaddr_in);
					ssize_t len = recvfrom(f->sock, buf, MAXBUF, 0, (struct sockaddr *) &remote, &remote_len);
					if (len == -1) // todo: parse errno - EINTR
						errExit("recvfrom");
					if(arg_debug) {
						print_time();
						printf("(%d) rx forwarding len %d\n", arg_id, (int) len);
					}

					// check remote ip address
					if (remote.sin_addr.s_addr != f->saddr.sin_addr.s_addr) {
						rlogprintf("Warning: wrong IP address for fwd response: %d.%d.%d.%d\n",
							   PRINT_IP(ntohl(remote.sin_addr.s_addr)));
						continue;
					}

					struct sockaddr_in *addr_client = dnsdb_retrieve(0, buf);
					if (!addr_client) {
						rlogprintf("Warning: fwd DNS over UDP request timeout\n");
						continue;
					}
					socklen_t addr_client_len = sizeof(struct sockaddr_in);

					// send the data to the local client
					errno = 0;
					len = sendto(slocal, buf, len, 0, (struct sockaddr *) addr_client, addr_client_len);
					if(arg_debug) {
						print_time();
						printf("(%d) tx local len %d, errno %d\n", arg_id, (int) len, errno);
					}
					if (len == -1) // todo: parse errno - EAGAIN
						errExit("sendto");
				}

				f = f->next;
#ifdef HAVE_GCOV
				__gcov_flush();
#endif
			}
			continue;
		}

	}
}

