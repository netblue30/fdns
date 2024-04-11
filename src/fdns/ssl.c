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
#include "lint.h"
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#	include <openssl/bioerr.h>
#endif
#include <netdb.h>
#include <sys/wait.h>
#include <sys/socket.h>

SSLState ssl_state = SSL_CLOSED;
static BIO *bio = NULL;
static SSL_CTX *ctx = NULL;
static SSL *ssl = NULL;

// test SSL connection in a different process, in order to start directly
// in the fallback server if necessary; logging is disabled in this case
// return 1 if ok, 0 if error
int ssl_test_open(void)  {
	if (fallback_only)
		return 1;

	pid_t child = fork();
	if (child == 0) { // child
		log_disable();
		ssl_open();
		if (ssl_state == SSL_CLOSED)
			exit(1);
		ssl_close();
		exit(0);
	}

	// wait for the child to finish
	int i = 0;
	do {
		int status = 0;
		pid_t rv = waitpid(child, &status, WNOHANG);
		if (rv == child) {
			if (WIFEXITED(status) && WEXITSTATUS(status) == 1) {
				printf(" Error: SSL connect test failed\n");
				fflush(0);
				return 0;
			}
			break;
		}

		sleep(1);
		i++;
	}
	while (i < 5); // 5 seconds test

	kill(child, SIGKILL);
	usleep(10000);

	if (i >= 5)
		return 0;
	return 1;
}

static void ssl_alert_callback(const SSL *s, int where, int ret) {
	const char *str;
	int w = where & ~SSL_ST_MASK;

	if (w & SSL_ST_CONNECT)
		return;
	else if (w & SSL_ST_ACCEPT)
		str = "SSL_accept";
	else
		str = "undefined";

	if (where & SSL_CB_LOOP) {
		printf("(%d) Alert: %s:%s\n", arg_id, str, SSL_state_string_long(s));
		fflush(0);
	}
	else if (where & SSL_CB_ALERT) {
		str = (where & SSL_CB_READ) ? "read" : "write";
		printf("(%d) Alert: SSL3 alert %s:%s:%s\n", arg_id, str,
			   SSL_alert_type_string_long(ret),
			   SSL_alert_desc_string_long(ret));
		fflush(0);
	}
	else if (where & SSL_CB_EXIT) {
		if (ret == 0) {
			printf("(%d) Alert: %s:failed in %s\n",
				   arg_id, str, SSL_state_string_long(s));
			fflush(0);
		}
		else if (ret < 0) {
			printf("(%d) Alert: %s:error in %s\n",
				   arg_id, str, SSL_state_string_long(s));
			fflush(0);
		}
	}
}

int ssl_status_check(void) {
	if (ssl == NULL)
		return 0;

	fd_set readfds;
	FD_ZERO(&readfds);
	int fd = SSL_get_fd(ssl);
	FD_SET(fd, &readfds);
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 1;

	int rv = select(fd + 1, &readfds, NULL, NULL, &timeout);
	if (rv <= 0)
		return 0;

	if (FD_ISSET(fd, &readfds)) {
		printf("incoming data\n");
		return 1;
	}

	return 0;
}

void ssl_init(void) {
	SSL_load_error_strings();
	SSL_library_init();
	#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		/*
		* ERR_load_*(), ERR_func_error_string(), ERR_get_error_line(), ERR_get_error_line_data(), ERR_get_state()
		* OpenSSL now loads error strings automatically so these functions are not needed.
		* SEE: https://www.openssl.org/docs/manmaster/man7/migration_guide.html
		*/
	#else
		ERR_load_BIO_strings();
	#endif
	OpenSSL_add_all_algorithms();
}

static char *certlist[] = {
	"/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu
	"/etc/ssl/certs/ca-bundle.crt", // Fedora/CentOS
	"/usr/share/ca-certificates/ca-bundle.crt", // ALT
	NULL
};

char *get_cert_file(void) {
	if (arg_certfile)
		return arg_certfile;

	int i = 0;
	while (certlist[i]) {
		struct stat s;
		if (stat(certlist[i], &s) == 0)
			return certlist[i];
		i++;
	}

	return NULL;
}

void ssl_open(void) {
	assert(ssl_state == SSL_CLOSED);
	DnsServer *srv = server_get();
	assert(srv);

	if (fallback_only)
		return;

	if (arg_debug)
		printf("%d: opening ssl connection\n", arg_id);
	fflush(0);

	if (ctx == NULL) {
		ctx = SSL_CTX_new(TLS_client_method());
		char *certfile = get_cert_file();
		if (certfile == NULL) {
			if(! SSL_CTX_load_verify_locations(ctx, NULL, "/etc/ssl/certs")) {
				rlogprintf("Error: cannot find SSL certificates in /etc/ssl/certs\n");
				return;
			}
		}
		else {
			if(! SSL_CTX_load_verify_locations(ctx, certfile, NULL)) {
				rlogprintf("Error: cannot find SSL certificate %s\n", certfile);
				return;
			}
		}
	}

	if (arg_debug)
		printf("%d: arg_transport %s, srv->transport %s\n", arg_id, arg_transport, srv->transport);

	int dot = 0;
	if (arg_transport == NULL && srv->transport && strstr(srv->transport, "dot")) {
//		SSL_CTX_set_alpn_protos(ctx, (const unsigned char *)"\x03dot", 4);
		dns_set_transport("dot");
		dot = 1;
		if (arg_debug)
			printf("%d: No ALPN configured\n", arg_id);
	}
	else if (arg_transport == NULL) {
		// inform the server we prefer http2 over http/1.1
		SSL_CTX_set_alpn_protos(ctx, (const unsigned char *)"\x02h2\x08http/1.1", 12);
		if (arg_debug)
			printf("%d: Send ALPN h2, http/1.1\n", arg_id);

	}
	else if (strstr(arg_transport, "dot")) {
//		SSL_CTX_set_alpn_protos(ctx, (const unsigned char *)"\x03dot", 4);
		dns_set_transport("dot");
		dot = 1;
		if (arg_debug)
			printf("%d: No ALPN configured\n", arg_id);
	}
	else if (strstr(arg_transport, "h2")) {
		SSL_CTX_set_alpn_protos(ctx, (const unsigned char *)"\x02h2", 3);
		if (arg_debug)
			printf("%d: Send ALPN h2\n", arg_id);
	}
	else if (strstr(arg_transport, "http/1.1")) {
		// ALPN was mandated starting with h2, more likely a http/1.1 server won't implement ALPN
//		SSL_CTX_set_alpn_protos(ctx, (const unsigned char *)"\x08http/1.1", 9);
		if (arg_debug)
			printf("%d: No ALPN configured\n", arg_id);
	}
	else
		assert(0);

	fflush(0);
	bio = BIO_new_ssl_connect(ctx);
	BIO_get_ssl(bio, &ssl);
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	// set connection and SNI
	BIO_set_conn_hostname(bio, srv->address);
	if (srv->test_sni)
		; // testing sni: first try goes without any sni
	else if (srv->sni)
		SSL_set_tlsext_host_name(ssl, srv->host);
	else {
		; // no sni configured
	}

	if (arg_debug) {
		printf("%d: Connecting to the server %s\n", arg_id, srv->address);
		fflush(0);
	}
	if(BIO_do_connect(bio) <= 0) {
//		rlogprintf("Error: cannot connect SSL.\n");
		if (srv->test_sni) {
			// try again, this time with sni
			srv->test_sni = 0;
			srv->sni = 1;
			usleep(100000);
			return ssl_open();
		}

		return;
	}
	if (arg_debug) {
		printf("%d: Server connected!\n", arg_id);
		fflush(0);
	}

	if (arg_details && arg_id == -1)
		transport->print_url();
//		printf("   URL: https://%s%s\n", srv->host, srv->path);

	uint32_t ip;
	if (arg_details && arg_id == -1 && atoip(srv->address, &ip) == 0)
		printf("   Bootstrap IP address: %d.%d.%d.%d\n", PRINT_IP(ip));
	else if (arg_details && arg_id == -1 && arg_test_server) {
		char *domain  = strdup(srv->address);
		if (!domain)
			errExit("strdup");
		char *ptr = strchr(domain, ':');
		if (ptr) {
			*ptr = '\0';
			struct hostent *hp = gethostbyname(domain);
			if (hp) {
				int i=0;
				printf("   Bootstrap IP address: ");
				while ( hp -> h_addr_list[i] != NULL) {
					if (i != 0)
						printf(", ");
					printf( "%s", inet_ntoa( *( struct in_addr*)( hp -> h_addr_list[i])));
					i++;
				}
				printf("\n");
			}
		}
		free(domain);
	}
	char *portstr = strchr(srv->address, ':');
	if (portstr && arg_details && arg_id == -1)
		printf("   Port: %s\n", portstr + 1);

	int err;
	if ((err = SSL_get_verify_result(ssl)) != X509_V_OK) {
		if (arg_allow_self_signed_certs && err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
			printf("   Warning: %s\n", X509_verify_cert_error_string(err));
		else if (arg_allow_expired_certs && err == X509_V_ERR_CERT_HAS_EXPIRED)
			printf("   Warning: %s\n", X509_verify_cert_error_string(err));
		else {
			printf("   Error: %s\n", X509_verify_cert_error_string(err));
			rlogprintf("Error: %s\n", X509_verify_cert_error_string(err));
			return;
		}
	}

	// set alert callback
	SSL_set_info_callback(ssl, ssl_alert_callback);

	// check ALPN negotiation
	const char *ver = SSL_get_version(ssl);
	if (dot) {
		if (arg_details && arg_id == -1)
			printf("   %s, ", ver);
	}
	else {
		unsigned len = 0;
		const unsigned char *alpn;

		SSL_get0_alpn_selected(ssl, &alpn, &len);
		if (alpn == NULL) {
			if ((arg_details && arg_id == -1) || arg_debug)
				printf("   %s, ALPN not negotiated - assuming http/1.1\n", ver);
			dns_set_transport("http/1.1");
		}
		else if (len < 100) {
			char http[100 + 1];
			memcpy(http, alpn, len);
			http[len] = '\0';
			if (arg_details && arg_id == -1)
				printf("   %s, ALPN %s, ", ver, http);
			dns_set_transport(http);
		}
		else
			fprintf(stderr, "Error: invalid ALPN string of length %d\n", len);
		free((char *) alpn);
	}

	if (arg_details && arg_id == -1)
		printf("SNI %s\n", (srv->sni)? "yes": "no");

	ssl_state = SSL_OPEN;



	int fd = SSL_get_fd(ssl);
	struct sockaddr_in remote;
	memset(&remote, 0, sizeof(remote));
	socklen_t addrlen_remote = sizeof(remote);
	if (getpeername(fd, (struct sockaddr *) &remote, &addrlen_remote))
		rlogprintf("SSL connection opened\n");
	else {
		uint32_t ip = ntohl(remote.sin_addr.s_addr);
		rlogprintf("SSL connection opened to %d.%d.%d.%d\n", PRINT_IP(ip));
	}

	// transport connect
	transport->init();
	if (transport->connect() == -1)
		goto errh2;

	// ... followed by a simple query
	uint8_t msg[MAXBUF];
	unsigned len = transport->send_exampledotcom(msg);
	// some servers return NXDOMAIN for example.com
	if (len <= 0 || (lint_rx(msg, len) && lint_error() != DNSERR_NXDOMAIN))
		goto errh2;

	rlogprintf("%s transport up\n", dns_get_transport());
	return;

errh2:
	rlogprintf("%s transport failed\n", dns_get_transport());
	ssl_state = SSL_CLOSED;
	ssl_close();
}

void ssl_close(void) {
	if (ssl_state == SSL_OPEN)
		rlogprintf("SSL connection closed\n");
	transport->close();
	if (ssl) {
		SSL_shutdown(ssl);
		SSL_free(ssl);
	}

	ssl = NULL;
	ssl_state = SSL_CLOSED;

	// clear DNS cache
	cache_init();
}

int ssl_get_socket(void) {
	return SSL_get_fd(ssl);
}

int ssl_tx(uint8_t *buf, int len) {
	assert(buf);
	assert(len);

	if (ctx == NULL || ssl == NULL || ssl_state != SSL_OPEN)
		goto errout;

	assert(bio);
	assert(ctx);
	assert(ssl);

	if (arg_debug) {
		print_time();
		printf("(%d) ssl tx len %u\n", arg_id, len);
	}

	int lentx;
	if((lentx = BIO_write(bio, buf, len)) <= 0) {
		if(! BIO_should_retry(bio)) {
			rlogprintf("Error: failed SSL write, retval %d\n", lentx);
			goto errout;
		}
		if((lentx = BIO_write(bio, buf, len)) <= 0) {
			rlogprintf("Error: failed SSL write, retval %d\n", lentx);\
			goto errout;
		}
	}

	return lentx;
errout:
	ssl_close();
	return 0;
}

int ssl_rx(uint8_t *buf, int size) {
	assert(buf);
	if (size < 1 || ctx == NULL || ssl == NULL || ssl_state != SSL_OPEN)
		goto errout;

	int len = BIO_read(bio, buf, size - 1);
	if(len <= 0) {
		if(! BIO_should_retry(bio)) {
			rlogprintf("Error: failed SSL read, retval %d\n", len);
			goto errout;
		}
		len = BIO_read(bio, buf, MAXBUF);
		if(len <= 0) {
			rlogprintf("Error: failed SSL read, retval %d\n", len);
			goto errout;
		}
	}
	if (arg_debug) {
		print_time();
		printf("(%d) ssl rx len %u\n", arg_id, len);
	}
	buf[len] = '\0';

	return len;
errout:
	ssl_close();
	return 0;
}


// return 0 if nothing read, or error
int ssl_rx_timeout(uint8_t *buf, int size, int timeout) {
	fd_set readfds;
	FD_ZERO(&readfds);
	int fd = ssl_get_socket();
	FD_SET(fd, &readfds);
	struct timeval t;
	t.tv_sec = timeout;
	t.tv_usec = 0;

	int rv = select(fd + 1, &readfds, NULL, NULL, &t);
	if (rv <= 0)
		return 0;

	if (FD_ISSET(fd, &readfds))
		return ssl_rx(buf, size);

	return 0;
}





