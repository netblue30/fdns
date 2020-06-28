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
#include "lint.h"
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

SSLState ssl_state = SSL_CLOSED;
static BIO *bio = NULL;
static SSL_CTX *ctx = NULL;
static SSL *ssl = NULL;


static void ssl_alert_callback(const SSL *s, int where, int ret) {
	const char *str;
	int w = where & ~SSL_ST_MASK;

	if (w & SSL_ST_CONNECT)
		return;

	/*	if (w & SSL_ST_CONNECT)
			str = "SSL_connect";
		else */if (w & SSL_ST_ACCEPT)
		str = "SSL_accept";
	else
		str = "undefined";

	if (where & SSL_CB_LOOP) {
		printf("Alert: %s:%s\n", str, SSL_state_string_long(s));
		fflush(0);
	}
	else if (where & SSL_CB_ALERT) {
		str = (where & SSL_CB_READ) ? "read" : "write";
		printf("Alert: SSL3 alert %s:%s:%s\n", str,
			   SSL_alert_type_string_long(ret),
			   SSL_alert_desc_string_long(ret));
		fflush(0);
	}
	else if (where & SSL_CB_EXIT) {
		if (ret == 0) {
			printf("Alert: %s:failed in %s\n",
				   str, SSL_state_string_long(s));
			fflush(0);
		}
		else if (ret < 0) {
			printf("Alert: %s:error in %s\n",
				   str, SSL_state_string_long(s));
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
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
}

static char *certlist[] = {
	"/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu
	"/etc/ssl/certs/ca-bundle.crt", // Fedora/CentOS
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

	if (arg_fallback_only)
		return;

	if (ctx == NULL) {
		ctx = SSL_CTX_new(TLS_client_method());
		char *certfile = get_cert_file();
		if (certfile == NULL) {
			if(! SSL_CTX_load_verify_locations(ctx, NULL, "/etc/ssl/certs")) {
				rlogprintf("Error: cannot find SSL certificates in /etc/ssl/certs\n");
				exit(1);
			}
		}
		else {
			if(! SSL_CTX_load_verify_locations(ctx, certfile, NULL)) {
				rlogprintf("Error: cannot find SSL certificate %s\n", certfile);
				exit(1);
			}
		}
	}
	// inform the server we are using http2
	SSL_CTX_set_alpn_protos(ctx, (const unsigned char *)"\x02h2", 3);
#if 0
SSL_CTX_set_alpn_protos(ctx, (const unsigned char *)"\x02h2\x08http/1.1", 12);
#endif

	bio = BIO_new_ssl_connect(ctx);
	BIO_get_ssl(bio, &ssl);
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	// set connection and SNI
	BIO_set_conn_hostname(bio, srv->address);
	if (srv->sni)
		SSL_set_tlsext_host_name(ssl, srv->host);

	if(BIO_do_connect(bio) <= 0) {
//		rlogprintf("Error: cannot connect SSL.\n");
		return;
	}

	int val;
	if ((val = SSL_get_verify_result(ssl)) != X509_V_OK) {
		rlogprintf("Error: cannot handle certificate verification (error %d), shutting down...\n", val);
		return;	// give the program a chance to switch to fallback
	}

	// set alert callback
	SSL_set_info_callback(ssl, ssl_alert_callback);

#if 0
int lenp = 0;
const unsigned char *datap[100];
SSL_get0_alpn_selected(ssl, datap, &lenp);
assert(lenp == 2);
#endif

	ssl_state = SSL_OPEN;
	rlogprintf("SSL connection opened\n");

	// h2 connect
	h2_init();
	h2_connect();

	// ... followed by a simple query
	uint8_t msg[MAXBUF];
	int len = h2_send_exampledotcom(msg);
	// some servers return NXDOMAIN for example.com
	if (len == 0 || (lint_rx(msg, len) && lint_error() != DNSERR_NXDOMAIN)) {
		ssl_state = SSL_CLOSED;
		ssl_close();
		return;
	}
	rlogprintf("h2 connection opened\n");
}

void ssl_close(void) {
	h2_close();
	if (ssl) {
		SSL_shutdown(ssl);
		SSL_free(ssl);
	}

	ssl = NULL;
	ssl_state = SSL_CLOSED;
	rlogprintf("SSL connection closed\n");
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

	if (arg_debug_ssl || arg_debug) {
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

int ssl_rx(uint8_t *buf) {
	assert(buf);
	if (ctx == NULL || ssl == NULL || ssl_state != SSL_OPEN)
		goto errout;

	int len = BIO_read(bio, buf, MAXBUF);
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
	if (arg_debug_ssl || arg_debug) {
		print_time();
		printf("(%d) ssl rx len %u\n", arg_id, len);
	}

	return len;
errout:
	ssl_close();
	return 0;
}






