#ifndef STUB_H
#define STUB_H
#include "../../../src/fdns/fdns.h"

int arg_allow_all_queries = 0;
int arg_nofilter = 0;
int arg_ipv6 = 0;
Stats stats;
SSLState ssl_state = SSL_OPEN;

// remote logging (worker processes)
void rlogprintf(const char *format, ...) {
	va_list valist;
	va_start(valist, format);
	vprintf(format, valist);
	va_end(valist);
	fflush(0);
}

int dnsfilter_blocked(const char *str, int verbose) {
	(void) str;
	(void) verbose;
	return 0;
}

void cache_set_name(const char *name, int ipv6) {
	(void) name;
	(void) ipv6;
}

uint8_t *cache_check(uint16_t id, const char *name, ssize_t *lenptr, int ipv6) {
	(void) id;
	(void) name;
	(void) lenptr;
	(void) ipv6;
	return NULL;
}

#endif