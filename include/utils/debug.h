#ifndef DEBUG_H
#define DEBUG_H

#include "core/pverify.h"
#include <string.h>          // For memcmp
#include <rte_mbuf.h>        // For rte_pktmbuf_free and struct rte_mbuf

void hex_dump(const void *data, size_t size);
void print_offset_and_hex(const char *label, const void *base, const void *ptr, size_t len);
void print_ipv6_address(const struct in6_addr *ipv6_addr, const char *label);
void print_ipv4_address(uint32_t ipv4_addr, const char *label);

#endif // DEBUG_H