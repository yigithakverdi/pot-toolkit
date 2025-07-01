#ifndef HEADERS_H
#define HEADERS_H

#include <arpa/inet.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include <rte_mbuf_dyn.h>
#include <stdalign.h>
#include <stdint.h>


#define MAX_SEGMENTS 10  // Maximum number of segments in the path

// Global segment array and count
extern struct in6_addr g_segments[MAX_SEGMENTS];
extern int g_segment_count;

// Function to read segment list from file
int read_segment_list(const char *file_path);

void add_custom_header(struct rte_mbuf *pkt);
void remove_headers(struct rte_mbuf *pkt);

#endif // HEADERS_H
