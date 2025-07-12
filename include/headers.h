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

// This is also a hard limit for the number of segments that can be defined and placed in the
// custom header, soft limit is placed using the configurations, i.e. environment variable.
// POT_MAX_SEGMENTS is the soft limit.
#define HMAC_MAX_LENGTH 32
#define MAX_SEGMENTS 50
#define MAX_POT_NODES 50
#define MAX_NEXT_HOPS 8

// Global segment array and count
extern struct in6_addr *g_segments;
extern int g_segment_count;

extern int operation_bypass_bit;
extern int tsc_dynfield_offset;
typedef uint64_t tsc_t;

struct next_hop_entry {
  struct in6_addr ipv6;
  struct rte_ether_addr mac;
};

static struct next_hop_entry next_hops[MAX_NEXT_HOPS];
static int next_hop_count = 0;

struct ipv6_srh {
  uint8_t next_header;  // Next header type
  uint8_t hdr_ext_len;  // Length of SRH in 8-byte units
  uint8_t routing_type; // Routing type (4 for SRv6)
  uint8_t segments_left;
  uint8_t last_entry;
  uint8_t flags;               // Segments yet to be visited
  uint8_t reserved[2];         // Reserved for future use
  
  // Commented out fixed segment size for making it dynamic 
  // struct in6_addr segments[2];  // Array of IPv6 segments max 10 nodes
};

struct hmac_tlv {
  uint8_t type;           // 1 byte for TLV type
  uint8_t length;         // 1 byte for TLV length
  uint16_t d_flag : 1;    // 1-bit D flag
  uint16_t reserved : 15; // Remaining 15 bits for reserved
  uint32_t hmac_key_id;   // 4 bytes for the HMAC Key ID
  uint8_t hmac_value[32]; // 8 Octets HMAC value must be multiples of 8 octetx
                          // and ma is 32 octets
};

struct pot_tlv {
  uint8_t type;               // Type field (1 byte)
  uint8_t length;             // Length field (1 byte)
  uint8_t reserved;           // Reserved field (1 byte)
  uint8_t nonce_length;       // Nonce Length field (1 byte)
  uint32_t key_set_id;        // Key Set ID (4 bytes)
  uint8_t nonce[16];          // Nonce (variable length)
  uint8_t encrypted_hmac[32]; // Encrypted HMAC (variable length)
};

void add_custom_header(struct rte_mbuf* pkt);
void remove_headers(struct rte_mbuf* pkt);
int load_srh_segments(const char* filepath);
void free_srh_segments(void);

#endif // HEADERS_H