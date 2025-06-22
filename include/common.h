#ifndef COMMON_H
#define COMMON_H

#include <arpa/inet.h>
#include <getopt.h>
#include <inttypes.h>
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

#define RX_RING_SIZE 2048
#define TX_RING_SIZE 2048
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 256
#define CUSTOM_HEADER_TYPE 0x0833
#define EXTRA_SPACE 128
#define NONCE_LENGTH 16
#define HMAC_MAX_LENGTH 32
#define SID_NO 4
#define MAX_NEXT_HOPS 8
extern int operation_bypass_bit;
extern int tsc_dynfield_offset;
typedef uint64_t tsc_t;


uint8_t k_pot_in[SID_NO][HMAC_MAX_LENGTH] = {
    // egress key (16 bytes), pad with zeros if HMAC_MAX_LENGTH > 16
    {0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x30, 0x4b, 0x6c, 0x7d, 0x8e, 0x9f, 0xa0,
     0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0},
    // transit key (16 bytes), pad with zeros if needed
    {0xd8, 0xf9, 0xcd, 0xe1, 0xab, 0x34, 0x5c, 0xd0, 0xef, 0x67, 0x89, 0xab, 0x12, 0xcd, 0xef, 0x34,
     0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0}};


struct next_hop_entry {
  struct in6_addr ipv6;
  struct rte_ether_addr mac;
};

static struct next_hop_entry next_hops[MAX_NEXT_HOPS];
static int next_hop_count = 0;

struct ipv6_srh {
  uint8_t next_header;   // Next header type
  uint8_t hdr_ext_len;   // Length of SRH in 8-byte units
  uint8_t routing_type;  // Routing type (4 for SRv6)
  uint8_t segments_left;
  uint8_t last_entry;
  uint8_t flags;                // Segments yet to be visited
  uint8_t reserved[2];          // Reserved for future use
  struct in6_addr segments[2];  // Array of IPv6 segments max 10 nodes
};

struct hmac_tlv {
  uint8_t type;            // 1 byte for TLV type
  uint8_t length;          // 1 byte for TLV length
  uint16_t d_flag : 1;     // 1-bit D flag
  uint16_t reserved : 15;  // Remaining 15 bits for reserved
  uint32_t hmac_key_id;    // 4 bytes for the HMAC Key ID
  uint8_t hmac_value[32];  // 8 Octets HMAC value must be multiples of 8 octetx
                           // and ma is 32 octets
};

struct pot_tlv {
  uint8_t type;                // Type field (1 byte)
  uint8_t length;              // Length field (1 byte)
  uint8_t reserved;            // Reserved field (1 byte)
  uint8_t nonce_length;        // Nonce Length field (1 byte)
  uint32_t key_set_id;         // Key Set ID (4 bytes)
  uint8_t nonce[16];           // Nonce (variable length)
  uint8_t encrypted_hmac[32];  // Encrypted HMAC (variable length)
};

void print_ipv4_address(uint32_t ipv4_addr, const char *label);
void send_packet_to(struct rte_ether_addr mac_addr, struct rte_mbuf *mbuf, uint16_t tx_port_id);
int main(int argc, char *argv[]);
struct rte_mempool *create_mempool();
void init_eal(int argc, char *argv[]);
void register_tsc_dynfield();
void hex_dump(const void *data, size_t size);
void add_next_hop(const char *ipv6_str, const char *mac_str);
struct rte_ether_addr *lookup_mac_for_ipv6(struct in6_addr *ipv6);
void print_ipv6_address(const struct in6_addr *ipv6_addr, const char *label);

#endif  // COMMON_H