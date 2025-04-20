#ifndef PACKET_UTILS_H
#define PACKET_UTILS_H

#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define CUSTOM_HEADER_TYPE 0x0833
#define NONCE_LENGTH 16

struct ipv6_srh {
  uint8_t next_header;              // Next header type
  uint8_t hdr_ext_len;              // Length of SRH in 8-byte units
  uint8_t routing_type;             // Routing type (4 for SRv6)
  uint8_t segments_left;            // Segments left to visit
  uint8_t last_entry;               // Last entry in the segment list 
  uint8_t flags;                    // Segments yet to be visited
  uint8_t reserved[2];              // Reserved for future use
  struct in6_addr segments[2];      // Array of IPv6 segments max 10 nodes
};

struct hmac_tlv {
  uint8_t type;                     // 1 byte for TLV type
  uint8_t length;                   // 1 byte for TLV length
  uint16_t d_flag : 1;              // 1-bit D flag
  uint16_t reserved : 15;           // Remaining 15 bits for reserved
  uint32_t hmac_key_id;             // 4 bytes for the HMAC Key ID
  uint8_t hmac_value[32];           // 8 Octets HMAC value must be multiples of 8 octetx
                                    // and ma is 32 octets
};

void process_ip4(struct rte_mbuf *mbuf, uint16_t nb_rx,
                 struct rte_ether_hdr *eth_hdr, int i);
void print_ipv6_address(const struct in6_addr *ipv6_addr, const char *label);
int process_ip6_with_srh(struct rte_ether_hdr *eth_hdr, struct rte_mbuf *mbuf,
                         int i);                         
void remove_headers(struct rte_mbuf *pkt);
static uint16_t add_timestamps(uint16_t port __rte_unused,
                               uint16_t qidx __rte_unused,
                               struct rte_mbuf **pkts, uint16_t nb_pkts,
                               uint16_t max_pkts __rte_unused,
                               void *_ __rte_unused);
static uint16_t calc_latency(uint16_t port, uint16_t qidx __rte_unused,
                             struct rte_mbuf **pkts, uint16_t nb_pkts,
                             void *_ __rte_unused);
void add_custom_header6(struct rte_mbuf *pkt);
int generate_nonce(uint8_t nonce[NONCE_LENGTH]);
void parse_eth_packet();
void process_packet();

#endif // PACKET_UTILS_H