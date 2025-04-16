#include <stdint.h>
#include <rte_common.h>

#define CUSTOM_HEADER_TYPE 0x0833
#define NONCE_LENGTH 16

struct ipv6_srh {
    uint8_t next_header;
    uint8_t hdr_ext_len;
    uint8_t routing_type;
    uint8_t segments_left;
    uint8_t flags;
    uint8_t tag[3];
    uint8_t reserved[3];
    uint8_t segments[0];
};

struct hmac_tlv
{
    uint8_t type;           // 1 byte for TLV type
    uint8_t length;         // 1 byte for TLV length
    uint16_t d_flag : 1;    // 1-bit D flag
    uint16_t reserved : 15; // Remaining 15 bits for reserved
    uint32_t hmac_key_id;   // 4 bytes for the HMAC Key ID
    uint8_t hmac_value[32]; // 8 Octets HMAC value must be multiples of 8 octetx and ma is 32 octets
};

void process_ip4(struct rte_mbuf *mbuf, uint16_t nb_rx, struct rte_ether_hdr *eth_hdr, int i);
void print_ipv6_address(const struct in6_addr *ipv6_addr, const char *label);
int process_ip6_with_srh(struct rte_ether_hdr *eth_hdr, struct rte_mbuf *mbuf, int i);
void remove_headers(struct rte_mbuf *pkt);
static uint16_t add_timestamps(uint16_t port __rte_unused, uint16_t qidx __rte_unused, struct rte_mbuf **pkts, uint16_t nb_pkts, uint16_t max_pkts __rte_unused, void *_ __rte_unused);
static uint16_t calc_latency(uint16_t port, uint16_t qidx __rte_unused, struct rte_mbuf **pkts, uint16_t nb_pkts, void *_ __rte_unused);
void add_custom_header6(struct rte_mbuf *pkt);
int generate_nonce(uint8_t nonce[NONCE_LENGTH]);