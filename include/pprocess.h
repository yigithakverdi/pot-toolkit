#ifndef PPROCESS_H
#define PPROCESS_H

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

#include "common.h"

enum role {
  ROLE_INGRESS,
  ROLE_TRANSIT,
  ROLE_EGRESS,
};

void add_custom_header(struct rte_mbuf *pkt);
void add_custom_header_only(struct rte_mbuf *pkt);

void remove_headers(struct rte_mbuf *pkt);
void remove_headers_only(struct rte_mbuf *pkt);

void process_ip4(struct rte_mbuf *mbuf, uint16_t nb_rx, struct rte_ether_hdr *eth_hdr, int i);
int compare_hmac(struct hmac_tlv *hmac, uint8_t *hmac_out, struct rte_mbuf *mbuf);

int lcore_main_forward(void *arg);
void launch_lcore_forwarding(uint16_t *ports);

static inline enum role determine_role(uint16_t rx_port_id, uint16_t tx_port_id);
static inline void process_ingress(struct rte_mbuf **pkts, uint16_t nb_rx);
static inline void process_transit(struct rte_mbuf **pkts, uint16_t nb_rx);
static inline void process_egress(struct rte_mbuf **pkts, uint16_t nb_rx);

#endif  // PPROCESS_H