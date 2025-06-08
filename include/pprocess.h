#ifndef PPROCESS_H
#define PPROCESS_H

#include <netinet/in.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <stdint.h>

#include "common.h"

void add_custom_header6(struct rte_mbuf *pkt);
void add_custom_header6_only_srh(struct rte_mbuf *pkt);
void remove_headers(struct rte_mbuf *pkt);
void remove_headers_only_srh(struct rte_mbuf *pkt);
int process_ip6_with_srh(struct rte_ether_hdr *eth_hdr, struct rte_mbuf *mbuf, int i);
void process_ip4(struct rte_mbuf *mbuf, uint16_t nb_rx, struct rte_ether_hdr *eth_hdr, int i);
int compare_hmac(struct hmac_tlv *hmac, uint8_t *hmac_out, struct rte_mbuf *mbuf);

#endif  // PPROCESS_H