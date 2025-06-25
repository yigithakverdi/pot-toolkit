#include "node/ingress.h"

#include "utils/common.h"
#include "security/crypto.h"
#include "dataplane/processing.h"
#include "dataplane/headers.h"
#include "dataplane/forward.h"
#include "utils/common.h"
#include "routing/routecontroller.h"

static inline void process_ingress_packet(struct rte_mbuf *mbuf, uint16_t rx_port_id) {
  struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
  uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

  if (ether_type != RTE_ETHER_TYPE_IPV6) {
    rte_pktmbuf_free(mbuf);
    return;
  }

  if ((eth_hdr->dst_addr.addr_bytes[0] & 0x01) != 0) {
    rte_pktmbuf_free(mbuf);
    return;
  }

  switch (ether_type) {
    case RTE_ETHER_TYPE_IPV6:
      switch (operation_bypass_bit) {
        case 0:

          add_custom_header(mbuf);
          struct rte_ether_hdr *eth_hdr6 = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
          struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr6 + 1);
          struct ipv6_srh *srh = (struct ipv6_srh *)(ipv6_hdr + 1);
          struct hmac_tlv *hmac = (struct hmac_tlv *)(srh + 1);
          struct pot_tlv *pot = (struct pot_tlv *)(hmac + 1);

          char dst_ip_str[INET6_ADDRSTRLEN];
          if (inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_ip_str, sizeof(dst_ip_str)) == NULL) {
            perror("inet_ntop failed");
            break;
          }

          uint8_t *k_hmac_ie = k_pot_in[0];
          size_t key_len = HMAC_MAX_LENGTH;

          struct in6_addr ingress_addr;
          inet_pton(AF_INET6, "2a05:d014:dc7:12ff:f611:cc26:cf0d:5c92", &ingress_addr);

          size_t dump_len = rte_pktmbuf_pkt_len(mbuf);
          if (dump_len > 128) dump_len = 128;
          uint8_t hmac_out[HMAC_MAX_LENGTH];
          if (calculate_hmac((uint8_t *)&ingress_addr, srh, hmac, k_hmac_ie, key_len, hmac_out) == 0) {
            // for (int i = 0; i < HMAC_MAX_LENGTH; i++) printf("%02x", hmac_out[i]);
            rte_memcpy(hmac->hmac_value, hmac_out, HMAC_MAX_LENGTH);
          } else {
            break;
          }

          uint8_t nonce[NONCE_LENGTH];
          if (generate_nonce(nonce) != 0) {
            break;
          }
          encrypt_pvf(k_pot_in, nonce, hmac_out);
          rte_memcpy(pot->encrypted_hmac, hmac_out, HMAC_MAX_LENGTH);
          rte_memcpy(pot->nonce, nonce, NONCE_LENGTH);

          if (srh->segments_left == 0) {
            rte_pktmbuf_free(mbuf);
          } else {
            int next_sid_index = srh->last_entry - srh->segments_left + 1;
            memcpy(&ipv6_hdr->dst_addr, &srh->segments[next_sid_index], sizeof(struct in6_addr));
            struct rte_ether_addr *next_mac = lookup_mac_for_ipv6(&srh->segments[next_sid_index]);
            if (next_mac) {
              send_packet_to(*next_mac, mbuf, rx_port_id);
            } else {
              rte_pktmbuf_free(mbuf);
            }
          }

          break;
        case 1:
          // Bypass all operations
          break;
        // case 2: add_custom_header_only(mbuf); break;
        default: break;
      }
      break;
    default: break;
  }
}

void process_ingress(struct rte_mbuf **pkts, uint16_t nb_rx, uint16_t rx_port_id) {
  for (uint16_t i = 0; i < nb_rx; i++) {
    process_ingress_packet(pkts[i], rx_port_id);
  }
}