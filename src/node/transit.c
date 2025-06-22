#include "include/node/transit.h"
#include "include/common.h"
#include "include/crypto.h"

static inline void process_transit_packet(struct rte_mbuf *mbuf, int i) {
  size_t dump_len = rte_pktmbuf_pkt_len(mbuf);
  if (dump_len > 64) dump_len = 64;

  struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
  uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

  if ((eth_hdr->dst_addr.addr_bytes[0] & 0x01) != 0) {
    rte_pktmbuf_free(mbuf);
    return;
  }

  switch (ether_type) {
    case RTE_ETHER_TYPE_IPV6:
      switch (0) {
        case 0: {
          struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
          struct ipv6_srh *srh = (struct ipv6_srh *)(ipv6_hdr + 1);

          if (srh->next_header != 61 || srh->routing_type != 4) {
            rte_pktmbuf_free(mbuf);
            return;
          }

          if (srh->next_header == 61) {
            size_t srh_bytes = sizeof(struct ipv6_srh);
            uint8_t *hmac_ptr = (uint8_t *)srh + srh_bytes;
            uint8_t *pot_ptr = hmac_ptr + sizeof(struct hmac_tlv);
            struct pot_tlv *pot = (struct pot_tlv *)pot_ptr;

            char dst_ip_str[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_ip_str, sizeof(dst_ip_str)) == NULL) {
              perror("inet_ntop failed");
              rte_pktmbuf_free(mbuf);
              return;
            }

            uint8_t pvf_out[HMAC_MAX_LENGTH];
            memcpy(pvf_out, pot->encrypted_hmac, HMAC_MAX_LENGTH);
            decrypt_pvf(&k_pot_in[1], pot->nonce, pvf_out);
            memcpy(pot->encrypted_hmac, pvf_out, HMAC_MAX_LENGTH);

            if (srh->segments_left == 0) {
              rte_pktmbuf_free(mbuf);
              return;
            }

            srh->segments_left--;
            int next_sid_index = srh->last_entry - srh->segments_left + 1;
            memcpy(&ipv6_hdr->dst_addr, &srh->segments[next_sid_index], sizeof(ipv6_hdr->dst_addr));
            struct rte_ether_addr *next_mac = lookup_mac_for_ipv6(&srh->segments[next_sid_index]);
            if (next_mac) {
              send_packet_to(*next_mac, mbuf, 0);
              dump_len = rte_pktmbuf_pkt_len(mbuf);
            } else {
              rte_pktmbuf_free(mbuf);
            }
          }
          break;
        }
        case 1:
          // Bypass all operations
          break;
          // remove_headers_only(mbuf); break;
        default: break;
      }
      break;
    default: break;
  }
}

static inline void process_transit(struct rte_mbuf **pkts, uint16_t nb_rx) {
  for (uint16_t i = 0; i < nb_rx; i++) {
    process_transit_packet(pkts[i], i);
  }
}
