#include "node/egress.h"

#include "utils/common.h"
#include "security/crypto.h"
#include "dataplane/processing.h"
#include "dataplane/headers.h"
#include "dataplane/forward.h"

static inline void process_egress_packet(struct rte_mbuf *mbuf) {
  struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
  uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

  switch (ether_type) {
    case RTE_ETHER_TYPE_IPV6:
      switch (operation_bypass_bit) {
        case 0: {
          struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
          struct ipv6_srh *srh = (struct ipv6_srh *)(ipv6_hdr + 1);

          if (srh->next_header == 61) {
            size_t srh_bytes = sizeof(struct ipv6_srh);
            uint8_t *hmac_ptr = (uint8_t *)srh + srh_bytes;
            struct hmac_tlv *hmac = (struct hmac_tlv *)hmac_ptr;
            uint8_t *pot_ptr = hmac_ptr + sizeof(struct hmac_tlv);
            struct pot_tlv *pot = (struct pot_tlv *)pot_ptr;

            char dst_ip_str[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_ip_str, sizeof(dst_ip_str)) == NULL) {
              perror("inet_ntop failed");
              rte_pktmbuf_free(mbuf);
              return;
            }

            // Decrypt PVF
            uint8_t hmac_out[HMAC_MAX_LENGTH];
            memcpy(hmac_out, pot->encrypted_hmac, HMAC_MAX_LENGTH);
            decrypt_pvf(&k_pot_in[0], pot->nonce, hmac_out);
            memcpy(pot->encrypted_hmac, hmac_out, HMAC_MAX_LENGTH);
            uint8_t *k_hmac_ie = k_pot_in[0];

            uint8_t expected_hmac[HMAC_MAX_LENGTH];
            if (calculate_hmac((uint8_t *)&ipv6_hdr->src_addr, srh, hmac, k_hmac_ie, HMAC_MAX_LENGTH,
                               expected_hmac) != 0) {
              rte_pktmbuf_free(mbuf);
              return;
            }

            if (memcmp(hmac_out, expected_hmac, HMAC_MAX_LENGTH) != 0) {
              rte_pktmbuf_free(mbuf);
              return;
            }

            remove_headers(mbuf);

            struct rte_ether_hdr *eth_hdr_final = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
            struct rte_ipv6_hdr *ipv6_hdr_final = (struct rte_ipv6_hdr *)(eth_hdr_final + 1);

            char final_src_ip[INET6_ADDRSTRLEN], final_dst_ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &ipv6_hdr_final->src_addr, final_src_ip, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &ipv6_hdr_final->dst_addr, final_dst_ip, INET6_ADDRSTRLEN);
            
            struct rte_ether_addr iperf_mac = {{0x02, 0xcc, 0xef, 0x38, 0x4b, 0x25}};
            send_packet_to(iperf_mac, mbuf, 0);
          }
          break;
        }
        case 1:
          // Bypass all operations
          break;
        // case 2: remove_headers_only(mbuf); break;
        default: break;
      }
      break;
    default: break;
  }
}

void process_egress(struct rte_mbuf **pkts, uint16_t nb_rx) {
  for (uint16_t i = 0; i < nb_rx; i++) {
    process_egress_packet(pkts[i]);
  }
}
