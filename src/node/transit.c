#include "node/transit.h"

#include "dataplane/forward.h"
#include "dataplane/processing.h"
#include "routing/routecontroller.h"
#include "security/crypto.h"
#include "utils/common.h"
#include "utils/logging.h"

static inline void process_transit_packet(struct rte_mbuf *mbuf, int i) {
  size_t dump_len = rte_pktmbuf_pkt_len(mbuf);
  if (dump_len > 64) dump_len = 64;
  LOG_MAIN(DEBUG, "Processing transit packet %d with length %u.", i, rte_pktmbuf_pkt_len(mbuf));

  struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
  uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

  // Check if the destination MAC address is a multicast/broadcast address.
  // If the least significant bit of the first byte is set, it's multicast/broadcast.
  // Such packets are not processed by this specific logic and are dropped.
  if ((eth_hdr->dst_addr.addr_bytes[0] & 0x01) != 0) {
    LOG_MAIN(DEBUG, "Multicast/Broadcast packet received in transit, dropping.");
    rte_pktmbuf_free(mbuf);
    return;
  }

  switch (ether_type) {
    case RTE_ETHER_TYPE_IPV6:
      LOG_MAIN(DEBUG, "Transit packet is IPv6, processing headers.");

      switch (0) {
        case 0: {
          LOG_MAIN(DEBUG, "Processing transit packet with SRH.");

          // Get pointers to the IPv6 header and Segment Routing Header (SRH).
          // This assumes fixed header order: Ethernet -> IPv6 -> SRH.
          struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
          struct ipv6_srh *srh = (struct ipv6_srh *)(ipv6_hdr + 1);

          // Verify that the SRH's next header is 61 (Destination Options Header)
          // and its routing type is 4 (SRH). If not, the packet is not a valid SRv6 packet
          // for this transit node, so it's dropped.
          if (srh->next_header != 61 || srh->routing_type != 4) {
            LOG_MAIN(WARNING, "Transit: SRH next_header (%u) or routing_type (%u) mismatch, dropping packet.",
                     srh->next_header, srh->routing_type);
            rte_pktmbuf_free(mbuf);
            return;
          }

          if (srh->next_header == 61) {
            size_t srh_bytes = sizeof(struct ipv6_srh);

            uint8_t *hmac_ptr = (uint8_t *)srh + srh_bytes;
            uint8_t *pot_ptr = hmac_ptr + sizeof(struct hmac_tlv);
            struct pot_tlv *pot = (struct pot_tlv *)pot_ptr;
            LOG_MAIN(DEBUG, "Transit: SRH detected. POT TLV address: %p", (void *)pot);

            char dst_ip_str[INET6_ADDRSTRLEN];

            if (inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_ip_str, sizeof(dst_ip_str)) == NULL) {
              LOG_MAIN(ERR, "Transit: inet_ntop failed for destination address.");
              perror("inet_ntop failed");
              rte_pktmbuf_free(mbuf);
              return;
            }
            LOG_MAIN(DEBUG, "Transit: Destination IPv6 address: %s", dst_ip_str);

            uint8_t pvf_out[HMAC_MAX_LENGTH];

            memcpy(pvf_out, pot->encrypted_hmac, HMAC_MAX_LENGTH);

            // Decrypt the PVF. The key `k_pot_in[1]` is used here, implying
            // that transit nodes use a different key from ingress/egress, or a different key ID.
            // The decrypted result overwrites `pvf_out`.
            decrypt_pvf(&k_pot_in[1], pot->nonce, pvf_out);

            memcpy(pot->encrypted_hmac, pvf_out, HMAC_MAX_LENGTH);
            LOG_MAIN(DEBUG, "Transit: PVF (HMAC) decrypted and updated in POT TLV.");

            // Check if 'segments_left' is 0. If it is, the packet has reached
            // its final segment in the SRH path at this node, but this is a transit node.
            // This indicates a routing error or misconfiguration, so the packet is dropped.
            if (srh->segments_left == 0) {
              LOG_MAIN(WARNING, "Transit: segments_left is 0, but packet still in transit, dropping.");
              rte_pktmbuf_free(mbuf);
              return;
            }

            srh->segments_left--;
            int next_sid_index = srh->last_entry - srh->segments_left + 1;
            memcpy(&ipv6_hdr->dst_addr, &srh->segments[next_sid_index], sizeof(ipv6_hdr->dst_addr));
            LOG_MAIN(DEBUG, "Transit: Decremented segments_left. Next SID: %s",
                     inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_ip_str, sizeof(dst_ip_str)));

            struct rte_ether_addr *next_mac = lookup_mac_for_ipv6(&srh->segments[next_sid_index]);
            if (next_mac) {
              send_packet_to(*next_mac, mbuf, 0);
              LOG_MAIN(DEBUG, "Transit: Packet sent to next hop with MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                       next_mac->addr_bytes[0], next_mac->addr_bytes[1], next_mac->addr_bytes[2],
                       next_mac->addr_bytes[3], next_mac->addr_bytes[4], next_mac->addr_bytes[5]);

              dump_len = rte_pktmbuf_pkt_len(mbuf);
            } else {
              LOG_MAIN(ERR, "Transit: No MAC found for next SID, dropping packet.");
              rte_pktmbuf_free(mbuf);
            }
          }
          break;
        }
        case 1: LOG_MAIN(DEBUG, "Transit: Bypassing all operations."); break;

        default:
          LOG_MAIN(WARNING, "Transit: Unknown operation_bypass_bit value for transit processing.");
          break;
      }
      break;
    default: LOG_MAIN(DEBUG, "Transit: Packet is not IPv6, not processed by transit_packet_process."); break;
  }
}

void process_transit(struct rte_mbuf **pkts, uint16_t nb_rx) {
  // Processes each received packet in the transit queue.
  // This function iterates over the received packets, processes each one,
  // and logs the packet information.
  LOG_MAIN(DEBUG, "Processing %u transit packets", nb_rx);
  for (uint16_t i = 0; i < nb_rx; i++) {
    LOG_MAIN(DEBUG, "Processing transit packet %u with length %u", i, rte_pktmbuf_pkt_len(pkts[i]));
    process_transit_packet(pkts[i], i);
  }
}
