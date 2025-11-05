#include "node/transit.h"

#include "crypto.h"
#include "forward.h"
#include "headers.h"
#include "node/controller.h"
#include "utils/config.h"
#include "utils/logging.h"

static inline void process_transit_packet(struct rte_mbuf* mbuf, int i) {
  size_t dump_len = rte_pktmbuf_pkt_len(mbuf);
  if (dump_len > 64) dump_len = 64;
  // LOG_DP(DEBUG, "Processing transit packet %u with length %u.", i, rte_pktmbuf_pkt_len(mbuf));

  // Enhanced bounds checking - check for ALL expected headers
  // size_t min_packet_size = sizeof(struct rte_ether_hdr) +
  //                         sizeof(struct rte_ipv6_hdr) +
  //                         sizeof(struct ipv6_srh) +
  //                         sizeof(struct hmac_tlv) +
  //                         sizeof(struct pot_tlv);

  // If simple forward mode is selected then skip the size checks since it just directly forwards the packets
  // without any modification, SRH header additions etc.
  if (!g_simple_forward &&
      (rte_pktmbuf_pkt_len(mbuf) < sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr))) {
    LOG_MAIN(WARNING, "Transit: Packet too small for basic headers, dropping\n");
    rte_pktmbuf_free(mbuf);
    return;
  }

  struct rte_ether_hdr* eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);
  uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

  // Check if the destination MAC address is a multicast/broadcast address.
  // If the least significant bit of the first byte is set, it's multicast/broadcast.
  // Such packets are not processed by this specific logic and are dropped.
  if ((eth_hdr->dst_addr.addr_bytes[0] & 0x01) != 0) {
    LOG_MAIN(NOTICE, "Multicast/Broadcast packet received in transit, dropping.");
    rte_pktmbuf_free(mbuf);
    return;
  }

  // Check if the packet is IPv6, if not drop it
  if (ether_type != RTE_ETHER_TYPE_IPV6) {
    LOG_MAIN(NOTICE, "Non-IPv6 packet received in transit (EtherType: %u), dropping.\n", ether_type);
    rte_pktmbuf_free(mbuf);
    return;
  }

  struct rte_ipv6_hdr* ipv6_hdr = (struct rte_ipv6_hdr*)(eth_hdr + 1);
  struct ipv6_srh* srh = (struct ipv6_srh*)(ipv6_hdr + 1);
  size_t actual_srh_size = (srh->hdr_ext_len * 8) + 8;
  size_t min_packet_size = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr) + actual_srh_size +
                           sizeof(struct hmac_tlv) + sizeof(struct pot_tlv);

  if (!g_simple_forward && (rte_pktmbuf_pkt_len(mbuf) < min_packet_size)) {
    LOG_MAIN(WARNING, "Transit: Packet too small (%u bytes) for expected headers (%zu bytes), dropping\n",
             rte_pktmbuf_pkt_len(mbuf), min_packet_size);
    rte_pktmbuf_free(mbuf);
    return;
  }

  switch (ether_type) {
  case RTE_ETHER_TYPE_IPV6:
    LOG_MAIN(DEBUG, "Transit packet is IPv6, processing headers.\n");

    switch (operation_bypass_bit) {
    case 0: {
      LOG_MAIN(DEBUG, "Processing transit packet with SRH.\n");

      // Get pointers to the IPv6 header and Segment Routing Header (SRH).
      // This assumes fixed header order: Ethernet -> IPv6 -> SRH.
      struct rte_ipv6_hdr* ipv6_hdr = (struct rte_ipv6_hdr*)(eth_hdr + 1);
      struct ipv6_srh* srh = (struct ipv6_srh*)(ipv6_hdr + 1);

      // Add NULL pointer checks
      if (!ipv6_hdr || !srh) {
        LOG_MAIN(ERR, "Transit: NULL pointer detected in headers\n");
        rte_pktmbuf_free(mbuf);
        return;
      }

      // Verify that the SRH's next header is 61 (Destination Options Header)
      // and its routing type is 4 (SRH). If not, the packet is not a valid SRv6 packet
      // for this transit node, so it's dropped.
      if (srh->next_header != IPROTO_TCP || srh->routing_type != 4) {
        LOG_MAIN(WARNING, "Transit: SRH next_header (%u) or routing_type (%u) mismatch, dropping packet.\n",
                 srh->next_header, srh->routing_type);
        rte_pktmbuf_free(mbuf);
        return;
      }

      if (srh->next_header == IPROTO_TCP) {
        // size_t srh_bytes = sizeof(struct ipv6_srh);
        size_t actual_srh_size = (srh->hdr_ext_len * 8) + 8;
        struct in6_addr* segments = (struct in6_addr*)((uint8_t*)srh + sizeof(struct ipv6_srh));

        // uint8_t* hmac_ptr = (uint8_t*)srh + srh_bytes;
        // uint8_t* pot_ptr = hmac_ptr + sizeof(struct hmac_tlv);
        uint8_t* hmac_ptr = (uint8_t*)srh + actual_srh_size;
        uint8_t* pot_ptr = hmac_ptr + sizeof(struct hmac_tlv);

        // Add bounds check for POT TLV access
        if ((uint8_t*)pot_ptr + sizeof(struct pot_tlv) >
            (uint8_t*)rte_pktmbuf_mtod(mbuf, void*) + rte_pktmbuf_pkt_len(mbuf)) {
          LOG_MAIN(ERR, "Transit: POT TLV extends beyond packet boundary, dropping\n");
          rte_pktmbuf_free(mbuf);
          return;
        }

        struct pot_tlv* pot = (struct pot_tlv*)pot_ptr;
        LOG_MAIN(DEBUG, "Transit: SRH detected. POT TLV address: %p\n", (void*)pot);

        char dst_ip_str[INET6_ADDRSTRLEN];

        if (inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_ip_str, sizeof(dst_ip_str)) == NULL) {
          LOG_MAIN(ERR, "Transit: inet_ntop failed for destination address.\n");
          perror("inet_ntop failed");
          rte_pktmbuf_free(mbuf);
          return;
        }
        LOG_MAIN(DEBUG, "Transit: Destination IPv6 address: %s\n", dst_ip_str);

        uint8_t pvf_out[HMAC_MAX_LENGTH];

        memcpy(pvf_out, pot->encrypted_hmac, HMAC_MAX_LENGTH);

        // Add bounds check for g_node_index
        if (g_node_index < 0 || g_node_index >= MAX_POT_NODES) {
          LOG_MAIN(ERR, "Transit: Invalid g_node_index (%d), dropping packet\n", g_node_index);
          rte_pktmbuf_free(mbuf);
          return;
        }

        int curr_index = g_node_index;
        uint8_t decrypted_once[HMAC_MAX_LENGTH];
        int dec_len =
            decrypt(pot->encrypted_hmac, HMAC_MAX_LENGTH, k_pot_in[curr_index], pot->nonce, decrypted_once);

        if (dec_len < 0) {
          LOG_MAIN(ERR, "Transit: PVF decryption failed for this layer.\n");
          rte_pktmbuf_free(mbuf);
          return;
        }

        memcpy(pot->encrypted_hmac, decrypted_once, HMAC_MAX_LENGTH);
        LOG_MAIN(DEBUG, "Transit: Layer %d decrypted.\n", curr_index);

        // Check if 'segments_left' is 0. If it is, the packet has reached
        // its final segment in the SRH path at this node, but this is a transit node.
        // This indicates a routing error or misconfiguration, so the packet is dropped.
        if (srh->segments_left == 0) {
          LOG_MAIN(WARNING, "Transit: segments_left is 0, but packet still in transit, dropping.\n");
          rte_pktmbuf_free(mbuf);
          return;
        }

        // Add bounds check for segments_left
        // if (srh->segments_left > srh->last_entry) {
        //   LOG_MAIN(ERR, "Transit: segments_left (%u) > last_entry (%u), dropping packet\n",
        //            srh->segments_left, srh->last_entry);
        //   rte_pktmbuf_free(mbuf);
        //   return;
        // }

        srh->segments_left--;
        int next_sid_index = srh->last_entry - srh->segments_left + 1;

        // Add bounds check for segment array access
        if (next_sid_index < 0 || next_sid_index > srh->last_entry) {
          LOG_MAIN(ERR, "Transit: Invalid next_sid_index (%d), last_entry (%u), dropping packet\n",
                   next_sid_index, srh->last_entry);
          rte_pktmbuf_free(mbuf);
          return;
        }
        // memcpy(&ipv6_hdr->dst_addr, &srh->segments[next_sid_index], sizeof(ipv6_hdr->dst_addr));
        // LOG_MAIN(DEBUG, "Transit: Decremented segments_left. Next SID: %s\n",
        //          inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_ip_str, sizeof(dst_ip_str)));

        // struct rte_ether_addr* next_mac = lookup_mac_for_ipv6(&srh->segments[next_sid_index]);
        memcpy(&ipv6_hdr->dst_addr, &segments[next_sid_index], sizeof(ipv6_hdr->dst_addr));
        LOG_MAIN(DEBUG, "Transit: Decremented segments_left. Next SID: %s\n",
                 inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_ip_str, sizeof(dst_ip_str)));

        struct rte_ether_addr* next_mac = lookup_mac_for_ipv6(&segments[next_sid_index]);
        if (next_mac) {
          if (g_is_virtual_machine == 0) {
            send_packet_to(*next_mac, mbuf, 1);
          } else {
            send_packet_to(*next_mac, mbuf, 0);
          }
          LOG_MAIN(DEBUG, "Transit: Packet sent to next hop with MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   next_mac->addr_bytes[0], next_mac->addr_bytes[1], next_mac->addr_bytes[2],
                   next_mac->addr_bytes[3], next_mac->addr_bytes[4], next_mac->addr_bytes[5]);

          dump_len = rte_pktmbuf_pkt_len(mbuf);
        } else {
          LOG_MAIN(ERR, "Transit: No MAC found for next SID, dropping packet.\n");
          rte_pktmbuf_free(mbuf);
        }
      }
      break;
    }
    case 1: {
      // add_next_hop("2a05:d014:dc7:1281:7aa5:aa66:e3d1:d8a5", "02:56:e6:d5:57:05");
      // add_next_hop("2a05:d014:dc7:1210:818e:dec3:7ed3:a935", "02:63:a9:59:f8:8f");
      struct rte_ether_addr mac = {{0x02, 0x63, 0xa9, 0x59, 0xf8, 0x8f}};
      // 02:63:a9:59:f8:8f
      send_packet_to(mac, mbuf, 0);
      break;
    }

    case 2: {
      LOG_MAIN(DEBUG, "Processing SRH-only packet in transit.\n");

      struct rte_ipv6_hdr* ipv6_hdr = (struct rte_ipv6_hdr*)(eth_hdr + 1);
      struct ipv6_srh* srh = (struct ipv6_srh*)(ipv6_hdr + 1);
      size_t actual_srh_size = (srh->hdr_ext_len * 8) + 8;
      struct in6_addr* segments = (struct in6_addr*)((uint8_t*)srh + sizeof(struct ipv6_srh));

      if (srh->segments_left == 0) {
        LOG_MAIN(WARNING, "Transit: segments_left is 0, dropping packet\n");
        rte_pktmbuf_free(mbuf);
        return;
      }

      srh->segments_left--;
      int next_sid_index = srh->last_entry - srh->segments_left + 1;

      if (next_sid_index < 0 || next_sid_index > srh->last_entry) {
        LOG_MAIN(ERR, "Transit: Invalid next_sid_index (%d), dropping packet\n", next_sid_index);
        rte_pktmbuf_free(mbuf);
        return;
      }

      memcpy(&ipv6_hdr->dst_addr, &segments[next_sid_index], sizeof(struct in6_addr));

      struct rte_ether_addr* next_mac = lookup_mac_for_ipv6(&segments[next_sid_index]);
      if (next_mac) {
        send_packet_to(*next_mac, mbuf, g_is_virtual_machine ? 0 : 1);
      } else {
        LOG_MAIN(ERR, "Transit: No MAC found for next SID, dropping packet\n");
        rte_pktmbuf_free(mbuf);
      }
      break;
    }

    default:
      LOG_MAIN(WARNING, "Transit: Unknown operation_bypass_bit value for transit processing.\n");
      break;
    }
    break;
  default: LOG_MAIN(DEBUG, "Transit: Packet is not IPv6, not processed by transit_packet_process.\n"); break;
  }
}

void process_transit(struct rte_mbuf** pkts, uint16_t nb_rx) {
  // Processes each received packet in the transit queue.
  // This function iterates over the received packets, processes each one,
  // and logs the packet information.
  // LOG_MAIN(NOTICE, "Processing %u transit packets", nb_rx);
  for (uint16_t i = 0; i < nb_rx; i++) {
    // LOG_MAIN(DEBUG, "Processing transit packet %u with length %u", i, rte_pktmbuf_pkt_len(pkts[i]));
    process_transit_packet(pkts[i], i);
  }

  // Print DPDK RX/TX stats for port 0
  // struct rte_eth_stats stats;
  // int ret = rte_eth_stats_get(0, &stats);
  // if (ret == 0) {
  //   LOG_MAIN(INFO, "[DPDK Port 0 Stats] RX: %" PRIu64 ", TX: %" PRIu64 ", RX dropped: %" PRIu64 ", TX
  //   dropped: %" PRIu64 ", RX errors: %" PRIu64 ", TX errors: %\n" PRIu64,
  //     stats.ipackets, stats.opackets, stats.imissed, stats.oerrors, stats.ierrors, stats.oerrors);
  // } else {
  //   LOG_MAIN(ERR, "[DPDK Port 0 Stats] Failed to get stats (ret=%d)\n", ret);
  // }
}
