#include "node/ingress.h"

#include "dataplane/forward.h"
#include "dataplane/headers.h"
#include "dataplane/processing.h"
#include "routing/routecontroller.h"
#include "security/crypto.h"
#include "utils/common.h"
#include "utils/logging.h"

static inline void process_ingress_packet(struct rte_mbuf *mbuf, uint16_t rx_port_id) {
  struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
  uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

  // If the packet is not IPv6, free it and return.
  // This is an optimization to quickly discard irrelevant packets.
  if (ether_type != RTE_ETHER_TYPE_IPV6) {
    LOG_MAIN(DEBUG, "Non-IPv6 packet received (EtherType: %u), dropping.", ether_type);
    rte_pktmbuf_free(mbuf);
    return;
  }

  // Check if the destination MAC address is a multicast/broadcast address.
  // If the least significant bit of the first byte is set, it's multicast/broadcast.
  // Such packets are not processed by this specific logic and are dropped.
  if ((eth_hdr->dst_addr.addr_bytes[0] & 0x01) != 0) {
    LOG_MAIN(DEBUG, "Multicast/Broadcast packet received, dropping.");
    rte_pktmbuf_free(mbuf);
    return;
  }

  switch (ether_type) {
    case RTE_ETHER_TYPE_IPV6:
      LOG_MAIN(DEBUG, "Ingress packet is IPv6, processing headers.");

      // Control flow based on a global configuration bit.
      // This allows bypassing certain operations for testing or specific use cases.
      LOG_MAIN(DEBUG, "Operation bypass bit is %d", operation_bypass_bit);
      switch (operation_bypass_bit) {

        // Case 0: Full processing including custom header addition, HMAC calculation, and
        // encryption.
        case 0:
          LOG_MAIN(DEBUG, "Processing packet with SRH and HMAC for ingress.");

          // Add custom headers (SRH, HMAC, POT TLVs) to the packet.
          // This function modifies the mbuf in place by appending new headers and adjusting payload.
          add_custom_header(mbuf);

          // Re-obtain pointers to headers as the mbuf's data layout might have changed
          // after `add_custom_header` (e.g., if it moved existing data).
          struct rte_ether_hdr *eth_hdr6 = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
          struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr6 + 1);
          struct ipv6_srh *srh = (struct ipv6_srh *)(ipv6_hdr + 1);
          struct hmac_tlv *hmac = (struct hmac_tlv *)(srh + 1);
          struct pot_tlv *pot = (struct pot_tlv *)(hmac + 1);

          char dst_ip_str[INET6_ADDRSTRLEN];

          // Convert the IPv6 destination address from binary to string format for logging/debugging.
          // If conversion fails, log an error and break from processing this packet.
          if (inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_ip_str, sizeof(dst_ip_str)) == NULL) {
            LOG_MAIN(ERR, "inet_ntop failed for destination address.");
            perror("inet_ntop failed");
            break;
          }
          LOG_MAIN(DEBUG, "Packet Destination IPv6: %s", dst_ip_str);

          // Retrieve the HMAC key (k_hmac_ie) and its length from global storage.
          // This key is crucial for calculating the HMAC to secure the packet.
          uint8_t *k_hmac_ie = k_pot_in[0];
          size_t key_len = HMAC_MAX_LENGTH;

          // Define the IPv6 address of the ingress node.
          // This is used as part of the HMAC calculation to authenticate the ingress point.
          struct in6_addr ingress_addr;
          inet_pton(AF_INET6, "2a05:d014:dc7:127a:fe22:97ab:a0a8:ff18", &ingress_addr);

          // Determine the length to dump for debugging purposes.
          // Ensures that we don't try to dump more than the actual packet length, limiting to 128 bytes.
          size_t dump_len = rte_pktmbuf_pkt_len(mbuf);
          if (dump_len > 128) dump_len = 128;
          LOG_MAIN(DEBUG, "Packet length for dump: %zu", dump_len);

          uint8_t hmac_out[HMAC_MAX_LENGTH];

          // Calculate the HMAC for the packet.
          // This HMAC is computed over specific packet fields (source address, SRH, HMAC TLV, etc.)
          // using the ingress_addr and the HMAC key.
          if (calculate_hmac((uint8_t *)&ingress_addr, srh, hmac, k_hmac_ie, key_len, hmac_out) == 0) {
            rte_memcpy(hmac->hmac_value, hmac_out, HMAC_MAX_LENGTH);
            LOG_MAIN(DEBUG, "HMAC calculated and copied to packet.");
          } else {
            LOG_MAIN(ERR, "HMAC calculation failed for ingress packet, dropping.");
            break;
          }

          uint8_t nonce[NONCE_LENGTH];

          // Generate a cryptographically secure random nonce.
          // The nonce is essential for the PVF (Path Validation Function) encryption
          // to prevent replay attacks and ensure unique encryption for each packet.
          if (generate_nonce(nonce) != 0) {
            LOG_MAIN(ERR, "Nonce generation failed, dropping packet.");
            break;
          }

          // Encrypt the computed HMAC (now in hmac_out) using the PVF mechanism.
          // This uses the shared secret key (k_pot_in) and the generated nonce.
          encrypt_pvf(k_pot_in, nonce, hmac_out);
          rte_memcpy(pot->encrypted_hmac, hmac_out, HMAC_MAX_LENGTH);
          rte_memcpy(pot->nonce, nonce, NONCE_LENGTH);
          LOG_MAIN(DEBUG, "HMAC encrypted and Nonce added to POT TLV.");

          // Check the 'segments_left' field in the SRH.
          // If segments_left is 0, it means the packet has reached its final destination
          // in the segment routing path, or it's an invalid case for this router.
          if (srh->segments_left == 0) {
            LOG_MAIN(DEBUG, "SRH segments_left is 0, dropping packet.");
            rte_pktmbuf_free(mbuf);
          } else {

            // If segments_left is not 0, the packet needs to be forwarded to the next segment ID.
            // Calculate the index of the next segment ID (SID) in the SRH segment list.
            // srh->last_entry is the total number of segments.
            // srh->segments_left is the number of remaining segments to visit.
            // The next SID is (last_entry - segments_left + 1) index into the segments array.
            int next_sid_index = srh->last_entry - srh->segments_left + 1;
            memcpy(&ipv6_hdr->dst_addr, &srh->segments[next_sid_index], sizeof(struct in6_addr));
            LOG_MAIN(DEBUG, "Updated packet destination to next SID: %s",
                     inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_ip_str, sizeof(dst_ip_str)));

            // Lookup the MAC address corresponding to the new destination IPv6 address (next SID).
            // This is typically done via an ARP/NDP cache or a pre-configured table.
            struct rte_ether_addr *next_mac = lookup_mac_for_ipv6(&srh->segments[next_sid_index]);
            if (next_mac) {

              // If a MAC address is found, send the packet to that MAC address on the appropriate port.
              // rx_port_id is likely used to determine the egress port, or it's explicitly passed.
              send_packet_to(*next_mac, mbuf, rx_port_id);
              LOG_MAIN(DEBUG, "Packet sent to next hop with MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                       next_mac->addr_bytes[0], next_mac->addr_bytes[1], next_mac->addr_bytes[2],
                       next_mac->addr_bytes[3], next_mac->addr_bytes[4], next_mac->addr_bytes[5]);
            } else {
              // If no MAC address is found for the next SID, the packet cannot be forwarded.
              // Free the mbuf to prevent resource leaks.
              LOG_MAIN(ERR, "No MAC found for next SID, dropping packet.");
              rte_pktmbuf_free(mbuf);
            }
          }

          break;
        case 1:

          // Case 1: Bypass all custom header operations.
          // The packet is not modified by this function and will proceed
          // to subsequent processing stages (or be forwarded as-is) without
          // SRH/HMAC/POT functionality.
          LOG_MAIN(DEBUG, "Bypassing custom header operations for ingress packet.");
          break;
          
        // case 2: add_custom_header_only(mbuf); break; // Placeholder for a mode that only adds headers
        // without security operations.
        default: LOG_MAIN(WARNING, "Unknown operation_bypass_bit value: %d", operation_bypass_bit); break;
      }
      break;
    default:
      LOG_MAIN(DEBUG,
               "Packet is not IPv6, not processed by ingress_packet_process. This should not be reached.");
      break;
  }
}

void process_ingress(struct rte_mbuf **pkts, uint16_t nb_rx, uint16_t rx_port_id) {
  // Process each received packet in the ingress queue.
  // This function iterates over the received packets, processes each one,
  // and logs the packet information.
  LOG_MAIN(DEBUG, "Processing %u ingress packets on port %u", nb_rx, rx_port_id);
  for (uint16_t i = 0; i < nb_rx; i++) {
    LOG_MAIN(DEBUG, "Processing packet %u with length %u on port %u", i, rte_pktmbuf_pkt_len(pkts[i]),
             rx_port_id);
    process_ingress_packet(pkts[i], rx_port_id);
  }
}