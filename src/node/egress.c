#include "node/egress.h"

#include "crypto.h"
#include "forward.h"
#include "headers.h"
#include "utils/config.h"
#include "utils/logging.h"

static inline void process_egress_packet(struct rte_mbuf* mbuf) {
  // LOG_MAIN(NOTICE, "Processing egress packet with length %u", rte_pktmbuf_pkt_len(mbuf));
  // LOG_MAIN(NOTICE, "Egress packet nb_segs: %u", mbuf->nb_segs);

  // Add bounds checking before accessing headers
  if (rte_pktmbuf_pkt_len(mbuf) < sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr)) {
    LOG_MAIN(WARNING, "Egress: Packet too small for basic headers, dropping\n");
    rte_pktmbuf_free(mbuf);
    return;
  }

  struct rte_ether_hdr* eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);
  uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

  // Check if the packet is IPv6, if not drop it
  if (ether_type != RTE_ETHER_TYPE_IPV6) {
    LOG_MAIN(NOTICE, "Non-IPv6 packet received in egress (EtherType: %u), dropping.\n", ether_type);
    rte_pktmbuf_free(mbuf);
    return;
  }

  // Check if the destination MAC address is a multicast/broadcast address
  // If the least significant bit of the first byte is set, it's multicast/broadcast
  if ((eth_hdr->dst_addr.addr_bytes[0] & 0x01) != 0) {
    LOG_MAIN(NOTICE, "Multicast/Broadcast packet received in egress, dropping.\n");
    rte_pktmbuf_free(mbuf);
    return;
  }

  switch (ether_type) {
  case RTE_ETHER_TYPE_IPV6:
    LOG_MAIN(DEBUG, "Egress packet is IPv6, processing headers\n");

    // Depending on the operation bypass bit, we either process the packet or bypass operations
    // operation_bypass_bit is a global variable that indicates whether to bypass operations
    // 0: Process packet with SRH and HMAC
    // 1: Bypass all operations
    // 2: Remove headers only (not implemented in this case)
    // This simplifies the process logic, and allows easy extension in the future
    // if needed.
    switch (operation_bypass_bit) {
      LOG_MAIN(DEBUG, "Operation bypass bit is %d\n", operation_bypass_bit);
    case 0: {
      LOG_MAIN(DEBUG, "Processing packet with SRH and HMAC\n");
      struct rte_ipv6_hdr* ipv6_hdr = (struct rte_ipv6_hdr*)(eth_hdr + 1);
      struct ipv6_srh* srh = (struct ipv6_srh*)(ipv6_hdr + 1);

      // Check if the SRH next header is 61 (SRv6). If it is, we proceed with processing.
      // 61 is the next header type for SRv6, as per RFC 8200.
      // If the next header is not 61, we do not process the packet further
      // and simply return.
      if (srh->next_header == 61) {
        LOG_MAIN(DEBUG, "SRH detected, processing packet\n");
        size_t actual_srh_size = (srh->hdr_ext_len * 8) + 8;
        size_t min_packet_size = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr) +
                                 actual_srh_size + sizeof(struct hmac_tlv) + sizeof(struct pot_tlv);
        if (rte_pktmbuf_pkt_len(mbuf) < min_packet_size) {
          LOG_MAIN(WARNING,
                   "Egress: Packet too small (%u bytes) for expected headers (%zu bytes), dropping\n",
                   rte_pktmbuf_pkt_len(mbuf), min_packet_size);
          rte_pktmbuf_free(mbuf);
          return;
        }
        uint8_t* hmac_ptr = (uint8_t*)srh + actual_srh_size;
        struct hmac_tlv* hmac = (struct hmac_tlv*)hmac_ptr;
        uint8_t* pot_ptr = hmac_ptr + sizeof(struct hmac_tlv);
        struct pot_tlv* pot = (struct pot_tlv*)pot_ptr;
        LOG_MAIN(DEBUG, "HMAC TLV type: %u, length: %u\n", hmac->type, hmac->length);

        // Create a buffer to hold the destination IPv6 address as a string
        // Convert the destination IPv6 address from binary to text form.
        // If inet_ntop fails, log an error, free the packet, and exit processing.
        char dst_ip_str[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_ip_str, sizeof(dst_ip_str)) == NULL) {
          LOG_MAIN(ERR, "inet_ntop failed for destination address\n");
          rte_pktmbuf_free(mbuf);
          return;
        }

        LOG_MAIN(DEBUG, "Destination IPv6 address: %s\n", dst_ip_str);
        uint8_t hmac_out[HMAC_MAX_LENGTH];
        memcpy(hmac_out, pot->encrypted_hmac, HMAC_MAX_LENGTH);

        // This code decrypts the HMAC in the PoT TLV structure that was encrypted at ingress.
        // First logs the encrypted HMAC length for debugging
        // Then decrypts the Packet Verification Field (PVF) using:
        //  - k_pot_in[0]: Secret key shared between ingress/egress nodes
        //  - pot->nonce: Prevents replay attacks
        //  - hmac_out: Buffer for decrypted result
        // Finally copies the decrypted HMAC back to the PoT structure
        //
        // After this, the code will verify packet integrity by comparing this HMAC
        // with a freshly calculated value to confirm path compliance
        LOG_MAIN(DEBUG, "Encrypted HMAC length: %zu\n", sizeof(pot->encrypted_hmac));

        uint8_t final_hmac[HMAC_MAX_LENGTH];
        int dec_len = decrypt(pot->encrypted_hmac, HMAC_MAX_LENGTH, k_pot_in[0], pot->nonce, final_hmac);

        if (dec_len < 0) {
          LOG_MAIN(ERR, "Egress: Final PVF decryption failed.\n");
          return;
        }
        // memcpy(pot->encrypted_hmac, hmac_out, HMAC_MAX_LENGTH);
        LOG_MAIN(DEBUG, "Decrypted HMAC length: %zu\n", sizeof(pot->encrypted_hmac));

        // Prepare the HMAC key for verification
        // This key is used to calculate the expected HMAC for the packet.
        uint8_t* k_hmac_ie = k_pot_in[0];
        uint8_t expected_hmac[HMAC_MAX_LENGTH];
        LOG_MAIN(DEBUG, "Calculating expected HMAC with key length %zu\n",
                 HMAC_MAX_LENGTH); // Log the inputs to HMAC calculations for verifications
        //
        // Increase segment_left by 1 to temporarly test if it is the root cause of
        // HMAC verification failure
        srh->segments_left += 1;
        if (calculate_hmac((uint8_t*)&ipv6_hdr->src_addr, srh, hmac, k_hmac_ie, HMAC_MAX_LENGTH,
                           expected_hmac) != 0) {
          LOG_MAIN(ERR, "Egress: HMAC calculation failed\n");
          rte_pktmbuf_free(mbuf);
          return;
        }

        LOG_MAIN(DEBUG, "Comparing calculated HMAC with expected HMAC\n");
        if (memcmp(final_hmac, expected_hmac, HMAC_MAX_LENGTH) != 0) {
          LOG_MAIN(DEBUG, "Final HMAC: ");
          log_hex_data("Final HMAC", final_hmac, HMAC_MAX_LENGTH);
          LOG_MAIN(DEBUG, "Expected HMAC: ");
          log_hex_data("Expected HMAC", expected_hmac, HMAC_MAX_LENGTH);
          LOG_MAIN(ERR, "Egress: HMAC verification failed, dropping packet\n");
          rte_pktmbuf_free(mbuf);
          return;
        }

        // If the HMAC verification is successful, we proceed to remove headers
        // and forward the packet to the iperf server.
        // This includes removing the SRH, HMAC TLV, and PoT TLV
        // from the packet, and then sending it to the iperf server.
        // The final packet will have the original IPv6 header and payload,
        // but without the SRH, HMAC TLV, and PoT TLV.
        // LOG_MAIN(INFO, "Egress: HMAC verified successfully, forwarding packet\n");
        remove_headers(mbuf);

        LOG_MAIN(DEBUG, "Packet after removing headers - length: %u\n", rte_pktmbuf_pkt_len(mbuf));
        struct rte_ether_hdr* eth_hdr_final = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);
        struct rte_ipv6_hdr* ipv6_hdr_final = (struct rte_ipv6_hdr*)(eth_hdr_final + 1);
        LOG_MAIN(DEBUG, "Final packet IPv6 src: %s, dst: %s\n",
                 inet_ntop(AF_INET6, &ipv6_hdr_final->src_addr, NULL, 0),
                 inet_ntop(AF_INET6, &ipv6_hdr_final->dst_addr, NULL, 0));

        char final_src_ip[INET6_ADDRSTRLEN], final_dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ipv6_hdr_final->src_addr, final_src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ipv6_hdr_final->dst_addr, final_dst_ip, INET6_ADDRSTRLEN);
        LOG_MAIN(DEBUG, "Final packet IPv6 src: %s, dst: %s\n", final_src_ip, final_dst_ip);

        // Forward the packet to the iperf server
        // The MAC address of the iperf server is hardcoded here.
        struct rte_ether_addr iperf_mac = {{0x02, 0xca, 0x40, 0x6e, 0x9b, 0xa3}};
        if (g_is_virtual_machine == 0) {
          send_packet_to(iperf_mac, mbuf, 1);
        } else {
          send_packet_to(iperf_mac, mbuf, 0);
        }
        LOG_MAIN(DEBUG, "Packet sent to iperf server with MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
                 iperf_mac.addr_bytes[0], iperf_mac.addr_bytes[1], iperf_mac.addr_bytes[2],
                 iperf_mac.addr_bytes[3], iperf_mac.addr_bytes[4], iperf_mac.addr_bytes[5]);
      }
      break;
    }
    case 1: {
      LOG_MAIN(DEBUG, "Processing packet with SRH\n");
      struct rte_ipv6_hdr* ipv6_hdr = (struct rte_ipv6_hdr*)(eth_hdr + 1);
      struct ipv6_srh* srh = (struct ipv6_srh*)(ipv6_hdr + 1);

      // Check if the SRH next header is 61 (SRv6). If it is, we proceed with processing.
      // 61 is the next header type for SRv6, as per RFC 8200.
      // If the next header is not 61, we do not process the packet further
      // and simply return.
      if (srh->next_header == 61) {
        LOG_MAIN(DEBUG, "SRH detected, processing packet\n");
        size_t actual_srh_size = (srh->hdr_ext_len * 8) + 8;
        size_t min_packet_size = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr) + actual_srh_size;
        if (rte_pktmbuf_pkt_len(mbuf) < min_packet_size) {
          LOG_MAIN(WARNING,
                   "Egress: Packet too small (%u bytes) for expected headers (%zu bytes), dropping\n",
                   rte_pktmbuf_pkt_len(mbuf), min_packet_size);
          rte_pktmbuf_free(mbuf);
          return;
        }

        // Create a buffer to hold the destination IPv6 address as a string
        // Convert the destination IPv6 address from binary to text form.
        // If inet_ntop fails, log an error, free the packet, and exit processing.
        char dst_ip_str[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_ip_str, sizeof(dst_ip_str)) == NULL) {
          LOG_MAIN(ERR, "inet_ntop failed for destination address\n");
          rte_pktmbuf_free(mbuf);
          return;
        }

        LOG_MAIN(DEBUG, "Destination IPv6 address: %s\n", dst_ip_str);

        srh->segments_left += 1;

        // If the HMAC verification is successful, we proceed to remove headers
        // and forward the packet to the iperf server.
        // This includes removing the SRH, HMAC TLV, and PoT TLV
        // from the packet, and then sending it to the iperf server.
        // The final packet will have the original IPv6 header and payload,
        // but without the SRH, HMAC TLV, and PoT TLV.
        // LOG_MAIN(INFO, "Egress: HMAC verified successfully, forwarding packet\n");
        remove_headers(mbuf);

        LOG_MAIN(DEBUG, "Packet after removing headers - length: %u\n", rte_pktmbuf_pkt_len(mbuf));
        struct rte_ether_hdr* eth_hdr_final = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);
        struct rte_ipv6_hdr* ipv6_hdr_final = (struct rte_ipv6_hdr*)(eth_hdr_final + 1);
        struct rte_udp_hdr* udp_hdr = (struct rte_udp_hdr*)((char*)ipv6_hdr_final + sizeof(struct rte_ipv6_hdr));

        LOG_MAIN(DEBUG, "UDP payload length before sending: %u", 
                rte_be_to_cpu_16(udp_hdr->dgram_len));

        // Store original UDP ports before any modification
        uint16_t orig_src_port = rte_be_to_cpu_16(udp_hdr->src_port);
        uint16_t orig_dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);

        LOG_MAIN(DEBUG, "Original UDP ports - Source: %d, Destination: %d",
                orig_src_port, orig_dst_port);

        // Verify payload length matches IPv6 length
        uint16_t ipv6_payload_len = rte_be_to_cpu_16(ipv6_hdr_final->payload_len);
        uint16_t udp_total_len = rte_be_to_cpu_16(udp_hdr->dgram_len);

        LOG_MAIN(DEBUG, "IPv6 payload length: %u, UDP total length: %u",
                ipv6_payload_len, udp_total_len);

        if (ipv6_payload_len != udp_total_len) {
            LOG_MAIN(WARNING, "Mismatch between IPv6 payload length and UDP length");
            // Fix UDP length if needed
            udp_hdr->dgram_len = ipv6_hdr_final->payload_len;
        }

        // Set destination port to 5001 (iperf)
        udp_hdr->dst_port = rte_cpu_to_be_16(5001);
        LOG_MAIN(DEBUG, "Updated UDP destination port to 5001");

        // Ensure source port is preserved from original packet
        if (orig_src_port != 0) {
            udp_hdr->src_port = rte_cpu_to_be_16(orig_src_port);
        } else {
            // If original source port was 0, use a default ephemeral port
            udp_hdr->src_port = rte_cpu_to_be_16(49152); // First ephemeral port
            LOG_MAIN(DEBUG, "Set source port to ephemeral port 49152");
        }

        // Recalculate UDP checksum after all port changes
        udp_hdr->dgram_cksum = 0;
        udp_hdr->dgram_cksum = rte_ipv6_udptcp_cksum(ipv6_hdr_final, udp_hdr);

        LOG_MAIN(DEBUG, "UDP ports - Source: %d, Destination: %d",
                rte_be_to_cpu_16(udp_hdr->src_port),
                rte_be_to_cpu_16(udp_hdr->dst_port));

        // Log packet details before sending
        rte_hexdump(stdout, "UDP Payload", 
                    (void*)((char*)udp_hdr + sizeof(struct rte_udp_hdr)),
                    rte_be_to_cpu_16(udp_hdr->dgram_len) - sizeof(struct rte_udp_hdr));

        LOG_MAIN(DEBUG, "Final packet IPv6 src: %s, dst: %s\n",
                 inet_ntop(AF_INET6, &ipv6_hdr_final->src_addr, NULL, 0),
                 inet_ntop(AF_INET6, &ipv6_hdr_final->dst_addr, NULL, 0));

        char final_src_ip[INET6_ADDRSTRLEN], final_dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ipv6_hdr_final->src_addr, final_src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ipv6_hdr_final->dst_addr, final_dst_ip, INET6_ADDRSTRLEN);
        LOG_MAIN(DEBUG, "Final packet IPv6 src: %s, dst: %s\n", final_src_ip, final_dst_ip);

        // Forward the packet to the iperf server
        // The MAC address of the iperf server is hardcoded here.
        struct rte_ether_addr iperf_mac = {{0x02, 0xca, 0x40, 0x6e, 0x9b, 0xa3}};
        if (g_is_virtual_machine == 0) {
          send_packet_to(iperf_mac, mbuf, 1);
        } else {
          send_packet_to(iperf_mac, mbuf, 0);
        }
        LOG_MAIN(DEBUG, "Packet sent to iperf server with MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
                 iperf_mac.addr_bytes[0], iperf_mac.addr_bytes[1], iperf_mac.addr_bytes[2],
                 iperf_mac.addr_bytes[3], iperf_mac.addr_bytes[4], iperf_mac.addr_bytes[5]);
      }
    } break;
    }
  }
}

void process_egress(struct rte_mbuf** pkts, uint16_t nb_rx) {
  // Processes each received packet in the egress queue.
  // This function iterates over the received packets, processes each one,
  // and logs the packet information.
  // It is called by the egress node to handle packets that are ready to be sent
  // out of the egress node.
  // LOG_MAIN(NOTICE, "Processing %u egress packets\n", nb_rx);
  for (uint16_t i = 0; i < nb_rx; i++) {
    // Skip per-packet logging to reduce spam
    process_egress_packet(pkts[i]);
  }
}
