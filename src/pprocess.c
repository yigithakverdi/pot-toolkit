#include "pprocess.h"

#include <arpa/inet.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <stdint.h>
#include <sys/socket.h>

#include "common.h"
#include "crypto.h"

enum role global_role = ROLE_INGRESS;

// Functions appends an SRH structure immidiately after the IPv6 header in the packet.
// This header contains fields such as:
//
// - next_header: the type of the next header (e.g., TCP, UDP)
// - hdr_ext_len: the length of the SRH in 8-byte units
// - routing_type: the type of routing (4 for SRv6)
// - segments_left: the number of segments left to visit
// - last_entry: the last entry in the SRH
//
// and an array of IPv6 segments that represent the path the packet should take.
// This effectively inserts a segment routing header into the packet.
//
// Right after the SRH addition, an HMAC TLV (Type-Length-Value) structure is appended
// to the packet. This structure is reserved to carry a computed HMAC value for integrity
// verification. Later on the forwarding loop (for operation_bypass_bit == 0) the code,
// realings the pointers to access SRH, HMAC TLV and POT headers.
//
// It then computes an HMAC (using OpenSSL's HMAC with SHA-256) over the selected fields
// of the packet, and writes the result into the `hmac->hmac_value` field of the HMAC
// TLV structure.
void add_custom_header(struct rte_mbuf *pkt) {
  // Packet must be large enough to hold the new headers
  if (rte_pktmbuf_tailroom(pkt) < sizeof(struct ipv6_srh) + sizeof(struct hmac_tlv)) {
    rte_pktmbuf_free(pkt);
    RTE_LOG(ERR, USER1, "Packet too small for custom headers\n");
    return;
  }

  // Packet headers and payload pointers
  struct ipv6_srh *srh_hdr;
  struct hmac_tlv *hmac_hdr;
  struct pot_tlv *pot_hdr;
  struct rte_ether_hdr *eth_hdr_6 = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
  struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr_6 + 1);
  uint8_t *payload = (uint8_t *)(ipv6_hdr + 1);

  size_t payload_size = rte_pktmbuf_pkt_len(pkt) - 54;
  uint8_t *tmp_payload = rte_malloc("tmp_payload", payload_size, RTE_CACHE_LINE_SIZE);
  if (tmp_payload == NULL) {
    rte_pktmbuf_free(pkt);
    RTE_LOG(ERR, USER1, "rte_malloc failed\n");
    return;
  }

  // Move the payload to a temporary buffer
  rte_memcpy(tmp_payload, payload, payload_size);

  // Remove the payload
  rte_pktmbuf_trim(pkt, payload_size);

  // Add the custom headers in order and finally add the payload back
  srh_hdr = (struct ipv6_srh *)rte_pktmbuf_append(pkt, sizeof(struct ipv6_srh));
  hmac_hdr = (struct hmac_tlv *)rte_pktmbuf_append(pkt, sizeof(struct hmac_tlv));
  pot_hdr = (struct pot_tlv *)rte_pktmbuf_append(pkt, sizeof(struct pot_tlv));
  payload = (uint8_t *)rte_pktmbuf_append(pkt, payload_size);

  // Reinsert the payload
  rte_memcpy(payload, tmp_payload, payload_size);
  rte_free(tmp_payload);

  // Populate the newly added headers through `rte_pktmbuf_append` on the above.
  pot_hdr->type = 1;
  pot_hdr->length = 48;
  pot_hdr->reserved = 0;
  pot_hdr->nonce_length = 16;
  pot_hdr->key_set_id = rte_cpu_to_be_32(1234);
  memset(pot_hdr->nonce, 0, sizeof(pot_hdr->nonce));
  memset(pot_hdr->encrypted_hmac, 0, sizeof(pot_hdr->encrypted_hmac));

  hmac_hdr->type = 5;
  hmac_hdr->length = 16;
  hmac_hdr->d_flag = 0;
  hmac_hdr->reserved = 0;
  hmac_hdr->hmac_key_id = rte_cpu_to_be_32(1234);
  memset(hmac_hdr->hmac_value, 0, sizeof(hmac_hdr->hmac_value));

  srh_hdr->next_header = 61;
  srh_hdr->hdr_ext_len = 2;
  srh_hdr->routing_type = 4;
  srh_hdr->last_entry = 0;
  srh_hdr->flags = 0;
  srh_hdr->segments_left = 1;
  memset(srh_hdr->reserved, 0, 2);

  struct in6_addr segments[] = {
      {.s6_addr = {0x2a, 0x05, 0xd0, 0x14, 0x0d, 0xc7, 0x12, 0xdc, 0x96, 0x48, 0x6b, 0xf3, 0xe1, 0x82, 0xc7,
                   0xb4}},  // Transit Node IP

      {.s6_addr = {0x2a, 0x05, 0xd0, 0x14, 0x0d, 0xc7, 0x12, 0xdc, 0x96, 0x48, 0x6b, 0xf3, 0xe1, 0x82, 0xc7,
                   0xb4}}};  // Example next hop or placeholder
  memcpy(srh_hdr->segments, segments, sizeof(segments));
  RTE_LOG(INFO, USER1, "Custom headers added to packet\n");

  // Dump the first 128 bytes (or the whole packet if smaller)
  size_t dump_len = rte_pktmbuf_pkt_len(pkt);
  if (dump_len > 128) dump_len = 128;
  printf("Packet hex dump after custom header addition (first %zu bytes):\n", dump_len);
  hex_dump(rte_pktmbuf_mtod(pkt, void *), dump_len);
}

void add_custom_header_only(struct rte_mbuf *pkt) {
  // Packet must be large enough to hold the new headers
  if (rte_pktmbuf_tailroom(pkt) < sizeof(struct ipv6_srh)) { // Adjusted tailroom check
    rte_pktmbuf_free(pkt);
    RTE_LOG(ERR, USER1, "Packet too small for custom headers\\n");
    return;
  }

  // Packet headers and payload pointers
  struct ipv6_srh *srh_hdr;
  // struct hmac_tlv *hmac_hdr; // Removed unused variable
  // struct pot_tlv *pot_hdr;   // Removed unused variable
  struct rte_ether_hdr *eth_hdr_6 = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
  struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr_6 + 1);
  uint8_t *payload = (uint8_t *)(ipv6_hdr + 1);

  size_t payload_size = rte_pktmbuf_pkt_len(pkt) - 54;
  uint8_t *tmp_payload = rte_malloc("tmp_payload", payload_size, RTE_CACHE_LINE_SIZE);
  if (tmp_payload == NULL) {
    rte_pktmbuf_free(pkt);
    RTE_LOG(ERR, USER1, "rte_malloc failed\n");
    return;
  }

  // Move the payload to a temporary buffer
  rte_memcpy(tmp_payload, payload, payload_size);

  // Remove the payload
  rte_pktmbuf_trim(pkt, payload_size);

  // Add the custom headers in order and finally add the payload back
  srh_hdr = (struct ipv6_srh *)rte_pktmbuf_append(pkt, sizeof(struct ipv6_srh));
  payload = (uint8_t *)rte_pktmbuf_append(pkt, payload_size);

  // Reinsert the payload
  rte_memcpy(payload, tmp_payload, payload_size);
  rte_free(tmp_payload);

  srh_hdr->next_header = 61;
  srh_hdr->hdr_ext_len = 2;
  srh_hdr->routing_type = 4;
  srh_hdr->last_entry = 0;
  srh_hdr->flags = 0;
  srh_hdr->segments_left = 1;
  memset(srh_hdr->reserved, 0, 2);

  struct in6_addr segments[] = {
      {.s6_addr = {0x2a, 0x05, 0xd0, 0x14, 0x0d, 0xc7, 0x12, 0xdc, 0x96, 0x48, 0x6b, 0xf3, 0xe1, 0x82, 0xc7,
                   0xb4}},  // Transit Node IP

      {.s6_addr = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x01}}};  // Example next hop or placeholder
  memcpy(srh_hdr->segments, segments, sizeof(segments));

  // Log als the segments
  printf("SRH segments:\n");
  for (int i = 0; i < srh_hdr->segments_left; i++) {
    char segment_str[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, &srh_hdr->segments[i], segment_str, sizeof(segment_str)) == NULL) {
      perror("inet_ntop failed");
    } else {
      printf("Segment %d: %s\n", i, segment_str);
    }
  }
  RTE_LOG(INFO, USER1, "Custom headers added to packet\n");
}

// Helper: process a single packet for ingress
static inline void process_ingress_packet(struct rte_mbuf *mbuf, uint16_t rx_port_id) {
  printf("Processing ingress packet on lcore %u\n", rte_lcore_id());
  struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
  uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

  // 1. Skip non-IPv6
  if (ether_type != RTE_ETHER_TYPE_IPV6) {
    printf("Ingress: Not an IPv6 packet, skipping and freeing mbuf\n");
    rte_pktmbuf_free(mbuf);
    return;
  }

  // 2. Skip non-unicast (multicast/broadcast) destination MAC
  if ((eth_hdr->dst_addr.addr_bytes[0] & 0x01) != 0) {
    printf("Ingress: Multicast/Broadcast MAC, skipping and freeing mbuf\n");
    // Print more info for debugging
    printf("  MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", eth_hdr->dst_addr.addr_bytes[0],
           eth_hdr->dst_addr.addr_bytes[1], eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
           eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);
    struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
    printf("  IPv6 src: ");
    print_ipv6_address((struct in6_addr *)&ipv6_hdr->src_addr, "");
    printf("  IPv6 dst: ");
    print_ipv6_address((struct in6_addr *)&ipv6_hdr->dst_addr, "");
    printf("  EtherType: 0x%04x\n", ether_type);
    printf("  Next header: %u\n", ipv6_hdr->proto);
    if (ipv6_hdr->proto == IPPROTO_UDP) {
      struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ipv6_hdr + 1);
      printf("  UDP src port: %u, dst port: %u\n", ntohs(udp_hdr->src_port), ntohs(udp_hdr->dst_port));
    } else if (ipv6_hdr->proto == IPPROTO_TCP) {
      struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)(ipv6_hdr + 1);
      printf("  TCP src port: %u, dst port: %u\n", ntohs(tcp_hdr->src_port), ntohs(tcp_hdr->dst_port));
    }
    rte_pktmbuf_free(mbuf);
    return;
  }

  switch (ether_type) {
    case RTE_ETHER_TYPE_IPV6:
      switch (operation_bypass_bit) {
        case 0:
          printf("Processing IPv6 packet with operation_bypass_bit = 0\n");
          add_custom_header(mbuf);

          // Realign pointers after header addition
          printf("Realigning pointers after adding custom headers\n");
          struct rte_ether_hdr *eth_hdr6 = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
          struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr6 + 1);
          struct ipv6_srh *srh = (struct ipv6_srh *)(ipv6_hdr + 1);
          struct hmac_tlv *hmac = (struct hmac_tlv *)(srh + 1);
          struct pot_tlv *pot = (struct pot_tlv *)(hmac + 1);

          // Extract destination IPv6 address as string
          printf("Extracting destination IPv6 address\n");
          char dst_ip_str[INET6_ADDRSTRLEN];
          if (inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_ip_str, sizeof(dst_ip_str)) == NULL) {
            perror("inet_ntop failed");
            break;
          }

          // Prepare k_pot_in array using the loaded key for all SIDs
          printf("Preparing k_pot_in array for all SIDs\n");
          uint8_t k_pot_in[SID_NO][HMAC_MAX_LENGTH] = {0};
          for (int sid = 0; sid < SID_NO; sid++) {
            if (read_encryption_key("keys.txt", dst_ip_str, k_pot_in[sid], HMAC_MAX_LENGTH) != 0) {
              printf("Failed to read key for %s\n", dst_ip_str);
              break;
            }
          }

          // Prepare HMAC key (use same as encryption key for demo)
          printf("Preparing HMAC key for HMAC computation\n");
          uint8_t k_hmac_ie[HMAC_MAX_LENGTH] = {0};
          if (read_encryption_key("keys.txt", dst_ip_str, k_hmac_ie, HMAC_MAX_LENGTH) != 0) {
            printf("Failed to read HMAC key for %s\n", dst_ip_str);
            break;
          }
          size_t key_len = HMAC_MAX_LENGTH;

          // Compute HMAC
          printf("Computing HMAC for the packet\n");
          uint8_t hmac_out[HMAC_MAX_LENGTH];
          if (calculate_hmac((uint8_t *)&ipv6_hdr->src_addr, srh, hmac, k_hmac_ie, key_len, hmac_out) == 0) {
            printf("HMAC Computation Successful\nHMAC: ");
            for (int i = 0; i < HMAC_MAX_LENGTH; i++) printf("%02x", hmac_out[i]);
            printf("\n");
            rte_memcpy(hmac->hmac_value, hmac_out, HMAC_MAX_LENGTH);
            printf("HMAC value inserted to srh_hmac header\n");
          } else {
            printf("HMAC Computation Failed\n");
            break;
          }

          // Nonce Generation and Encryption (PVF Computation)
          printf("Generating nonce and encrypting PVF\n");
          uint8_t nonce[NONCE_LENGTH];
          if (generate_nonce(nonce) != 0) {
            printf("Nonce generation failed, returning\n");
            break;
          }
          encrypt_pvf(k_pot_in, nonce, hmac_out);
          printf("Encrypted PVF before writing to the header: ");
          for (int i = 0; i < HMAC_MAX_LENGTH; i++) printf("%02x", hmac_out[i]);
          printf("\n");
          rte_memcpy(pot->encrypted_hmac, hmac_out, HMAC_MAX_LENGTH);
          rte_memcpy(pot->nonce, nonce, NONCE_LENGTH);
          printf("Encrypted PVF and nonce values inserted to pot header\n");

          // Forward the packet using the `send_packet_to` function
          printf("Forwarding packet to next hop\n");

          if (srh->segments_left == 0) {
            printf("No segments left in SRH, would not forward.\n");
          } else {
            int next_sid_index = srh->segments_left - 1;
            char next_sid_str[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, &srh->segments[next_sid_index], next_sid_str, sizeof(next_sid_str)) ==
                NULL) {
              perror("inet_ntop failed for next segment");
            } else {
              printf("Next segment IPv6 (from SRH): %s\n", next_sid_str);
            }

            // Lookup MAC for next segment
            struct rte_ether_addr *next_mac = lookup_mac_for_ipv6(&srh->segments[next_sid_index]);
            if (next_mac) {
              printf("Resolved next-hop MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", next_mac->addr_bytes[0],
                     next_mac->addr_bytes[1], next_mac->addr_bytes[2], next_mac->addr_bytes[3],
                     next_mac->addr_bytes[4], next_mac->addr_bytes[5]);
            } else {
              printf("No MAC mapping found for next segment IPv6!\n");
            }

            // Store original DstIP (ingress's own IP for this interface) to use as SrcIP later
            struct in6_addr ingress_own_ip_as_src;
            memcpy(&ingress_own_ip_as_src, &ipv6_hdr->dst_addr, sizeof(struct in6_addr));

            // Update the main IPv6 header's Destination Address to the next segment.
            memcpy(&ipv6_hdr->dst_addr, &srh->segments[next_sid_index], sizeof(struct in6_addr));

            // Update the main IPv6 header's Source Address to the ingress node's own IP.
            memcpy(&ipv6_hdr->src_addr, &ingress_own_ip_as_src, sizeof(struct in6_addr));

            // Get the MAC address of the ingress DPDK port (which will be the source MAC)
            struct rte_ether_addr ingress_port_mac;
            rte_eth_macaddr_get(rx_port_id, &ingress_port_mac);

            // Print what the packet's destination/source MAC and IPv6 would be
            printf("Packet would be sent with:\n");
            printf("  Src MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", ingress_port_mac.addr_bytes[0],
                   ingress_port_mac.addr_bytes[1], ingress_port_mac.addr_bytes[2],
                   ingress_port_mac.addr_bytes[3], ingress_port_mac.addr_bytes[4],
                   ingress_port_mac.addr_bytes[5]);
            if (next_mac) {
              printf("  Dst MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", next_mac->addr_bytes[0],
                     next_mac->addr_bytes[1], next_mac->addr_bytes[2], next_mac->addr_bytes[3],
                     next_mac->addr_bytes[4], next_mac->addr_bytes[5]);
            }
            printf("  Src IPv6: ");
            print_ipv6_address((struct in6_addr *)&ipv6_hdr->src_addr, "");
            printf("  Dst IPv6: ");
            print_ipv6_address((struct in6_addr *)&ipv6_hdr->dst_addr, "");

            // Actually send the packet
            if (next_mac) {
              send_packet_to(*next_mac, mbuf, rx_port_id);
            } else {
              printf("No MAC address found for next segment, dropping packet\n");
              rte_pktmbuf_free(mbuf);
            }
          }

          break;
        case 1:
          // Bypass all operations
          break;
        case 2: add_custom_header_only(mbuf); break;
        default: break;
      }
      break;
    default: break;
  }
}

static inline void process_ingress(struct rte_mbuf **pkts, uint16_t nb_rx, uint16_t rx_port_id) {
  printf("Starting process on ingress role with %u packets\n", nb_rx);
  for (uint16_t i = 0; i < nb_rx; i++) {
    process_ingress_packet(pkts[i], rx_port_id);
  }
}

// Helper: process a single packet for transit
static inline void process_transit_packet(struct rte_mbuf *mbuf, int i) {
  struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
  uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

  // Skip non-unicast (multicast/broadcast) destination MAC
  if ((eth_hdr->dst_addr.addr_bytes[0] & 0x01) != 0) {
    printf("Transit: Multicast/Broadcast MAC, skipping and freeing mbuf\n");
    // Print more info for debugging
    printf("  MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", eth_hdr->dst_addr.addr_bytes[0],
           eth_hdr->dst_addr.addr_bytes[1], eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
           eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);
    struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
    printf("  IPv6 src: ");
    print_ipv6_address((struct in6_addr *)&ipv6_hdr->src_addr, "");
    printf("  IPv6 dst: ");
    print_ipv6_address((struct in6_addr *)&ipv6_hdr->dst_addr, "");
    printf("  EtherType: 0x%04x\n", ether_type);
    printf("  Next header: %u\n", ipv6_hdr->proto);
    if (ipv6_hdr->proto == IPPROTO_UDP) {
      struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ipv6_hdr + 1);
      printf("  UDP src port: %u, dst port: %u\n", ntohs(udp_hdr->src_port), ntohs(udp_hdr->dst_port));
    } else if (ipv6_hdr->proto == IPPROTO_TCP) {
      struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)(ipv6_hdr + 1);
      printf("  TCP src port: %u, dst port: %u\n", ntohs(tcp_hdr->src_port), ntohs(tcp_hdr->dst_port));
    }
    rte_pktmbuf_free(mbuf);
    return;
  }

  switch (ether_type) {
    case RTE_ETHER_TYPE_IPV6:
      switch (operation_bypass_bit) {
        case 0: { // Added braces for case block
          struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
          struct ipv6_srh *srh = (struct ipv6_srh *)(ipv6_hdr + 1);

          // Only process packets with your SRH
          if (srh->next_header != 61 || srh->routing_type != 4) {
            printf("Packet %d: Not a valid SRH packet, skipping\n", i + 1);
            rte_pktmbuf_free(mbuf);
            return;
          }

          if (srh->next_header == 61) {
            printf("SRH detected at transit node \n");

            struct hmac_tlv *hmac = (struct hmac_tlv *)(srh + 1);
            struct pot_tlv *pot = (struct pot_tlv *)(hmac + 1);

            // Display source and destination MAC addresses
            printf("Packet %d:\n", i + 1);
            printf("  Src MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
                   "\n",
                   eth_hdr->src_addr.addr_bytes[0], eth_hdr->src_addr.addr_bytes[1],
                   eth_hdr->src_addr.addr_bytes[2], eth_hdr->src_addr.addr_bytes[3],
                   eth_hdr->src_addr.addr_bytes[4], eth_hdr->src_addr.addr_bytes[5]);
            printf("  Dst MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
                   "\n",
                   eth_hdr->dst_addr.addr_bytes[0], eth_hdr->dst_addr.addr_bytes[1],
                   eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
                   eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);
            printf("  EtherType: 0x%04x\n", rte_be_to_cpu_16(eth_hdr->ether_type));

            print_ipv6_address((struct in6_addr *)&ipv6_hdr->src_addr, "source");
            print_ipv6_address((struct in6_addr *)&ipv6_hdr->dst_addr, "destination");

            printf("The size of srh is %lu\n", sizeof(*srh));
            printf("The size of hmac is %lu\n", sizeof(*hmac));
            printf("The size of pot is %lu\n", sizeof(*pot));

            printf("HMAC type: %u\n", hmac->type);
            printf("HMAC length: %u\n", hmac->length);
            printf("HMAC key ID: %u\n", rte_be_to_cpu_32(hmac->hmac_key_id));
            printf("HMAC size: %ld\n", sizeof(hmac->hmac_value));

            // Decrypt the POT field (PVF) if needed
            char dst_ip_str[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_ip_str, sizeof(dst_ip_str)) == NULL) {
              perror("inet_ntop failed");
              rte_pktmbuf_free(mbuf);
              return;
            }

            uint8_t k_pot_in_transit[1][HMAC_MAX_LENGTH] = {{0}}; // Changed declaration
            if (read_encryption_key("keys.txt", dst_ip_str, k_pot_in_transit[0], HMAC_MAX_LENGTH) != 0) { // Read into k_pot_in_transit[0]
              printf("Failed to read key for %s\n", dst_ip_str);
              rte_pktmbuf_free(mbuf);
              return;
            }

            printf("Decrypting PVF for %s\n", dst_ip_str);
            uint8_t pvf_out[HMAC_MAX_LENGTH];
            memcpy(pvf_out, pot->encrypted_hmac, HMAC_MAX_LENGTH);
            decrypt_pvf(k_pot_in_transit, pot->nonce, pvf_out); // Use k_pot_in_transit
            memcpy(pot->encrypted_hmac, pvf_out, HMAC_MAX_LENGTH);

            // SRH forwarding logic
            if (srh->segments_left == 0) {
              printf("Transit: No more segments left, dropping or processing as egress\n");
              rte_pktmbuf_free(mbuf);
              return;
            }

            printf("Transit: Forwarding to next segment, segments left: %d\n", srh->segments_left);
            srh->segments_left--;
            memcpy(&ipv6_hdr->dst_addr, &srh->segments[srh->segments_left], sizeof(ipv6_hdr->dst_addr));

            // Lookup MAC for new IPv6 destination
            struct rte_ether_addr *next_mac = lookup_mac_for_ipv6((struct in6_addr *)&ipv6_hdr->dst_addr); // Added cast
            printf("Transit: Next segment IPv6: %s\n",
                   inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_ip_str, sizeof(dst_ip_str)));
            if (next_mac) {
              printf("Transit: Found MAC for next segment: %02X:%02X:%02X:%02X:%02X:%02X\n",
                     next_mac->addr_bytes[0], next_mac->addr_bytes[1], next_mac->addr_bytes[2],
                     next_mac->addr_bytes[3], next_mac->addr_bytes[4], next_mac->addr_bytes[5]);
              send_packet_to(*next_mac, mbuf, /*tx_port_id*/ 0);
            } else {
              printf("Transit: No MAC mapping for next segment!\n");
              rte_pktmbuf_free(mbuf);
            }
          }
          break;
        } // Added braces for case block
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

static inline void process_transit(struct rte_mbuf **pkts, uint16_t nb_rx) {
  for (uint16_t i = 0; i < nb_rx; i++) {
    process_transit_packet(pkts[i], i);
  }
}

// Helper: process a single packet for egress
static inline void process_egress_packet(struct rte_mbuf *mbuf) {
  // struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
  // uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
  // switch (ether_type) {
  //   case RTE_ETHER_TYPE_IPV6:
  //     switch (operation_bypass_bit) {
  //       case 0: remove_headers(mbuf); break;
  //       case 1:
  //         // Bypass all operations
  //         break;
  //       case 2: remove_headers_only(mbuf); break;
  //       default: break;
  //     }
  //     break;
  //   default: break;
  // }
}

static inline void process_egress(struct rte_mbuf **pkts, uint16_t nb_rx) {
  for (uint16_t i = 0; i < nb_rx; i++) {
    process_egress_packet(pkts[i]);
  }
}

int lcore_main_forward(void *arg) {
  printf("Starting lcore_main_forward\n");

  // Parse arguments (ports) from input.
  uint16_t *ports = (uint16_t *)arg;
  uint16_t rx_port_id = ports[0];
  // uint16_t tx_port_id = ports[1]; // Assuming tx_port_id might be needed later
  printf("RX Port ID: %u\n",
         rx_port_id);  // Removed TX Port ID from this line as it's not used yet in this context

  enum role cur_role = global_role;  // Use global_role set from main.c
  printf("Current role: %s\n",
         cur_role == ROLE_INGRESS ? "INGRESS" : (cur_role == ROLE_TRANSIT ? "TRANSIT" : "EGRESS"));

  // Main processing loop.
  printf("Entering main forwarding loop on lcore %u\n", rte_lcore_id());
  while (1) {
    struct rte_mbuf *pkts[BURST_SIZE];
    uint16_t nb_rx = rte_eth_rx_burst(rx_port_id, 0, pkts, BURST_SIZE);

    if (nb_rx == 0) continue;

    if (nb_rx > 0) {
      struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkts[0], struct rte_ether_hdr *);
      printf("Received %u packets on port %u, EtherType: 0x%04x\n", nb_rx, rx_port_id,
             rte_be_to_cpu_16(eth_hdr->ether_type));
      uint8_t *data = rte_pktmbuf_mtod(pkts[0], uint8_t *);
      printf("First 8 bytes: %02x %02x %02x %02x %02x %02x %02x %02x\n", data[0], data[1], data[2], data[3],
             data[4], data[5], data[6], data[7]);
    }

    // Route packet batch to the appropriate processing logic.
    switch (cur_role) {
      case ROLE_INGRESS: process_ingress(pkts, nb_rx, rx_port_id); break;
      case ROLE_TRANSIT: process_transit(pkts, nb_rx); break;
      case ROLE_EGRESS: process_egress(pkts, nb_rx); break;
      default: break;
    }

    // Send processed packets out.
    // uint16_t nb_tx = rte_eth_tx_burst(tx_port_id, 0, pkts, nb_rx);

    // Free any unsent packets.
    // if (nb_tx < nb_rx) {
    //   uint16_t i;
    //   for (i = nb_tx; i < nb_rx; i++) rte_pktmbuf_free(pkts[i]);
    // }
  }
  return 0;
}

void launch_lcore_forwarding(uint16_t *ports) {
  unsigned lcore_id = rte_get_next_lcore(-1, 1, 0);
  rte_eal_remote_launch(lcore_main_forward, (void *)ports, lcore_id);
  rte_eal_mp_wait_lcore();  // Wait for all lcores to finish (optional, for clean shutdown)
}