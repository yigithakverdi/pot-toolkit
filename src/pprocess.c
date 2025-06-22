#include "pprocess.h"

#include <arpa/inet.h>
#include <inttypes.h>
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

void remove_headers(struct rte_mbuf *pkt) {
  struct rte_ether_hdr *eth_hdr_6 = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
  struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr_6 + 1);
  struct ipv6_srh *srh = (struct ipv6_srh *)(ipv6_hdr + 1);
  struct hmac_tlv *hmac = (struct hmac_tlv *)(srh + 1);
  struct pot_tlv *pot = (struct pot_tlv *)(hmac + 1);
  uint8_t *payload = (uint8_t *)(pot + 1);

  printf("[EGRESS] Processing verified packet for forwarding to iperf server\n");
  printf("[EGRESS] Packet before removing headers - length: %u\n", rte_pktmbuf_pkt_len(pkt));

  char pre_dst_str[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, pre_dst_str, sizeof(pre_dst_str));
  printf("[EGRESS] Pre-modification IPv6 destination: %s\n", pre_dst_str);

  printf("[DEBUG-REMOVE] Original packet before header removal:\n");
  printf("  Packet length: %u bytes\n", rte_pktmbuf_pkt_len(pkt));
  printf("  IPv6 next header: %u\n", ipv6_hdr->proto);
  printf("  SRH next header: %u\n", srh->next_header);
  printf("  IPv6 payload length: %u bytes\n", rte_be_to_cpu_16(ipv6_hdr->payload_len));

  // Calculate payload size correctly
  size_t headers_size = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr) + sizeof(struct ipv6_srh) +
                        sizeof(struct hmac_tlv) + sizeof(struct pot_tlv);
  size_t payload_size = rte_pktmbuf_pkt_len(pkt) - headers_size;

  printf("  Calculated payload size: %lu bytes\n", payload_size);
  printf("[DEBUG-REMOVE] Header sizes: Eth=%lu, IPv6=%lu, SRH=%lu, HMAC=%lu, POT=%lu\n",
         sizeof(struct rte_ether_hdr), sizeof(struct rte_ipv6_hdr), sizeof(struct ipv6_srh),
         sizeof(struct hmac_tlv), sizeof(struct pot_tlv));
  printf("[DEBUG-REMOVE] Total headers size: %lu bytes\n", headers_size);

  // Copy payload to temporary buffer
  uint8_t *tmp_payload = malloc(payload_size);
  if (tmp_payload == NULL) {
    printf("malloc failed\n");
    return;
  }
  memcpy(tmp_payload, payload, payload_size);
  printf("[DEBUG-REMOVE] Payload copied to temp buffer (%lu bytes)\n", payload_size);
  printf("[DEBUG-REMOVE] First 16 bytes of payload: ");
  for (int i = 0; i < (payload_size < 16 ? payload_size : 16); i++) {
    printf("%02x ", tmp_payload[i]);
  }
  printf("\n");

  // Calculate how much to trim (everything except Ethernet + IPv6 + payload)
  size_t trim_size = rte_be_to_cpu_16(ipv6_hdr->payload_len);
  printf("[DEBUG-REMOVE] Trimming %lu bytes from packet\n", trim_size);
  rte_pktmbuf_trim(pkt, trim_size);

  // Restore the original next header (UDP = 17)
  ipv6_hdr->proto = 17;

  // Set the destination IPv6 address to the iperf server's address
  struct in6_addr iperf_server_ipv6;
  if (inet_pton(AF_INET6, "2a05:d014:dc7:12c2:724:c0e1:c16d:2f16", &iperf_server_ipv6) != 1) {
    printf("Error converting IPv6 address\n");
    free(tmp_payload);
    return;
  }
  memcpy(&ipv6_hdr->dst_addr, &iperf_server_ipv6, sizeof(struct in6_addr));

  // Append the payload back
  uint8_t *new_payload = (uint8_t *)rte_pktmbuf_append(pkt, payload_size);
  if (new_payload == NULL) {
    printf("Failed to append payload back to packet\n");
    free(tmp_payload);
    return;
  }
  memcpy(new_payload, tmp_payload, payload_size);
  printf("[DEBUG-REMOVE] Copied %lu bytes of payload back to packet\n", payload_size);

  // Update IPv6 payload length
  ipv6_hdr->payload_len = rte_cpu_to_be_16(payload_size);
  printf("[DEBUG-REMOVE] Updated IPv6 payload length: %lu bytes\n", payload_size);

  // Fix UDP header if present
  if (ipv6_hdr->proto == 17 && payload_size >= sizeof(struct rte_udp_hdr)) {
    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)new_payload;
    // Update UDP length to match the actual payload size
    udp_hdr->dgram_len = rte_cpu_to_be_16(payload_size);
    // Zero out checksum to let the NIC recalculate it
    udp_hdr->dgram_cksum = 0;
    udp_hdr->dgram_cksum = rte_ipv6_udptcp_cksum(ipv6_hdr, udp_hdr);
    printf("[DEBUG-REMOVE] Fixed UDP header - src_port: %u, dst_port: %u, dgram_len: %u, cksum: 0x%04x\n",
           rte_be_to_cpu_16(udp_hdr->src_port), rte_be_to_cpu_16(udp_hdr->dst_port),
           rte_be_to_cpu_16(udp_hdr->dgram_len), rte_be_to_cpu_16(udp_hdr->dgram_cksum));
  }

  char dst_str[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_str, sizeof(dst_str));
  printf("[DEBUG-REMOVE] New destination IPv6: %s\n", dst_str);
  printf("[DEBUG-REMOVE] Final packet length: %u bytes\n", rte_pktmbuf_pkt_len(pkt));
  printf("[DEBUG-REMOVE] Protocol in IPv6 header: %u\n", ipv6_hdr->proto);

  printf("[EGRESS] Packet after removing headers - length: %u\n", rte_pktmbuf_pkt_len(pkt));
  printf("[EGRESS] Forwarding packet to iperf server MAC: 02:38:81:E2:F9:A7\n");

  free(tmp_payload);
}

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
  hmac_hdr->hmac_key_id = rte_cpu_to_be_32(0);  // Set to 0 for HMAC test
  memset(hmac_hdr->hmac_value, 0, sizeof(hmac_hdr->hmac_value));

  srh_hdr->next_header = 61;
  srh_hdr->hdr_ext_len = 2;
  srh_hdr->routing_type = 4;
  srh_hdr->last_entry = 1;
  srh_hdr->flags = 0;
  srh_hdr->segments_left = 2;
  memset(srh_hdr->reserved, 0, 2);

  struct in6_addr segments[] = {{.s6_addr = {0x2a, 0x05, 0xd0, 0x14, 0x0d, 0xc7, 0x12, 0xdc, 0x96, 0x48, 0x6b,
                                             0xf3, 0xe1, 0x82, 0xc7, 0xb4}},
                                {.s6_addr = {0x2a, 0x05, 0xd0, 0x14, 0x0d, 0xc7, 0x12, 0x09, 0x81, 0x69, 0xd7,
                                             0xd9, 0x3b, 0xcb, 0xd2, 0xb3}}};

  memcpy(srh_hdr->segments, segments, sizeof(segments));
  RTE_LOG(INFO, USER1, "Custom headers added to packet\n");

  // Update IPv6 payload length to include new extension headers
  uint16_t new_plen = rte_pktmbuf_pkt_len(pkt) - sizeof(*eth_hdr_6) - sizeof(*ipv6_hdr);
  ipv6_hdr->payload_len = rte_cpu_to_be_16(new_plen);
  printf("[INGRESS] Updated IPv6 payload_len: %u\n", new_plen);

  // Dump the first 128 bytes (or the whole packet if smaller)
  size_t dump_len = rte_pktmbuf_pkt_len(pkt);
  if (dump_len > 128) dump_len = 128;
  printf("Packet hex dump after custom header addition (first %zu bytes):\n", dump_len);
  hex_dump(rte_pktmbuf_mtod(pkt, void *), dump_len);
}

void add_custom_header_only(struct rte_mbuf *pkt) {
  // Packet must be large enough to hold the new headers
  if (rte_pktmbuf_tailroom(pkt) < sizeof(struct ipv6_srh)) {  // Adjusted tailroom check
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
  srh_hdr->last_entry = 1;
  srh_hdr->flags = 0;
  srh_hdr->segments_left = 1;
  memset(srh_hdr->reserved, 0, 2);

  struct in6_addr segments[] = {{.s6_addr = {0x2a, 0x05, 0xd0, 0x14, 0x0d, 0xc7, 0x12, 0xdc, 0x96, 0x48, 0x6b,
                                             0xf3, 0xe1, 0x82, 0xc7, 0xb4}},

                                {.s6_addr = {0x2a, 0x05, 0xd0, 0x14, 0x12, 0x09, 0x81, 0x69, 0xd7, 0xd9, 0x3b,
                                             0xcb, 0xd2, 0xb3, 0x00, 0x00}}};
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


int compare_hmac(struct hmac_tlv *hmac, uint8_t *hmac_out, struct rte_mbuf *mbuf) {
  if (memcmp(hmac->hmac_value, hmac_out, 32) != 0) {
    printf("The decrypted hmac is not the same as the computed hmac\n");
    printf("dropping the packet\n");
    rte_pktmbuf_free(mbuf);
    return 0;
  } else {
    printf("The transit of the packet is verified\n");
    // forward it to the tap interface so iperf can catch it
    return 1;
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

// Utility: Print offset and hex for a structure
void print_offset_and_hex(const char *label, const void *base, const void *ptr, size_t len) {
  printf("%s offset: %ld\n", label, (const uint8_t *)ptr - (const uint8_t *)base);
  printf("%s hex dump:\n", label);
  hex_dump(ptr, len);
}