#include "pprocess.h"

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <stdint.h>

#include "common.h"
#include "crypto.h"

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

  struct in6_addr segments[] = {{.s6_addr = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                                             0x00, 0x00, 0x00, 0x00, 0x01}},

                                {.s6_addr = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                                             0x00, 0x00, 0x00, 0x00, 0x01}}};
  memcpy(srh_hdr->segments, segments, sizeof(segments));
  RTE_LOG(INFO, USER1, "Custom headers added to packet\n");
}

void add_custom_header_only(struct rte_mbuf *pkt) {
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

  struct in6_addr segments[] = {{.s6_addr = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                                             0x00, 0x00, 0x00, 0x00, 0x01}},

                                {.s6_addr = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                                             0x00, 0x00, 0x00, 0x00, 0x01}}};
  memcpy(srh_hdr->segments, segments, sizeof(segments));
  RTE_LOG(INFO, USER1, "Custom headers added to packet\n");
}

// Function to add a custom header to the packet
static inline enum role determine_role(uint16_t rx_port_id, uint16_t tx_port_id) {
  if (rx_port_id == tx_port_id)
    return ROLE_TRANSIT;
  else if (rx_port_id < tx_port_id)
    return ROLE_INGRESS;
  else
    return ROLE_EGRESS;
}

// Helper: process a single packet for ingress
static inline void process_ingress_packet(struct rte_mbuf *mbuf) {
  struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
  uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
  switch (ether_type) {
    case RTE_ETHER_TYPE_IPV6:
      switch (operation_bypass_bit) {
        case 0:
          add_custom_header(mbuf);

          // Realign pointers after header addition
          // struct rte_ether_hdr *eth_hdr6 = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
          // struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr6 + 1);
          // struct ipv6_srh *srh = (struct ipv6_srh *)(ipv6_hdr + 1);
          // struct hmac_tlv *hmac = (struct hmac_tlv *)(srh + 1);
          // struct pot_tlv *pot = (struct pot_tlv *)(hmac + 1);

          // Extract destination IPv6 address as string
          // char dst_ip_str[INET6_ADDRSTRLEN];
          // if (inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_ip_str, sizeof(dst_ip_str)) == NULL) {
          //   perror("inet_ntop failed");
          //   break;
          // }

          // Prepare k_pot_in array using the loaded key for all SIDs
          // uint8_t k_pot_in[SID_NO][HMAC_MAX_LENGTH] = {0};
          // for (int sid = 0; sid < SID_NO; sid++) {
          //   if (read_encryption_key("keys.txt", dst_ip_str, k_pot_in[sid], HMAC_MAX_LENGTH) != 0) {
          //     printf("Failed to read key for %s\n", dst_ip_str);
          //     break;
          //   }
          // }

          // Prepare HMAC key (use same as encryption key for demo)
          // uint8_t k_hmac_ie[HMAC_MAX_LENGTH] = {0};
          // if (read_encryption_key("keys.txt", dst_ip_str, k_hmac_ie, HMAC_MAX_LENGTH) != 0) {
          //   printf("Failed to read HMAC key for %s\n", dst_ip_str);
          //   break;
          // }
          // size_t key_len = HMAC_MAX_LENGTH;

          // Compute HMAC
          // uint8_t hmac_out[HMAC_MAX_LENGTH];
          // if (calculate_hmac((uint8_t *)&ipv6_hdr->src_addr, srh, hmac, k_hmac_ie, key_len, hmac_out) == 0) {
          //   printf("HMAC Computation Successful\nHMAC: ");
          //   for (int i = 0; i < HMAC_MAX_LENGTH; i++) printf("%02x", hmac_out[i]);
          //   printf("\n");
          //   rte_memcpy(hmac->hmac_value, hmac_out, HMAC_MAX_LENGTH);
          //   printf("HMAC value inserted to srh_hmac header\n");
          // } else {
          //   printf("HMAC Computation Failed\n");
          //   break;
          // }

          // Nonce Generation and Encryption (PVF Computation)
          // uint8_t nonce[NONCE_LENGTH];
          // if (generate_nonce(nonce) != 0) {
          //   printf("Nonce generation failed, returning\n");
          //   break;
          // }
          // encrypt_pvf(k_pot_in, nonce, hmac_out);
          // printf("Encrypted PVF before writing to the header: ");
          // for (int i = 0; i < HMAC_MAX_LENGTH; i++) printf("%02x", hmac_out[i]);
          // printf("\n");
          // rte_memcpy(pot->encrypted_hmac, hmac_out, HMAC_MAX_LENGTH);
          // rte_memcpy(pot->nonce, nonce, NONCE_LENGTH);
          // printf("Encrypted PVF and nonce values inserted to pot header\n");
          

          // Forward the packet using the `send_packet_to` function

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

static inline void process_ingress(struct rte_mbuf **pkts, uint16_t nb_rx) {
  RTE_LOG(INFO, USER1, "Processing %u ingress packets\n", nb_rx);
  for (uint16_t i = 0; i < nb_rx; i++) {
    process_ingress_packet(pkts[i]);
  }
}

// Helper: process a single packet for transit
static inline void process_transit_packet(struct rte_mbuf *mbuf) {
  struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
  uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
  switch (ether_type) {
    case RTE_ETHER_TYPE_IPV6:
      switch (operation_bypass_bit) {
        case 0:
          process_ip4(mbuf, 1, eth_hdr, 0);  // 1 as nb_rx, 0 as index placeholder
          break;
        case 1:
          // Bypass all operations
          break;
        case 2: remove_headers_only(mbuf); break;
        default: break;
      }
      break;
    default: break;
  }
}

static inline void process_transit(struct rte_mbuf **pkts, uint16_t nb_rx) {
  for (uint16_t i = 0; i < nb_rx; i++) {
    process_transit_packet(pkts[i]);
  }
}

// Helper: process a single packet for egress
static inline void process_egress_packet(struct rte_mbuf *mbuf) {
  struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
  uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
  switch (ether_type) {
    case RTE_ETHER_TYPE_IPV6:
      switch (operation_bypass_bit) {
        case 0: remove_headers(mbuf); break;
        case 1:
          // Bypass all operations
          break;
        case 2: remove_headers_only(mbuf); break;
        default: break;
      }
      break;
    default: break;
  }
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
  uint16_t tx_port_id = ports[1];

  // Main processing loop.
  while (1) {
    struct rte_mbuf *pkts[BURST_SIZE];
    uint16_t nb_rx = rte_eth_rx_burst(rx_port_id, 0, pkts, BURST_SIZE);

    if (nb_rx == 0) continue;

    // if (nb_rx > 0) {
    //   struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkts[0], struct rte_ether_hdr *);
    //   printf("Received %u packets on port %u, EtherType: 0x%04x\n", nb_rx, rx_port_id,
    //          rte_be_to_cpu_16(eth_hdr->ether_type));
    //   // Optionally print first few bytes:
    //   uint8_t *data = rte_pktmbuf_mtod(pkts[0], uint8_t *);
    //   printf("First 8 bytes: %02x %02x %02x %02x %02x %02x %02x %02x\n", data[0], data[1], data[2],
    //   data[3],
    //          data[4], data[5], data[6], data[7]);
    // }

    enum role cur_role = determine_role(rx_port_id, tx_port_id);

    // Route packet batch to the appropriate processing logic.
    switch (cur_role) {
      case ROLE_INGRESS: process_ingress(pkts, nb_rx); break;
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