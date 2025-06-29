#include "dataplane/headers.h"

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

#include "utils/common.h"
#include "utils/logging.h"

void remove_headers(struct rte_mbuf *pkt) {

  // Assuming the packet structure. This code makes strong assumptions
  // about the order and presence of headers: Ethernet -> IPv6 -> SRH -> HMAC -> POT.
  // If a packet doesn't conform to this exact structure, subsequent pointer
  // arithmetic will lead to incorrect memory accesses and potential crashes.
  struct rte_ether_hdr *eth_hdr_6 = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
  struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr_6 + 1);
  struct ipv6_srh *srh = (struct ipv6_srh *)(ipv6_hdr + 1);
  struct hmac_tlv *hmac = (struct hmac_tlv *)(srh + 1);
  struct pot_tlv *pot = (struct pot_tlv *)(hmac + 1);

  // 'payload' now points to the data immediately following the last known header (POT TLV).
  uint8_t *payload = (uint8_t *)(pot + 1);

  char pre_dst_str[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, pre_dst_str, sizeof(pre_dst_str));
  LOG_MAIN(DEBUG, "Pre-modification IPv6 destination: %s", pre_dst_str);

  // Calculating the total size of all headers to be removed.
  // This sum must precisely match the actual size of the headers in the packet.
  // Any mismatch here will result in incorrect payload extraction or truncation later.
  size_t headers_size = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr) + sizeof(struct ipv6_srh) +
                        sizeof(struct hmac_tlv) + sizeof(struct pot_tlv);
  LOG_MAIN(DEBUG, "Headers size: %zu bytes", headers_size);

  // Calculating the payload size by subtracting the known header size
  // from the total packet length. This implies the rest of the packet is payload.
  size_t payload_size = rte_pktmbuf_pkt_len(pkt) - headers_size;
  LOG_MAIN(DEBUG, "Payload size: %zu bytes", payload_size);

  // Dynamically allocating temporary memory to store the payload.
  // This is necessary because rte_pktmbuf_trim will remove data from the mbuf,
  // and we need to preserve the payload to append it back later.
  uint8_t *tmp_payload = malloc(payload_size);
  if (tmp_payload == NULL) {
    LOG_MAIN(ERR, "Failed to allocate memory for tmp_payload");
    return;
  }
  memcpy(tmp_payload, payload, payload_size);
  LOG_MAIN(DEBUG, "Copied %zu bytes of payload to tmp_payload", payload_size);

  // TODO: The following line is potentially problematic.
  // rte_ipv6_hdr->payload_len usually indicates the length of the payload
  // *following* the IPv6 header, which would include SRH, HMAC, POT, and the actual data.
  // If 'trim_size' is intended to remove *only* the headers identified for removal,
  // it should be 'headers_size', not 'ipv6_hdr->payload_len'.
  // rte_pktmbuf_trim removes 'trim_size' bytes from the *end* of the packet data.
  // If the goal is to remove headers from the *front*, rte_pktmbuf_adj() is the correct function.
  // As written, this line will truncate the payload, not remove headers.
  size_t trim_size = rte_be_to_cpu_16(ipv6_hdr->payload_len);
  rte_pktmbuf_trim(pkt, trim_size);
  ipv6_hdr->proto = 17;
  LOG_MAIN(DEBUG, "Trimmed packet by %zu bytes", trim_size);

  // TODO: Instead of hardcoding the destination IPv6 address,
  // Hardcoding a new destination IPv6 address.
  // This is a specific transformation, changing where the packet is conceptually headed.
  struct in6_addr iperf_server_ipv6;
  if (inet_pton(AF_INET6, "2a05:d014:dc7:12c2:724:c0e1:c16d:2f16", &iperf_server_ipv6) != 1) {
    free(tmp_payload);
    LOG_MAIN(ERR, "Error converting IPv6 address, freeing tmp_payload");
    return;
  }
  memcpy(&ipv6_hdr->dst_addr, &iperf_server_ipv6, sizeof(struct in6_addr));
  LOG_MAIN(DEBUG, "Updated IPv6 destination to: %s",
           inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, pre_dst_str, sizeof(pre_dst_str)));

  // Appending the saved payload back to the mbuf.
  // After the 'rte_pktmbuf_trim' (which might be incorrect) or any previous header
  // manipulations, this ensures the original payload data is still present in the mbuf.
  // If 'rte_pktmbuf_adj' was used to remove headers, 'append' would add payload
  // after the remaining headers.
  uint8_t *new_payload = (uint8_t *)rte_pktmbuf_append(pkt, payload_size);
  if (new_payload == NULL) {
    free(tmp_payload);
    LOG_MAIN(ERR, "Failed to append payload back to packet, freeing tmp_payload");
    return;
  }
  memcpy(new_payload, tmp_payload, payload_size);
  LOG_MAIN(DEBUG, "Copied %zu bytes of payload back to packet", payload_size);

  // This block assumes that if the IPv6 next proto is UDP (17), and there's enough
  // payload for a UDP header, then it must be a UDP packet.
  // It then calculates and updates the UDP checksum. This is vital for packet validity.
  // Setting dgram_cksum to 0 before calculation is a common practice.
  // rte_ipv6_udptcp_cksum calculates the pseudo-header checksum + UDP/TCP checksum.
  ipv6_hdr->payload_len = rte_cpu_to_be_16(payload_size);
  if (ipv6_hdr->proto == 17 && payload_size >= sizeof(struct rte_udp_hdr)) {
    LOG_MAIN(DEBUG, "Updating UDP header checksum");
    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)new_payload;
    udp_hdr->dgram_len = rte_cpu_to_be_16(payload_size);
    udp_hdr->dgram_cksum = 0;
    udp_hdr->dgram_cksum = rte_ipv6_udptcp_cksum(ipv6_hdr, udp_hdr);
    LOG_MAIN(DEBUG, "Updated UDP checksum: %04x", udp_hdr->dgram_cksum);
  }

  char dst_str[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_str, sizeof(dst_str));
  free(tmp_payload);
  LOG_MAIN(DEBUG, "New destination IPv6: %s", dst_str);
  LOG_MAIN(DEBUG, "Headers removed and payload restored successfully");
}

void add_custom_header(struct rte_mbuf *pkt) {
  LOG_MAIN(DEBUG, "Adding custom headers to packet");

  // Check if there's enough tailroom (free space at the end of the mbuf's data buffer)
  // to append the new headers. If not, the mbuf cannot accommodate the additions.
  // rte_pktmbuf_free(pkt) is called to release the packet, preventing a leak
  // and indicating that this packet cannot be processed as intended.
  if (rte_pktmbuf_tailroom(pkt) < sizeof(struct ipv6_srh) + sizeof(struct hmac_tlv)) {
    rte_pktmbuf_free(pkt);
    return;
  }

  struct ipv6_srh *srh_hdr;
  struct hmac_tlv *hmac_hdr;
  struct pot_tlv *pot_hdr;
  struct rte_ether_hdr *eth_hdr_6 = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
  struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr_6 + 1);

  // 'payload' here initially points to the data immediately following the IPv6 header.
  // This is the part that will be temporarily moved to make space for new headers.
  uint8_t *payload = (uint8_t *)(ipv6_hdr + 1);

  // This 54' here represents the combined size of Ethernet (14 bytes) and IPv6 (40 bytes) headers.
  // This assumes a fixed header size before the actual data.
  size_t payload_size = rte_pktmbuf_pkt_len(pkt) - 54;
  uint8_t *tmp_payload = rte_malloc("tmp_payload", payload_size, RTE_CACHE_LINE_SIZE);
  if (tmp_payload == NULL) {
    LOG_MAIN(ERR, "Failed to allocate memory for tmp_payload");
    rte_pktmbuf_free(pkt);
    return;
  }
  // Copying the existing payload into the temporary buffer.
  // This is a necessary step before headers are inserted, as inserting
  // in the middle of the mbuf can overwrite existing data if not handled carefully.
  rte_memcpy(tmp_payload, payload, payload_size);
  LOG_MAIN(DEBUG, "Copied %zu bytes of payload to tmp_payload", payload_size);

  // Trimming the packet from the end to effectively remove the payload.
  // This operation, combined with subsequent appends, "reorders" the mbuf's data segments
  // to allow insertion of new headers after the IPv6 header.
  rte_pktmbuf_trim(pkt, payload_size);
  LOG_MAIN(DEBUG, "Trimmed packet by %zu bytes", payload_size);

  // Appending the new headers in order.
  // rte_pktmbuf_append increases the mbuf's data_len and returns a pointer
  // to the newly appended space. These calls ensure the SRH, HMAC, and POT TLVs
  // are inserted directly after the IPv6 header.
  srh_hdr = (struct ipv6_srh *)rte_pktmbuf_append(pkt, sizeof(struct ipv6_srh));
  hmac_hdr = (struct hmac_tlv *)rte_pktmbuf_append(pkt, sizeof(struct hmac_tlv));
  pot_hdr = (struct pot_tlv *)rte_pktmbuf_append(pkt, sizeof(struct pot_tlv));
  payload = (uint8_t *)rte_pktmbuf_append(pkt, payload_size);
  LOG_MAIN(DEBUG, "Appended custom headers and payload to packet");

  rte_memcpy(payload, tmp_payload, payload_size);
  rte_free(tmp_payload);
  LOG_MAIN(DEBUG, "Copied %zu bytes of payload back to packet", payload_size);

  // Initializing the fields of the newly added POT TLV header.
  // The specific values (type, length, nonce_length, key_set_id, memset for nonce/encrypted_hmac)
  // are protocol-specific and depend on the definition of the POT TLV.
  // rte_cpu_to_be_32() ensures multi-byte fields are in network byte order.
  pot_hdr->type = 1;
  pot_hdr->length = 48;
  pot_hdr->reserved = 0;
  pot_hdr->nonce_length = 16;
  pot_hdr->key_set_id = rte_cpu_to_be_32(1234);
  memset(pot_hdr->nonce, 0, sizeof(pot_hdr->nonce));
  memset(pot_hdr->encrypted_hmac, 0, sizeof(pot_hdr->encrypted_hmac));
  LOG_MAIN(DEBUG, "POT TLV header added with type %u and length %u", pot_hdr->type, pot_hdr->length);

  // Initializing the fields of the newly added HMAC TLV header.
  hmac_hdr->type = 5;
  hmac_hdr->length = 16;
  hmac_hdr->d_flag = 0;
  hmac_hdr->reserved = 0;
  hmac_hdr->hmac_key_id = rte_cpu_to_be_32(0);
  memset(hmac_hdr->hmac_value, 0, sizeof(hmac_hdr->hmac_value));
  LOG_MAIN(DEBUG, "HMAC TLV header added with type %u and length %u", hmac_hdr->type, hmac_hdr->length);

  // Initializing the fields of the newly added IPv6 Segment Routing Header (SRH).
  // 'next_header = 61' indicates that the next header *after* the SRH is an IPv6 "Destination Options"
  // header. 'hdr_ext_len = 2' is specific to SRH and its length calculation. 'routing_type = 4' indicates a
  // Segment Routing Header. 'last_entry = 1' and 'segments_left = 2' define the routing path specifics.
  srh_hdr->next_header = 61;
  srh_hdr->hdr_ext_len = 2;
  srh_hdr->routing_type = 4;
  srh_hdr->last_entry = 1;
  srh_hdr->flags = 0;
  srh_hdr->segments_left = 2;
  memset(srh_hdr->reserved, 0, 2);
  LOG_MAIN(DEBUG, "SRH header added with next_header %u, hdr_ext_len %u, routing_type %u",
           srh_hdr->next_header, srh_hdr->hdr_ext_len, srh_hdr->routing_type);

  // Defining the IPv6 segments (waypoints) for the Segment Routing Header.
  // These are hardcoded IPv6 addresses that the packet is intended to visit.
  // The 'segments' array contains two IPv6 addresses in binary format.
  struct in6_addr segments[] = {{.s6_addr = {0x2a, 0x05, 0xd0, 0x14, 0x0d, 0xc7, 0x12, 0xdc, 0x96, 0x48, 0x6b,
                                             0xf3, 0xe1, 0x82, 0xc7, 0xb4}},
                                {.s6_addr = {0x2a, 0x05, 0xd0, 0x14, 0x0d, 0xc7, 0x12, 0x09, 0x81, 0x69, 0xd7,
                                             0xd9, 0x3b, 0xcb, 0xd2, 0xb3}}};

  memcpy(srh_hdr->segments, segments, sizeof(segments));
  LOG_MAIN(DEBUG, "SRH segments added: %s, %s", inet_ntop(AF_INET6, &srh_hdr->segments[0], NULL, 0),
           inet_ntop(AF_INET6, &srh_hdr->segments[1], NULL, 0));

  uint16_t new_plen = rte_pktmbuf_pkt_len(pkt) - sizeof(*eth_hdr_6) - sizeof(*ipv6_hdr);
  ipv6_hdr->payload_len = rte_cpu_to_be_16(new_plen);
  LOG_MAIN(DEBUG, "Updated IPv6 payload length to %u", new_plen);

  size_t dump_len = rte_pktmbuf_pkt_len(pkt);
  if (dump_len > 128) dump_len = 128;
  LOG_MAIN(DEBUG, "Packet hex dump after custom header addition (first %zu bytes):", dump_len);
  rte_pktmbuf_dump(stdout, pkt, dump_len);
  LOG_MAIN(DEBUG, "Custom headers added to packet successfully");
}
