#include "headers.h"
#include "utils/config.h"
#include "utils/logging.h"
#include <rte_malloc.h>
#include <rte_tcp.h>
#include <rte_udp.h>

// Global segment list pointer to store IPv6 addresses read from file
struct in6_addr* g_segments = NULL;
int g_segment_count = 0;
int operation_bypass_bit = 0;

// Function to read segment list from a file
int load_srh_segments(const char* filepath) {
  FILE* file = fopen(filepath, "r");
  if (!file) {
    perror("Error opening segment list file");
    return -1;
  }

  // Add debug output before allocation
  LOG_MAIN(DEBUG, "Allocating memory for %d segments, size: %zu bytes\n", MAX_SEGMENTS,
           MAX_SEGMENTS * sizeof(struct in6_addr));

  // Use regular malloc instead of rte_malloc for this test
  g_segments = malloc(MAX_SEGMENTS * sizeof(struct in6_addr));
  if (g_segments == NULL) {
    LOG_MAIN(ERR, "Failed to allocate memory for SRH segments\n");
    fclose(file);
    return -1;
  }

  // Zero-initialize the memory
  memset(g_segments, 0, MAX_SEGMENTS * sizeof(struct in6_addr));

  // Add debug output after allocation
  LOG_MAIN(DEBUG, "Successfully allocated memory at %p for SRH segments\n", g_segments);

  char line[INET6_ADDRSTRLEN];
  while (fgets(line, sizeof(line), file) && g_segment_count < MAX_SEGMENTS) {
    // Remove newline character from the end of the line
    line[strcspn(line, "\n")] = 0;

    // Skip empty lines
    if (strlen(line) == 0) {
      continue;
    }

    // Add bounds checking
    if (g_segment_count >= MAX_SEGMENTS) {
      LOG_MAIN(ERR, "Too many segments in file, maximum is %d\n", MAX_SEGMENTS);
      break;
    }

    // Add debug output before inet_pton
    LOG_MAIN(DEBUG, "Processing segment %d: '%s', target address: %p\n", g_segment_count, line,
             &g_segments[g_segment_count]);

    // Add validation for the target address
    if (&g_segments[g_segment_count] == NULL) {
      LOG_MAIN(ERR, "Invalid target address for segment %d\n", g_segment_count);
      break;
    }

    // Convert string to binary IPv6 address and store it
    int result = inet_pton(AF_INET6, line, &g_segments[g_segment_count]);
    if (result == 1) {
      LOG_MAIN(DEBUG, "Successfully parsed segment %d\n", g_segment_count);
      g_segment_count++;
    } else if (result == 0) {
      LOG_MAIN(WARNING, "Invalid IPv6 address in segment file: %s\n", line);
    } else {
      LOG_MAIN(ERR, "inet_pton error for address: %s\n", line);
      perror("inet_pton");
    }
  }

  fclose(file);

  if (g_segment_count == 0) {
    LOG_MAIN(WARNING, "No valid segments were loaded from %s\n", filepath);
    free(g_segments);
    g_segments = NULL;
    return -1;
  }

  LOG_MAIN(INFO, "Successfully loaded %d SRH segments from %s\n", g_segment_count, filepath);
  return 0;
}

// Function to read segment list from a file
// Function to read segment list from a file
// Function to free the allocated memory when the application shuts down
void free_srh_segments(void) {
  if (g_segments != NULL) {
    free(g_segments);
    g_segments = NULL;
    g_segment_count = 0;
  }
}

void remove_headers(struct rte_mbuf* pkt) {
  struct rte_ether_hdr* eth_hdr_6 = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr*);
  struct rte_ipv6_hdr* ipv6_hdr = (struct rte_ipv6_hdr*)(eth_hdr_6 + 1);
  struct ipv6_srh* srh = (struct ipv6_srh*)(ipv6_hdr + 1);

  uint8_t original_proto = srh->next_header;
  size_t actual_srh_size = (srh->hdr_ext_len * 8) + 8;

  // Calculate dynamic SRH size from header
  size_t actual_srh_size = (srh->hdr_ext_len * 8) + 8;  // Convert back from 8-byte units
  struct hmac_tlv* hmac = (struct hmac_tlv*)((uint8_t*)srh + actual_srh_size);
  struct pot_tlv* pot = (struct pot_tlv*)(hmac + 1);
  uint8_t* payload = (uint8_t*)(pot + 1);
  // struct hmac_tlv* hmac = (struct hmac_tlv*)(srh + 1);
  // struct pot_tlv* pot = (struct pot_tlv*)(hmac + 1);
  // uint8_t* payload = (uint8_t*)(pot + 1);

  // Add bounds checking before accessing headers
  // size_t expected_headers_size = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr) + 
  //                               sizeof(struct ipv6_srh) + sizeof(struct hmac_tlv) + sizeof(struct pot_tlv);
  size_t expected_headers_size = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr) + 
                                actual_srh_size + sizeof(struct hmac_tlv) + sizeof(struct pot_tlv);
    
  
  if (rte_pktmbuf_pkt_len(pkt) < expected_headers_size) {
    LOG_MAIN(ERR, "Packet too small for header removal, expected %zu bytes, got %u\n", 
             expected_headers_size, rte_pktmbuf_pkt_len(pkt));
    rte_pktmbuf_free(pkt);
    return;
  }  

  char pre_dst_str[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, pre_dst_str, sizeof(pre_dst_str));
  LOG_MAIN(DEBUG, "Pre-modification IPv6 destination: %s\n", pre_dst_str);

  // size_t headers_size = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr) + sizeof(struct ipv6_srh) +
  //                       sizeof(struct hmac_tlv) + sizeof(struct pot_tlv);
  size_t headers_size = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr) + actual_srh_size +
                        sizeof(struct hmac_tlv) + sizeof(struct pot_tlv);  
  LOG_MAIN(DEBUG, "Headers size: %zu bytes\n", headers_size);

  size_t payload_size = rte_pktmbuf_pkt_len(pkt) - headers_size;
  LOG_MAIN(DEBUG, "Payload size: %zu bytes\n", payload_size);

  uint8_t* tmp_payload = malloc(payload_size);
  if (tmp_payload == NULL) {
    LOG_MAIN(ERR, "Failed to allocate memory for tmp_payload\n");
    rte_pktmbuf_free(pkt);
    return;
  }
  rte_memcpy(tmp_payload, payload, payload_size);
  LOG_MAIN(DEBUG, "Copied %zu bytes of payload to tmp_payload\n", payload_size);

  size_t trim_size = rte_be_to_cpu_16(ipv6_hdr->payload_len);
  rte_pktmbuf_trim(pkt, trim_size);
  ipv6_hdr->proto = original_proto;
  LOG_MAIN(DEBUG, "Trimmed packet by %zu bytes\n", trim_size);

  struct in6_addr iperf_server_ipv6;
  if(g_is_virtual_machine == 0) {
    if (inet_pton(AF_INET6, "2001:db8:1::d1", &iperf_server_ipv6) != 1) {
      free(tmp_payload);
      LOG_MAIN(ERR, "Error converting IPv6 address, freeing tmp_payload\n");
      return;
    }
  } else {
    if (inet_pton(AF_INET6, "2a05:d014:dc7:12ef:2dc:bf79:a352:6efe", &iperf_server_ipv6) != 1) {
      free(tmp_payload);
      LOG_MAIN(ERR, "Error converting IPv6 address, freeing tmp_payload\n");
      return;
    }    
  }

  rte_memcpy(&ipv6_hdr->dst_addr, &iperf_server_ipv6, sizeof(struct in6_addr));
  LOG_MAIN(DEBUG, "Updated IPv6 destination to: %s\n",
           inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, pre_dst_str, sizeof(pre_dst_str)));

  uint8_t* new_payload = (uint8_t*)rte_pktmbuf_append(pkt, payload_size);
  if (new_payload == NULL) {
    free(tmp_payload);
    LOG_MAIN(ERR, "Failed to append payload back to packet, freeing tmp_payload\n");
    return;
  }
  rte_memcpy(new_payload, tmp_payload, payload_size);
  LOG_MAIN(DEBUG, "Copied %zu bytes of payload back to packet\n", payload_size);

  ipv6_hdr->payload_len = rte_cpu_to_be_16(payload_size);
  if (ipv6_hdr->proto == 17 && payload_size >= sizeof(struct rte_udp_hdr)) {
    LOG_MAIN(DEBUG, "Updating UDP header checksum\n");
    struct rte_udp_hdr* udp_hdr = (struct rte_udp_hdr*)new_payload;
    udp_hdr->dgram_len = rte_cpu_to_be_16(payload_size);
    udp_hdr->dgram_cksum = 0;
    udp_hdr->dgram_cksum = rte_ipv6_udptcp_cksum(ipv6_hdr, udp_hdr);
    LOG_MAIN(DEBUG, "Updated UDP checksum: %04x\n", udp_hdr->dgram_cksum);
  }

  char dst_str[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_str, sizeof(dst_str));
  free(tmp_payload);
  LOG_MAIN(DEBUG, "New destination IPv6: %s\n", dst_str);
  LOG_MAIN(DEBUG, "Headers removed and payload restored successfully\n");
}

void add_custom_header(struct rte_mbuf *pkt) {
  LOG_MAIN(DEBUG, "Adding custom headers to packet\n");
  LOG_MAIN(DEBUG, "g_segments pointer: %p, g_segment_count: %d\n", g_segments, g_segment_count);

  // Check if segments are loaded properly
  if (g_segments == NULL || g_segment_count <= 0) {
    LOG_MAIN(ERR, "ERROR: g_segments is NULL or empty - cannot add custom headers\n");
    rte_pktmbuf_free(pkt);
    return;
  }
  
  // Calculating the dynamic SRH size based on actual segment count
  size_t srh_segments_size = g_segment_count * sizeof(struct in6_addr);
  size_t total_srh_size = sizeof(struct ipv6_srh) + srh_segments_size;
  size_t needed_tailroom = total_srh_size + sizeof(struct hmac_tlv) + sizeof(struct pot_tlv);
  
  // Check if there's enough tailroom
  // size_t needed_tailroom = sizeof(struct ipv6_srh) + sizeof(struct hmac_tlv) + sizeof(struct pot_tlv);
  if (rte_pktmbuf_tailroom(pkt) < needed_tailroom) {
    LOG_MAIN(ERR, "ERROR: Not enough tailroom in mbuf (%zu needed, %u available) - cannot add custom headers\n",
             needed_tailroom, rte_pktmbuf_tailroom(pkt));
    rte_pktmbuf_free(pkt);
    return;
  }

  if (g_segment_count > 0) {
    char addr_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, g_segments, addr_str, sizeof(addr_str));
    LOG_MAIN(DEBUG, "First segment address: %s\n", addr_str);
  }

  struct ipv6_srh *srh_hdr;
  struct hmac_tlv *hmac_hdr;
  struct pot_tlv *pot_hdr;
  struct rte_ether_hdr *eth_hdr_6 = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
  struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr_6 + 1);
  LOG_MAIN(DEBUG, "IPv6 header at %p, next header: %u\n", ipv6_hdr, ipv6_hdr->proto);


  // Save the original protocol to restore later
  uint8_t original_proto = ipv6_hdr->proto;
  LOG_MAIN(DEBUG, "Original IPv6 next header: %u\n", original_proto);

  // Calculate the exact offset to payload based on actual header sizes
  size_t header_size = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr);
  uint8_t *payload = (uint8_t *)(ipv6_hdr + 1);
  LOG_MAIN(DEBUG, "Payload starts at %p\n", payload);

  // Safe calculation of payload size
  size_t total_pkt_len = rte_pktmbuf_pkt_len(pkt);
  size_t payload_size = (total_pkt_len > header_size) ? (total_pkt_len - header_size) : 0;
  LOG_MAIN(DEBUG, "Total packet length: %zu, Header size: %zu, Payload size: %zu bytes\n", 
           total_pkt_len, header_size, payload_size);
  
  // Safely allocate temporary buffer with size check
  uint8_t *tmp_payload = NULL;
  if (payload_size > 0) {
    tmp_payload = malloc(payload_size);
    if (tmp_payload == NULL) {
      LOG_MAIN(ERR, "Failed to allocate memory for tmp_payload (size: %zu)\n", payload_size);
      rte_pktmbuf_free(pkt);
      return;
    }
    
    // Copy payload safely
    rte_memcpy(tmp_payload, payload, payload_size);
    LOG_MAIN(DEBUG, "Copied %zu bytes of payload to tmp_payload\n", payload_size);
    
    // Trim packet safely
    if (rte_pktmbuf_trim(pkt, payload_size) < 0) {
      LOG_MAIN(ERR, "Failed to trim packet\n");
      free(tmp_payload);
      rte_pktmbuf_free(pkt);
      return;
    }
    LOG_MAIN(DEBUG, "Trimmed packet by %zu bytes\n", payload_size);
  } else {
    LOG_MAIN(DEBUG, "No payload to save (payload_size is 0)\n");
  }

  // Append headers with NULL checks
  LOG_MAIN(DEBUG, "Appending custom headers to packet\n");
  // srh_hdr = (struct ipv6_srh *)rte_pktmbuf_append(pkt, sizeof(struct ipv6_srh));
  srh_hdr = (struct ipv6_srh *)rte_pktmbuf_append(pkt, total_srh_size);
  if (srh_hdr == NULL) {
    LOG_MAIN(ERR, "Failed to append SRH header\n");
    if (tmp_payload) free(tmp_payload);
    rte_pktmbuf_free(pkt);
    return;
  }
  LOG_MAIN(DEBUG, "SRH header appended at %p\n", srh_hdr);

  hmac_hdr = (struct hmac_tlv *)rte_pktmbuf_append(pkt, sizeof(struct hmac_tlv));
  if (hmac_hdr == NULL) {
    LOG_MAIN(ERR, "Failed to append HMAC header\n");
    if (tmp_payload) free(tmp_payload); 
    rte_pktmbuf_free(pkt);
    return;
  }
  LOG_MAIN(DEBUG, "HMAC header appended at %p\n", hmac_hdr);

  pot_hdr = (struct pot_tlv *)rte_pktmbuf_append(pkt, sizeof(struct pot_tlv));
  if (pot_hdr == NULL) {
    LOG_MAIN(ERR, "Failed to append POT header\n");
    if (tmp_payload) free(tmp_payload); 
    rte_pktmbuf_free(pkt);
    return;
  }
  LOG_MAIN(DEBUG, "POT header appended at %p\n", pot_hdr);

  // Re-append payload if it exists
  if (payload_size > 0 && tmp_payload != NULL) {
    payload = (uint8_t *)rte_pktmbuf_append(pkt, payload_size);
    if (payload == NULL) {
      LOG_MAIN(ERR, "Failed to append payload\n");
      free(tmp_payload); 
      rte_pktmbuf_free(pkt);
      return;
    }
    LOG_MAIN(DEBUG, "New payload space appended at %p\n", payload);
    
    rte_memcpy(payload, tmp_payload, payload_size);
    free(tmp_payload); 
    LOG_MAIN(DEBUG, "Copied %zu bytes of payload back to packet\n", payload_size);
  }

  // Initialize the POT TLV header safely
  pot_hdr->type = 1;
  pot_hdr->length = 48;
  pot_hdr->reserved = 0;
  pot_hdr->nonce_length = 16;
  pot_hdr->key_set_id = rte_cpu_to_be_32(1234);
  memset(pot_hdr->nonce, 0, sizeof(pot_hdr->nonce));
  memset(pot_hdr->encrypted_hmac, 0, sizeof(pot_hdr->encrypted_hmac));
  LOG_MAIN(DEBUG, "POT TLV header added with type %u and length %u\n", pot_hdr->type, pot_hdr->length);

  // Initialize the HMAC TLV header
  hmac_hdr->type = 5;
  hmac_hdr->length = 16;
  hmac_hdr->d_flag = 0;
  hmac_hdr->reserved = 0;
  hmac_hdr->hmac_key_id = rte_cpu_to_be_32(0);
  memset(hmac_hdr->hmac_value, 0, sizeof(hmac_hdr->hmac_value));
  LOG_MAIN(DEBUG, "HMAC TLV header added with type %u and length %u\n", hmac_hdr->type, hmac_hdr->length);

  // Initialize the SRH header
  srh_hdr->next_header = original_proto;  // Example next header
  // Only use the available segments - don't overflow
  srh_hdr->hdr_ext_len = (total_srh_size - 8) / 8;
  srh_hdr->routing_type = 4;
  srh_hdr->segments_left = g_segment_count;   // Set to the total number of segments
  srh_hdr->last_entry = g_segment_count - 1;  // Index of the last element
  srh_hdr->flags = 0;
  memset(srh_hdr->reserved, 0, 2);

  ipv6_hdr->proto = IPPROTO_ROUTING;

  LOG_MAIN(DEBUG, "SRH header added with hdr_ext_len %u, segments_left %u\n", 
           srh_hdr->hdr_ext_len, srh_hdr->segments_left);

  // Copy the loaded segments safely - limit to max 2 segments (as per struct definition)
  // int segments_to_copy = (g_segment_count > 2) ? 2 : g_segment_count;
  // rte_memcpy(srh_hdr->segments, g_segments, segments_to_copy * sizeof(struct in6_addr));
  // LOG_MAIN(DEBUG, "Copied %d segments into SRH\n", segments_to_copy);
  uint8_t *segments_ptr = (uint8_t *)srh_hdr + sizeof(struct ipv6_srh);
  rte_memcpy(segments_ptr, g_segments, srh_segments_size);
  LOG_MAIN(DEBUG, "Copied %d segments (%zu bytes) into SRH\n", g_segment_count, srh_segments_size);

  // Add verification logging
  struct in6_addr *copied_segments = (struct in6_addr *)segments_ptr;
  for (int i = 0; i < g_segment_count; i++) {
    char seg_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &copied_segments[i], seg_str, sizeof(seg_str));
    LOG_MAIN(DEBUG, "Copied segment [%d]: %s\n", i, seg_str);
  }

  // Update IPv6 next header field to point to SRH
  // uint8_t original_proto = ipv6_hdr->proto;
  // ipv6_hdr->proto = 43;  // IPv6 Routing Header
  // Update SRH next header to point to the original protocol
  // srh_hdr->next_header = original_proto;

  // Update IPv6 payload length
  uint16_t new_plen = rte_pktmbuf_pkt_len(pkt) - sizeof(*eth_hdr_6) - sizeof(*ipv6_hdr);
  ipv6_hdr->payload_len = rte_cpu_to_be_16(new_plen);
  LOG_MAIN(DEBUG, "Updated IPv6 payload length to %u\n", new_plen);
  LOG_MAIN(DEBUG, "Custom headers added to packet successfully\n");
}
