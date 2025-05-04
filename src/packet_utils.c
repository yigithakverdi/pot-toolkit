#include "include/packet_utils.h"
#include "include/crypto_utils.h"
#include "include/pot/pot.h"

// TODO Functions that will be implemented. These are the main logic of 
//      packet processing
void packet_eth_parsing() {}
void process_packet() {}

void print_ipv6_address(const struct in6_addr *ipv6_addr, const char *label) {
  char addr_str[INET6_ADDRSTRLEN]; // Buffer for human-readable address

  // Convert the IPv6 binary address to a string
  if (inet_ntop(AF_INET6, ipv6_addr, addr_str, sizeof(addr_str)) != NULL) {
    printf("%s: %s\n", label, addr_str);
  } else {
    perror("inet_ntop");
  }
}

int process_ip6_with_srh(struct rte_ether_hdr *eth_hdr, struct rte_mbuf *mbuf,
                         int i) {
  printf("\n###################################################################"
         "########\n");
  printf("\nip6 packet is encountered\n");
  struct ipv6_srh *srh;
  struct pot_tlv *pot;
  struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
  srh = (struct ipv6_srh *)(ipv6_hdr + 1); // SRH follows IPv6 header
  pot = (struct pot_tlv *)(srh + 1);

  printf("the proto nums are %d and %d\n", ipv6_hdr->proto, srh->next_header);
  if (srh->next_header == 61 && ipv6_hdr->proto == 43) {
    printf("segment routing detected\n");

    struct hmac_tlv *hmac;
    struct pot_tlv *pot;
    hmac = (struct hmac_tlv *)(srh + 1);
    pot = (struct pot_tlv *)(hmac + 1);
    // The key of this node (middle)
    uint8_t k_pot_in[32] = "qqwwqqwwqqwwqqwwqqwwqqwwqqwwqqw";
    uint8_t k_hmac_ie[] = "my-hmac-key-for-pvf-calculation";

    // Display source and destination MAC addresses
    printf("Packet %d:\n", i + 1);
    printf("  Src MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
           ":%02" PRIx8 ":%02" PRIx8 "\n",
           eth_hdr->src_addr.addr_bytes[0], eth_hdr->src_addr.addr_bytes[1],
           eth_hdr->src_addr.addr_bytes[2], eth_hdr->src_addr.addr_bytes[3],
           eth_hdr->src_addr.addr_bytes[4], eth_hdr->src_addr.addr_bytes[5]);
    printf("  Dst MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
           ":%02" PRIx8 ":%02" PRIx8 "\n",
           eth_hdr->dst_addr.addr_bytes[0], eth_hdr->dst_addr.addr_bytes[1],
           eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
           eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);
    printf("  EtherType: 0x%04x\n", rte_be_to_cpu_16(eth_hdr->ether_type));

    print_ipv6_address((struct in6_addr *)&ipv6_hdr->src_addr, "source");
    print_ipv6_address((struct in6_addr *)&ipv6_hdr->dst_addr, "destination");

    // Get srh pointer after ipv6 header
    if (ipv6_hdr->proto == IPPROTO_ROUTING) {
      printf("The size of srh is %lu\n", sizeof(*srh));
      printf("The size of hmac is %lu\n", sizeof(*hmac));
      printf("The size of pot is %lu\n", sizeof(*pot));

      printf("HMAC type: %u\n", hmac->type);
      printf("HMAC length: %u\n", hmac->length);
      printf("HMAC key ID: %u\n", rte_be_to_cpu_32(hmac->hmac_key_id));
      printf("HMAC size: %ld\n", sizeof(hmac->hmac_value));

      // TODO burayı dinamik olarak bastır çünkü hmac 8 octet (8 byte 64 bit)
      // veya katı olabilir şimdilik i 1 den başıyor ve i-1 yazdırıyor
      printf("HMAC value: \n");
      for (int i = 0; i < 32; i++) {
        printf("%02x", hmac->hmac_value[i]);
      }
      printf("\nPVF value before decrypting: \n");
      for (int i = 0; i < 32; i++) {
        printf("%02x", pot->encrypted_hmac[i]);
      }
      // decrypyt one time with the key of node
      //  first declare the value to store decrypted pvf
      uint8_t hmac_out[32];
      memcpy(hmac_out, pot->encrypted_hmac, 32);
      decrypt_pvf(k_pot_in, pot->nonce, hmac_out);

      // update the pot header pvf field
      memcpy(pot->encrypted_hmac, hmac_out, 32);

      int retval;
      retval = compare_hmac(hmac, hmac_out, mbuf);

      fflush(stdout);
      return retval;
    }
  }
  return -1;
}

void process_ip4(struct rte_mbuf *mbuf, uint16_t nb_rx,
                 struct rte_ether_hdr *eth_hdr, int i) {
  printf("number of the packets received is %d", nb_rx);

  struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);

  // Display source and destination MAC addresses
  printf("Packet %d:\n", i + 1);
  printf("  Src MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
         ":%02" PRIx8 ":%02" PRIx8 "\n",
         eth_hdr->src_addr.addr_bytes[0], eth_hdr->src_addr.addr_bytes[1],
         eth_hdr->src_addr.addr_bytes[2], eth_hdr->src_addr.addr_bytes[3],
         eth_hdr->src_addr.addr_bytes[4], eth_hdr->src_addr.addr_bytes[5]);
  printf("  Dst MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
         ":%02" PRIx8 ":%02" PRIx8 "\n",
         eth_hdr->dst_addr.addr_bytes[0], eth_hdr->dst_addr.addr_bytes[1],
         eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
         eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);
  printf("  EtherType: 0x%04x\n", rte_be_to_cpu_16(eth_hdr->ether_type));
  // If the packet is IPv4, display source and destination IP addresses

  printf("  Src IP: %d.%d.%d.%d\n", (ipv4_hdr->src_addr & 0xff),
         (ipv4_hdr->src_addr >> 8) & 0xff, (ipv4_hdr->src_addr >> 16) & 0xff,
         (ipv4_hdr->src_addr >> 24) & 0xff);
  printf("  Dst IP: %d.%d.%d.%d\n", (ipv4_hdr->dst_addr & 0xff),
         (ipv4_hdr->dst_addr >> 8) & 0xff, (ipv4_hdr->dst_addr >> 16) & 0xff,
         (ipv4_hdr->dst_addr >> 24) & 0xff);

  // Free the mbuf after processing
  rte_pktmbuf_free(mbuf);
}

void remove_headers(struct rte_mbuf *pkt) {

  struct rte_ether_hdr *eth_hdr_6 =
      rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
  struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr_6 + 1);
  struct ipv6_srh *srh = (struct ipv6_srh *)(ipv6_hdr + 1);
  struct hmac_tlv *hmac = (struct hmac_tlv *)(srh + 1);
  struct pot_tlv *pot = (struct pot_tlv *)(hmac + 1);
  uint8_t *payload = (uint8_t *)(pot + 1); // this also cantains l4 header

  // reinsert the initial ip6 nexr header for iperf testing the insertion is
  // manual in this case is 6
  ipv6_hdr->proto = 6;
  struct rte_ether_addr mac_addr = {
      {0x5E, 0xC1, 0xE4, 0x87, 0x5D, 0xEF}}; // mac of dtap
  rte_ether_addr_copy(&mac_addr, &eth_hdr_6->dst_addr);

  printf("packet length: %u\n", rte_pktmbuf_pkt_len(pkt));
  // Assuming ip6 packets the size of ethernet header + ip6 header is 54 bytes
  // plus the headers between
  size_t payload_size = rte_pktmbuf_pkt_len(pkt) -
                        (54 + sizeof(struct ipv6_srh) +
                         sizeof(struct hmac_tlv) + sizeof(struct pot_tlv));

  printf("Payload size: %lu\n", payload_size);
  uint8_t *tmp_payload = (uint8_t *)malloc(payload_size);
  if (tmp_payload == NULL) {
    printf("malloc failed\n");
  }
  // save the payload which will be deleted and added later
  memcpy(tmp_payload, payload, payload_size);

  // remove headers from the tail
  rte_pktmbuf_trim(pkt, payload_size);
  rte_pktmbuf_trim(pkt, sizeof(struct pot_tlv));
  rte_pktmbuf_trim(pkt, sizeof(struct hmac_tlv));
  rte_pktmbuf_trim(pkt, sizeof(struct ipv6_srh));

  payload = (uint8_t *)rte_pktmbuf_append(pkt, payload_size);
  memcpy(payload, tmp_payload, payload_size);
  free(tmp_payload);
}