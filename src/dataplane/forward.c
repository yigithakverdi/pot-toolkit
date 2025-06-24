#include "dataplane/forward.h"
#include "utils/common.h"
#include "core/nodemng.h"
#include "dataplane/headers.h"
#include "node/ingress.h"
#include "node/transit.h"
#include "node/egress.h"

enum role global_role = ROLE_INGRESS;

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

void send_packet_to(struct rte_ether_addr mac_addr, struct rte_mbuf *mbuf, uint16_t tx_port_id) {
  printf("Sending packet to %02X:%02X:%02X:%02X:%02X:%02X\n", mac_addr.addr_bytes[0], mac_addr.addr_bytes[1],
         mac_addr.addr_bytes[2], mac_addr.addr_bytes[3], mac_addr.addr_bytes[4], mac_addr.addr_bytes[5]);
  struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

  // Print IPv6 header details if it's an IPv6 packet
  if (rte_be_to_cpu_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_IPV6) {
    struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
    char src_str[INET6_ADDRSTRLEN];
    char dst_str[INET6_ADDRSTRLEN];
    
    inet_ntop(AF_INET6, &ipv6_hdr->src_addr, src_str, sizeof(src_str));
    inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_str, sizeof(dst_str));
    
    printf("[SEND] IPv6 src: %s\n", src_str);
    printf("[SEND] IPv6 dst: %s\n", dst_str);
    printf("[SEND] IPv6 next header: %u\n", ipv6_hdr->proto);
    printf("[SEND] IPv6 payload length: %u\n", rte_be_to_cpu_16(ipv6_hdr->payload_len));
  }

  if (rte_is_broadcast_ether_addr(&eth_hdr->dst_addr) != 1) {
    printf("Not a broadcast address, replacing destination MAC address\n");
    rte_ether_addr_copy(&eth_hdr->dst_addr, &eth_hdr->src_addr);
    rte_ether_addr_copy(&mac_addr, &eth_hdr->dst_addr);
  }

  // Print packet size before sending
  printf("[SEND] Packet length before sending: %u bytes\n", rte_pktmbuf_pkt_len(mbuf));
  
  // Check if the packet is properly formatted
  if (rte_pktmbuf_pkt_len(mbuf) < sizeof(struct rte_ether_hdr)) {
    printf("[ERROR-SEND] Packet too small to contain Ethernet header\n");
    rte_pktmbuf_free(mbuf);
    return;
  }

  uint16_t sent = rte_eth_tx_burst(tx_port_id, 0, &mbuf, 1);
  if (sent == 0) {
    printf("Failed to send packet to %02X:%02X:%02X:%02X:%02X:%02X\n", eth_hdr->dst_addr.addr_bytes[0],
           eth_hdr->dst_addr.addr_bytes[1], eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
           eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);
    rte_pktmbuf_free(mbuf);
  } else {
    printf("Packet sent successfully to %02X:%02X:%02X:%02X:%02X:%02X\n", eth_hdr->dst_addr.addr_bytes[0],
           eth_hdr->dst_addr.addr_bytes[1], eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
           eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);
    // Don't free the mbuf here - rte_eth_tx_burst takes ownership of it when successful
    return;
  }
  // Note: We don't double-free the mbuf here
}

