#include "dataplane/forward.h"

#include "core/nodemng.h"       
#include "node/egress.h"
#include "node/ingress.h"
#include "node/transit.h"
#include "utils/common.h"
#include "utils/logging.h"

enum role global_role = ROLE_INGRESS;

int lcore_main_forward(void *arg) {
  LOG_MAIN(INFO, "Lcore %u started for forwarding\n", rte_lcore_id());

  uint16_t *ports = (uint16_t *)arg;
  uint16_t rx_port_id = ports[0];
  enum role cur_role = global_role;

  LOG_MAIN(INFO, "RX Port ID: %u\n", rx_port_id);
  LOG_MAIN(INFO, "Current role: %s\n",
           cur_role == ROLE_INGRESS ? "INGRESS" : (cur_role == ROLE_TRANSIT ? "TRANSIT" : "EGRESS"));
  LOG_MAIN(INFO, "Entering main forwarding loop on lcore %u\n", rte_lcore_id());

  while (1) {
    // Attempt to receive a burst of packets from the specified Ethernet device.
    // Arguments to rte_eth_rx_burst():
    // 1. rx_port_id: The ID of the Ethernet port (device) from which to receive packets.
    // 2. 0: The ID of the receive queue on that port. Most simple applications use queue 0.
    // 3. pkts: A pointer to the array where the received mbuf pointers will be stored.
    // 4. BURST_SIZE: The maximum number of packets to attempt to receive in this burst.
    //
    // The function returns the actual number of packets received (nb_rx),
    // which may be less than or equal to BURST_SIZE.
    struct rte_mbuf *pkts[BURST_SIZE];
    uint16_t nb_rx = rte_eth_rx_burst(rx_port_id, 0, pkts, BURST_SIZE);
    // LOG_MAIN(DEBUG, "Received %u packets on port %u", nb_rx, rx_port_id);

    // If no packets were received in this burst (nb_rx is 0),
    // continue to the next iteration of the loop to try again.
    // This avoids unnecessary processing when no data is available.
    if (nb_rx == 0) continue;

    // This block will execute only if at least one packet was received (nb_rx > 0).
    // Note: The original code only processes pkts[0] if nb_rx > 0.
    // In a real application, you would typically loop from 0 to nb_rx-1
    // to process ALL received packets in the burst.
    if (nb_rx > 0) {
      // LOG_MAIN(INFO, "Processing %u packets on port %u", nb_rx, rx_port_id);

      // Get a pointer to the Ethernet header of the first received packet (pkts[0]).
      // rte_pktmbuf_mtod() is a macro that converts an mbuf pointer to a data pointer
      // of a specified type, pointing to the start of the packet's data buffer.
      struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkts[0], struct rte_ether_hdr *);

      // Get a generic byte pointer to the start of the data buffer of the first packet.
      // This 'data' pointer would be used if you need to access the raw bytes
      // of the packet payload without knowing its specific protocol headers yet.
      uint8_t *data = rte_pktmbuf_mtod(pkts[0], uint8_t *);
    }

    switch (cur_role) {
      case ROLE_INGRESS: process_ingress(pkts, nb_rx, rx_port_id); break;
      case ROLE_TRANSIT: process_transit(pkts, nb_rx); break;
      case ROLE_EGRESS: process_egress(pkts, nb_rx); break;
      default: break;
    }
  }
  return 0;
}

void launch_lcore_forwarding(uint16_t *ports) {
  LOG_MAIN(INFO, "Launching forwarding on lcore %u\n", rte_get_next_lcore(-1, 1, 0));
  unsigned lcore_id = rte_get_next_lcore(-1, 1, 0);

  // Get the actual lcore ID that will execute the forwarding logic.
  // This call is the same as in the LOG_MAIN, ensuring consistency.
  rte_eal_remote_launch(lcore_main_forward, (void *)ports, lcore_id);
  LOG_MAIN(INFO, "Waiting for all lcores to complete\n");

  // Remotely launch the 'lcore_main_forward' function on the selected 'lcore_id'.
  // For distributing tasks across different lcores.
  // Arguments:
  // 1. lcore_main_forward: A function pointer to the function that contains
  //    the actual packet forwarding logic (e.g., the while(1) receive loop,
  //    processing, and transmit). This function will execute on 'lcore_id'.
  // 2. (void *)ports: A generic pointer to arguments that will be passed to
  //    'lcore_main_forward'. In this case, it's casting a pointer to an array
  //    of port IDs, likely indicating which network ports this lcore should
  //    monitor or forward between.
  // 3. lcore_id: The specific logical core on which 'lcore_main_forward'
  //    will be launched and executed.
  rte_eal_mp_wait_lcore();
  LOG_MAIN(INFO, "All lcores completed\n");
}

void send_packet_to(struct rte_ether_addr mac_addr, struct rte_mbuf *mbuf, uint16_t tx_port_id) {
  LOG_MAIN(DEBUG, "Sending packet to port %u with MAC %02x:%02x:%02x:%02x:%02x:%02x", tx_port_id,
           mac_addr.addr_bytes[0], mac_addr.addr_bytes[1], mac_addr.addr_bytes[2], mac_addr.addr_bytes[3],
           mac_addr.addr_bytes[4], mac_addr.addr_bytes[5]);
  struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

  // Check if the Ethernet frame's EtherType field indicates that the payload
  // is an IPv6 packet.
  // rte_be_to_cpu_16() converts a 16-bit value from big-endian (network byte order)
  // to the CPU's native byte order, as network protocols use big-endian.
  // RTE_ETHER_TYPE_IPV6 is a DPDK macro defining the EtherType value for IPv6.
  if (rte_be_to_cpu_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_IPV6) {
    LOG_MAIN(DEBUG, "Packet is IPv6, processing headers");
    struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
    char src_str[INET6_ADDRSTRLEN];
    char dst_str[INET6_ADDRSTRLEN];

    LOG_MAIN(DEBUG, "IPv6 Source: %s, Destination: %s",
             inet_ntop(AF_INET6, &ipv6_hdr->src_addr, src_str, sizeof(src_str)),
             inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_str, sizeof(dst_str)));

    // inet_ntop(AF_INET6, &ipv6_hdr->src_addr, src_str, sizeof(src_str));
    // inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_str, sizeof(dst_str));
  }

  // Check if the destination MAC address of the Ethernet frame is NOT a broadcast address.
  // rte_is_broadcast_ether_addr() returns 1 if the address is a broadcast address (FF:FF:FF:FF:FF:FF),
  // and 0 otherwise.
  if (rte_is_broadcast_ether_addr(&eth_hdr->dst_addr) != 1) {
    LOG_MAIN(DEBUG, "Packet is not broadcast, MAC addresses");
    rte_ether_addr_copy(&eth_hdr->dst_addr, &eth_hdr->src_addr);
    rte_ether_addr_copy(&mac_addr, &eth_hdr->dst_addr);

    LOG_MAIN(
        DEBUG, "New MAC Source: %02x:%02x:%02x:%02x:%02x:%02x, Destination: %02x:%02x:%02x:%02x:%02x:%02x",
        eth_hdr->src_addr.addr_bytes[0], eth_hdr->src_addr.addr_bytes[1], eth_hdr->src_addr.addr_bytes[2],
        eth_hdr->src_addr.addr_bytes[3], eth_hdr->src_addr.addr_bytes[4], eth_hdr->src_addr.addr_bytes[5],
        eth_hdr->dst_addr.addr_bytes[0], eth_hdr->dst_addr.addr_bytes[1], eth_hdr->dst_addr.addr_bytes[2],
        eth_hdr->dst_addr.addr_bytes[3], eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);
  }

  // Check if the packet length is less than the size of an Ethernet header.
  // If it is, free the mbuf and return early to avoid sending an invalid packet
  // This is a safety check to ensure that the packet has enough data to be a valid Ethernet frame.
  // rte_pktmbuf_pkt_len() returns the total length of the packet, including all headers and payload.
  // sizeof(struct rte_ether_hdr) is the size of the Ethernet header
  if (rte_pktmbuf_pkt_len(mbuf) < sizeof(struct rte_ether_hdr)) {
    LOG_MAIN(ERR, "Packet length %u is less than Ethernet header size %zu, dropping packet",
             rte_pktmbuf_pkt_len(mbuf), sizeof(struct rte_ether_hdr));
    rte_pktmbuf_free(mbuf);
    return;
  }

  // Send the packet using DPDK's Ethernet transmit function.
  // rte_eth_tx_burst() attempts to send a burst of packets on the specified transmit
  // port and queue. It returns the number of packets successfully sent.
  uint16_t sent = rte_eth_tx_burst(tx_port_id, 0, &mbuf, 1);
  if (sent == 0) {
    LOG_MAIN(ERR, "Failed to send packet on port %u, freeing mbuf", tx_port_id);
    rte_pktmbuf_free(mbuf);
  } else {
    LOG_MAIN(DEBUG, "Sent %u packet(s) on port %u", sent, tx_port_id);
    return;
  }
}
