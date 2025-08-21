#include "forward.h"
#include "utils/logging.h"
#include "utils/role.h"
#include "utils/utils.h"
#include "node/ingress.h"
#include "node/transit.h"
#include "node/egress.h"
#include <sys/resource.h>

// Add system health monitoring function
static void log_system_health(uint64_t packet_count) {
  static uint64_t last_log = 0;
  
  // Only log when significant packet activity occurs (every 1000 packets)
  if (packet_count - last_log >= 1) {
    last_log = packet_count;
    
    // Check memory usage
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
      LOG_MAIN(INFO, "Health Check: Processed %lu packets, Memory RSS: %ld KB\n", 
               packet_count, usage.ru_maxrss);
    }
  }
}

int lcore_main_forward(void* arg) {
  LOG_MAIN(INFO, "Lcore %u started for forwarding\n", rte_lcore_id());

  uint16_t* ports = (uint16_t*)arg;
  uint16_t rx_port_id = ports[0];
  uint16_t tx_port_id = ports[1];
  enum role cur_role = global_role;

  LOG_MAIN(INFO, "RX Port ID: %u\n", rx_port_id);
  if (cur_role == ROLE_TRANSIT) LOG_MAIN(INFO, "TX Port ID: %u\n", tx_port_id);
  LOG_MAIN(INFO, "Current role: %s\n",
           cur_role == ROLE_INGRESS ? "INGRESS" : (cur_role == ROLE_TRANSIT ? "TRANSIT" : "EGRESS"));
  LOG_MAIN(INFO, "Entering main forwarding loop on lcore %u\n", rte_lcore_id());

  // Add periodic health check counter
  uint64_t packet_count = 0;

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
    struct rte_mbuf* pkts[BURST_SIZE];
    uint16_t nb_rx = rte_eth_rx_burst(rx_port_id, 0, pkts, BURST_SIZE);
    // LOG_MAIN(DEBUG, "Received %u packets on port %u", nb_rx, rx_port_id);

    // If no packets were received in this burst (nb_rx is 0),
    // continue to the next iteration of the loop to try again.
    // This avoids unnecessary processing when no data is available.
    if (nb_rx == 0) {
      // Add a small delay when no packets to prevent CPU spinning
      rte_delay_us_block(1); // 1 microsecond delay
      continue;
    }

    // Only increment counter and log when we actually receive packets
    packet_count += nb_rx;
    
    // Log health check based on packet count instead of loop iterations
    log_system_health(packet_count);
    
    // Log burst info periodically for debugging
    if (packet_count % 10000 == 0 && nb_rx > 0) {
      LOG_MAIN(DEBUG, "Received burst of %u packets, total packets: %lu\n", 
               nb_rx, packet_count);
    }

    // This block will execute only if at least one packet was received (nb_rx > 0).
    // Note: The original code only processes pkts[0] if nb_rx > 0.
    // In a real application, you would typically loop from 0 to nb_rx-1
    // to process ALL received packets in the burst.
    if (nb_rx > 0) {
      // LOG_MAIN(INFO, "Processing %u packets on port %u", nb_rx, rx_port_id);

      // Remove unused variable declarations to avoid warnings
      // struct rte_ether_hdr* eth_hdr = rte_pktmbuf_mtod(pkts[0], struct rte_ether_hdr*);
      // uint8_t* data = rte_pktmbuf_mtod(pkts[0], uint8_t*);
    }

    switch (cur_role) {
    case ROLE_INGRESS: 
      process_ingress(pkts, nb_rx, rx_port_id); 
      break;
    case ROLE_TRANSIT: 
      process_transit(pkts, nb_rx); 
      break;
    case ROLE_EGRESS: 
      process_egress(pkts, nb_rx); 
      break;
    default: 
      // Free unprocessed packets to prevent memory leaks
      for (uint16_t i = 0; i < nb_rx; i++) {
        rte_pktmbuf_free(pkts[i]);
      }
      LOG_MAIN(WARNING, "Unknown role, dropped %u packets\n", nb_rx);
      break;
    }
  }
  return 0;
}

void launch_lcore_forwarding(uint16_t* ports) {
  LOG_MAIN(INFO, "Launching forwarding on lcore %u\n", rte_get_next_lcore(-1, 1, 0));
  unsigned lcore_id = rte_get_next_lcore(-1, 1, 0);
  LOG_MAIN(INFO, "Selected lcore ID: %u\n", lcore_id);

  // If only one lcore is enabled, run on the master lcore
  if (rte_lcore_count() == 1) {
    LOG_MAIN(INFO, "Only one lcore available, running forwarding on master lcore %u\n", rte_lcore_id());
    lcore_main_forward((void*)ports);
    return;
  }  

  LOG_MAIN(INFO, "Launching forwarding on lcore %u\n", lcore_id);
  LOG_MAIN(INFO, "Selected lcore ID: %u\n", lcore_id);

  // Get the actual lcore ID that will execute the forwarding logic.
  // This call is the same as in the LOG_MAIN, ensuring consistency.
  int ret = rte_eal_remote_launch(lcore_main_forward, (void*)ports, lcore_id);
  if (ret < 0) {
    LOG_MAIN(ERR, "Failed to launch forwarding on lcore %u (error %d)\n", lcore_id, ret);
    return;
  }
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

void send_packet_to(struct rte_ether_addr mac_addr, struct rte_mbuf* mbuf, uint16_t tx_port_id) {
  LOG_MAIN(DEBUG, "Sending packet to port %u with MAC %02x:%02x:%02x:%02x:%02x:%02x\n", tx_port_id,
           mac_addr.addr_bytes[0], mac_addr.addr_bytes[1], mac_addr.addr_bytes[2], mac_addr.addr_bytes[3],
           mac_addr.addr_bytes[4], mac_addr.addr_bytes[5]);
  struct rte_ether_hdr* eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);

  struct rte_ether_addr src_mac;
  int ret = rte_eth_macaddr_get(tx_port_id, &src_mac);
  if (ret != 0) {
      LOG_MAIN(ERR, "Failed to get MAC address for port %u: %s\n", tx_port_id, strerror(-ret));
      rte_pktmbuf_free(mbuf);
      return;
  }  

  rte_ether_addr_copy(&src_mac, &eth_hdr->src_addr);
  rte_ether_addr_copy(&mac_addr, &eth_hdr->dst_addr);  

  LOG_MAIN(DEBUG, "Final MACs -> Src: %02x:%02x:%02x:%02x:%02x:%02x, Dst: %02x:%02x:%02x:%02x:%02x:%02x\n",
        src_mac.addr_bytes[0], src_mac.addr_bytes[1], src_mac.addr_bytes[2],
        src_mac.addr_bytes[3], src_mac.addr_bytes[4], src_mac.addr_bytes[5],
        mac_addr.addr_bytes[0], mac_addr.addr_bytes[1], mac_addr.addr_bytes[2],
        mac_addr.addr_bytes[3], mac_addr.addr_bytes[4], mac_addr.addr_bytes[5]);  
  
  // Check if the Ethernet frame's EtherType field indicates that the payload
  // is an IPv6 packet.
  // rte_be_to_cpu_16() converts a 16-bit value from big-endian (network byte order)
  // to the CPU's native byte order, as network protocols use big-endian.
  // RTE_ETHER_TYPE_IPV6 is a DPDK macro defining the EtherType value for IPv6.
  if (rte_be_to_cpu_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_IPV6) {
    LOG_MAIN(DEBUG, "Packet is IPv6, processing headers\n");
    struct rte_ipv6_hdr* ipv6_hdr = (struct rte_ipv6_hdr*)(eth_hdr + 1);
    char src_str[INET6_ADDRSTRLEN];
    char dst_str[INET6_ADDRSTRLEN];

    LOG_MAIN(DEBUG, "IPv6 Source: %s, Destination: %s\n",
             inet_ntop(AF_INET6, &ipv6_hdr->src_addr, src_str, sizeof(src_str)),
             inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_str, sizeof(dst_str)));

    // inet_ntop(AF_INET6, &ipv6_hdr->src_addr, src_str, sizeof(src_str));
    // inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_str, sizeof(dst_str));
  }

  // Check if the destination MAC address of the Ethernet frame is NOT a broadcast address.
  // rte_is_broadcast_ether_addr() returns 1 if the address is a broadcast address (FF:FF:FF:FF:FF:FF),
  // and 0 otherwise.
  // if (rte_is_broadcast_ether_addr(&eth_hdr->dst_addr) != 1) {
  //   LOG_MAIN(DEBUG, "Packet is not broadcast, MAC addresses\n");
  //   rte_ether_addr_copy(&eth_hdr->dst_addr, &eth_hdr->src_addr);
  //   rte_ether_addr_copy(&mac_addr, &eth_hdr->dst_addr);

  //   LOG_MAIN(
  //       DEBUG, "New MAC Source: %02x:%02x:%02x:%02x:%02x:%02x, Destination: %02x:%02x:%02x:%02x:%02x:%02x\n",
  //       eth_hdr->src_addr.addr_bytes[0], eth_hdr->src_addr.addr_bytes[1], eth_hdr->src_addr.addr_bytes[2],
  //       eth_hdr->src_addr.addr_bytes[3], eth_hdr->src_addr.addr_bytes[4], eth_hdr->src_addr.addr_bytes[5],
  //       eth_hdr->dst_addr.addr_bytes[0], eth_hdr->dst_addr.addr_bytes[1], eth_hdr->dst_addr.addr_bytes[2],
  //       eth_hdr->dst_addr.addr_bytes[3], eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);
  // }

  // Check if the packet length is less than the size of an Ethernet header.
  // If it is, free the mbuf and return early to avoid sending an invalid packet
  // This is a safety check to ensure that the packet has enough data to be a valid Ethernet frame.
  // rte_pktmbuf_pkt_len() returns the total length of the packet, including all headers and payload.
  // sizeof(struct rte_ether_hdr) is the size of the Ethernet header
  if (rte_pktmbuf_pkt_len(mbuf) < sizeof(struct rte_ether_hdr)) {
    LOG_MAIN(ERR, "Packet length %u is less than Ethernet header size %zu, dropping packet\n",
             rte_pktmbuf_pkt_len(mbuf), sizeof(struct rte_ether_hdr));
    rte_pktmbuf_free(mbuf);
    return;
  }

  // Send the packet using DPDK's Ethernet transmit function.
  // rte_eth_tx_burst() attempts to send a burst of packets on the specified transmit
  // port and queue. It returns the number of packets successfully sent.
  uint16_t sent = rte_eth_tx_burst(tx_port_id, 0, &mbuf, 1);
  if (sent == 0) {
    LOG_MAIN(ERR, "Failed to send packet on port %u, freeing mbuf\n", tx_port_id);
    rte_pktmbuf_free(mbuf);
  } else {
    LOG_MAIN(DEBUG, "Sent %u packet(s) on port %u\n", sent, tx_port_id);
    return;
  }
}
