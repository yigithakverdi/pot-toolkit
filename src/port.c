#include "port.h"

#include "common.h"
#include "latency.h"

/*
 * port_init - Initialize a DPDK Ethernet port for RX and TX operation.
 *
 * This function configures a given Ethernet port for packet I/O using DPDK. It performs
 * the following steps:
 *   1. Validates the port ID.
 *   2. Retrieves and configures device information and offloads.
 *   3. Configures the Ethernet device.
 *   4. Sets up RX and TX queues.
 *   5. Starts the Ethernet device.
 *   6. Displays the port's MAC address.
 *   7. Enables promiscuous mode.
 *
 * The function is refactored for clarity and reusability, with each step handled by a
 * dedicated static helper function. Returns 0 on success, or a negative error code on failure.
 */
int port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
  struct rte_eth_conf port_conf;
  const uint16_t rx_rings = 1, tx_rings = 1;
  uint16_t nb_rxd = RX_RING_SIZE;
  uint16_t nb_txd = TX_RING_SIZE;
  struct rte_eth_dev_info dev_info;
  int retval;

  if (!rte_eth_dev_is_valid_port(port)) return -1;
  memset(&port_conf, 0, sizeof(struct rte_eth_conf));

  retval = get_and_configure_dev_info(port, &port_conf, &dev_info);
  if (retval != 0) {
    printf("Failed at get_and_configure_dev_info\n");
    return retval;
  }

  retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
  if (retval != 0) {
    printf("Failed at rte_eth_dev_configure: %d\n", retval);
    return retval;
  }

  retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
  if (retval != 0) {
    printf("Failed at rte_eth_dev_adjust_nb_rx_tx_desc\n");
    return retval;
  }

  retval = setup_rx_queues(port, rx_rings, nb_rxd, mbuf_pool);
  if (retval != 0) {
    printf("Failed at setup_rx_queues\n");
    return retval;
  }

  retval = setup_tx_queues(port, tx_rings, nb_txd, &dev_info, &port_conf);
  if (retval != 0) {
    printf("Failed at setup_tx_queues\n");
    return retval;
  }

  retval = start_port(port);
  if (retval != 0) {
    printf("Failed at start_port\n");
    return retval;
  }

  retval = display_port_mac(port);
  if (retval != 0) {
    printf("Failed at display_port_mac\n");
    return retval;
  }

  // retval = enable_promiscuous(port);
  // if (retval != 0) {
  //   printf("Failed at enable_promiscuous\n");
  //   return retval;
  // }

  return 0;
}

int get_and_configure_dev_info(uint16_t port, struct rte_eth_conf *port_conf,
                               struct rte_eth_dev_info *dev_info) {
  int retval = rte_eth_dev_info_get(port, dev_info);
  if (retval != 0) {
    printf("Error during getting device (port %u) info: %s\n", port, strerror(-retval));
    return retval;
  }
  if (dev_info->tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
    port_conf->txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
  return 0;
}

int setup_rx_queues(uint16_t port, uint16_t rx_rings, uint16_t nb_rxd, struct rte_mempool *mbuf_pool) {
  for (uint16_t q = 0; q < rx_rings; q++) {
    int retval = rte_eth_rx_queue_setup(port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
    if (retval < 0) return retval;
  }
  return 0;
}

int setup_tx_queues(uint16_t port, uint16_t tx_rings, uint16_t nb_txd, struct rte_eth_dev_info *dev_info,
                    struct rte_eth_conf *port_conf) {
  struct rte_eth_txconf txconf = dev_info->default_txconf;
  txconf.offloads = port_conf->txmode.offloads;
  for (uint16_t q = 0; q < tx_rings; q++) {
    int retval = rte_eth_tx_queue_setup(port, q, nb_txd, rte_eth_dev_socket_id(port), &txconf);
    if (retval < 0) return retval;
  }
  return 0;
}

int start_port(uint16_t port) {
  int retval = rte_eth_dev_start(port);
  if (retval < 0) return retval;
  return 0;
}

int display_port_mac(uint16_t port) {
  struct rte_ether_addr addr;
  int retval = rte_eth_macaddr_get(port, &addr);
  if (retval != 0) return retval;
  printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n", port,
         RTE_ETHER_ADDR_BYTES(&addr));
  return 0;
}

int enable_promiscuous(uint16_t port) {
  int retval = rte_eth_promiscuous_enable(port);
  if (retval != 0) return retval;
  return 0;
}

void display_mac_address(uint16_t port_id) {
  struct rte_ether_addr mac_addr;

  // Retrieve the MAC address of the specified port
  rte_eth_macaddr_get(port_id, &mac_addr);

  // Display the MAC address
  printf("MAC address of port %u: %02X:%02X:%02X:%02X:%02X:%02X\n", port_id, mac_addr.addr_bytes[0],
         mac_addr.addr_bytes[1], mac_addr.addr_bytes[2], mac_addr.addr_bytes[3], mac_addr.addr_bytes[4],
         mac_addr.addr_bytes[5]);
}

// Checks if there are any available Ethernet ports on the system for DPDK to use.
// If no ports are available, the function terminates the program with an error message.
// Otherwise, it prints the total number of Ethernet ports detected (including both available and unavailable
// ports). This function is useful for ensuring that the application does not proceed without any network
// interfaces to operate on.
void check_ports_available() {
  if (rte_eth_dev_count_avail() == 0)
    rte_exit(EXIT_FAILURE, "No Ethernet ports available\n");
  else
    printf("number of ports: %d \n", (int)rte_eth_dev_count_total());
}

void setup_port(uint16_t port_id, struct rte_mempool *mbuf_pool, int is_rx) {
  if (port_init(port_id, mbuf_pool) != 0) rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", port_id);
  if (is_rx) {
    rte_eth_add_rx_callback(port_id, 0, add_timestamps, NULL);
  } else {
    rte_eth_add_tx_callback(port_id, 0, calc_latency, NULL);
  }
  display_mac_address(port_id);

  struct rte_eth_link link;
  (void)rte_eth_link_get_nowait(port_id, &link);
  printf("Port %u link status: %s\n", port_id, link.link_status ? "UP" : "DOWN");
}