#include "port.h"
#include "common.h"
#include "latency.h"

int port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
  struct rte_eth_conf port_conf;
  const uint16_t rx_rings = 1, tx_rings = 1;
  uint16_t nb_rxd = RX_RING_SIZE;
  uint16_t nb_txd = TX_RING_SIZE;
  int retval;
  uint16_t q;
  struct rte_eth_dev_info dev_info;
  struct rte_eth_txconf txconf;

  if (!rte_eth_dev_is_valid_port(port)) return -1;

  memset(&port_conf, 0, sizeof(struct rte_eth_conf));

  retval = rte_eth_dev_info_get(port, &dev_info);
  if (retval != 0) {
    printf("Error during getting device (port %u) info: %s\n", port, strerror(-retval));
    return retval;
  }

  if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
    port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

  /* Configure the Ethernet device. */
  retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
  if (retval != 0) return retval;

  retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
  if (retval != 0) return retval;

  /* Allocate and set up 1 RX queue per Ethernet port. */
  for (q = 0; q < rx_rings; q++) {
    retval = rte_eth_rx_queue_setup(port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
    if (retval < 0) return retval;
  }

  txconf = dev_info.default_txconf;
  txconf.offloads = port_conf.txmode.offloads;
  /* Allocate and set up 1 TX queue per Ethernet port. */
  for (q = 0; q < tx_rings; q++) {
    retval = rte_eth_tx_queue_setup(port, q, nb_txd, rte_eth_dev_socket_id(port), &txconf);
    if (retval < 0) return retval;
  }

  /* Starting Ethernet port. 8< */
  retval = rte_eth_dev_start(port);
  /* >8 End of starting of ethernet port. */
  if (retval < 0) return retval;

  /* Display the port MAC address. */
  struct rte_ether_addr addr;
  retval = rte_eth_macaddr_get(port, &addr);
  if (retval != 0) return retval;

  printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n", port,
         RTE_ETHER_ADDR_BYTES(&addr));

  /* Enable RX in promiscuous mode for the Ethernet device. */
  retval = rte_eth_promiscuous_enable(port);
  /* End of setting RX port in promiscuous mode. */
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
}