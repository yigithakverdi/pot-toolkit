#include "port.h"
#include "utils/logging.h"
#include <rte_ethdev.h>

int setup_port(uint16_t port, struct rte_mempool* mbuf_pool) {
  struct rte_eth_conf port_conf = {0};
  const uint16_t rx_rings = 1, tx_rings = 1;
  uint16_t nb_rxd = RX_RING_SIZE;
  uint16_t nb_txd = TX_RING_SIZE;
  int retval;

  if (!rte_eth_dev_is_valid_port(port)) {
    LOG_MAIN(ERR, "Port %u is not a valid port.\n", port);
    return -1;
  }

  // Step 1: Get device info and set up basic configuration and offloads.
  retval = configure_device(port, &port_conf);
  LOG_AND_RETURN_ON_ERROR(retval, "Failed to configure device on port %u\n", port);

  // Step 2: Configure the number of RX/TX rings.
  retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
  LOG_AND_RETURN_ON_ERROR(retval, "rte_eth_dev_configure failed: %s\n", strerror(-retval));

  // Step 3: Adjust the number of RX/TX descriptors.
  retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
  LOG_AND_RETURN_ON_ERROR(retval, "rte_eth_dev_adjust_nb_rx_tx_desc failed: %s\n", strerror(-retval));

  // Step 4: Set up RX queues.
  retval = setup_rx_queues(port, rx_rings, nb_rxd, mbuf_pool);
  LOG_AND_RETURN_ON_ERROR(retval, "Failed to setup RX queues on port %u\n", port);

  // Step 5: Set up TX queues.
  retval = setup_tx_queues(port, tx_rings, nb_txd, &port_conf);
  LOG_AND_RETURN_ON_ERROR(retval, "Failed to setup TX queues on port %u\n", port);

  // Step 6: Start the port and enable promiscuous mode.
  retval = start_port(port, rx_rings);
  LOG_AND_RETURN_ON_ERROR(retval, "Failed to start port %u\n", port);

  // Step 7: Log the MAC address for verification.
  retval = log_port_mac_address(port);
  LOG_AND_RETURN_ON_ERROR(retval, "Failed to get MAC for port %u\n", port);

  return 0;
}

int configure_device(uint16_t port, struct rte_eth_conf* port_conf) {
  struct rte_eth_dev_info dev_info;
  int retval = rte_eth_dev_info_get(port, &dev_info);
  if (retval != 0) {
    LOG_MAIN(ERR, "Error getting device info for port %u: %s\n", port, strerror(-retval));
    return retval;
  }

  if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
    port_conf->txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
  }
  return 0;
}

int setup_rx_queues(uint16_t port, uint16_t nb_rx_queues, uint16_t nb_rxd,
                           struct rte_mempool* mbuf_pool) {
  int socket_id = rte_eth_dev_socket_id(port);
  for (uint16_t q = 0; q < nb_rx_queues; q++) {
    int retval = rte_eth_rx_queue_setup(port, q, nb_rxd, socket_id, NULL, mbuf_pool);
    if (retval < 0) {
      LOG_MAIN(ERR, "RX queue setup failed for port %u queue %u: %s\n", port, q, strerror(-retval));
      return retval;
    }
  }
  return 0;
}

int setup_tx_queues(uint16_t port, uint16_t nb_tx_queues, uint16_t nb_txd,
                           const struct rte_eth_conf* port_conf) {
  struct rte_eth_dev_info dev_info;
  int retval = rte_eth_dev_info_get(port, &dev_info);
  if (retval != 0) {
    LOG_MAIN(ERR, "Error getting device info for port %u: %s\n", port, strerror(-retval));
    return retval;
  }

  struct rte_eth_txconf txconf = dev_info.default_txconf;
  txconf.offloads = port_conf->txmode.offloads;

  int socket_id = rte_eth_dev_socket_id(port);
  for (uint16_t q = 0; q < nb_tx_queues; q++) {
    retval = rte_eth_tx_queue_setup(port, q, nb_txd, socket_id, &txconf);
    if (retval < 0) {
      LOG_MAIN(ERR, "TX queue setup failed for port %u queue %u: %s\n", port, q, strerror(-retval));
      return retval;
    }
  }
  return 0;
}

int start_port(uint16_t port, uint16_t num_queues) {
  int retval = rte_eth_dev_start(port);
  if (retval < 0) {
    LOG_MAIN(ERR, "rte_eth_dev_start failed: %s\n", strerror(-retval));
    return retval;
  }

  retval = rte_eth_promiscuous_enable(port);
  if (retval != 0) {
    LOG_MAIN(WARNING, "Promiscuous mode enable failed for port %u: %s (continuing anyway)\n", port, rte_strerror(-retval));
    // return retval;
  }
  LOG_MAIN(INFO, "Promiscuous mode enabled on port %u\n", port);

  struct rte_eth_link link;
  rte_eth_link_get_nowait(port, &link);
  LOG_MAIN(INFO, "Port %u Link Status: %s\n", port, link.link_status ? "UP" : "DOWN");

  return 0;
}

int log_port_mac_address(uint16_t port) {
  struct rte_ether_addr addr;
  int retval = rte_eth_macaddr_get(port, &addr);
  if (retval != 0) {
    LOG_MAIN(ERR, "Failed to get MAC address for port %u: %s\n", port, strerror(-retval));
    return retval;
  }

  char mac_str[RTE_ETHER_ADDR_FMT_SIZE];
  rte_ether_format_addr(mac_str, sizeof(mac_str), &addr);
  LOG_MAIN(INFO, "Port %u MAC: %s\n", port, mac_str);

  return 0;
}

void check_ports() {
  uint16_t count = rte_eth_dev_count_avail();
  if (count == 0) {
    rte_exit(EXIT_FAILURE, "No Ethernet ports available\n");
  }
  LOG_MAIN(INFO, "Available Ethernet ports: %u\n", count);
}
