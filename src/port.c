#include "port.h"

#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <stdint.h>

int get_and_configure_dev_info(uint16_t port, struct rte_eth_conf *port_conf,
                               struct rte_eth_dev_info *dev_info) {
  int retval = rte_eth_dev_info_get(port, dev_info);
  if (retval != 0) {
    return retval;
  }
  if (dev_info->tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
    port_conf->txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
  return 0;
}

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
    return retval;
  }

  retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
  if (retval != 0) {
    return retval;
  }

  retval = setup_rx_queues(port, rx_rings, nb_rxd, mbuf_pool);
  if (retval != 0) {
    return retval;
  }

  retval = setup_tx_queues(port, tx_rings, nb_txd, &dev_info, &port_conf);
  if (retval != 0) {
    return retval;
  }

  retval = start_port(port);
  if (retval != 0) {
    return retval;
  }

  rte_eth_promiscuous_enable(port);

  retval = display_port_mac(port);
  if (retval != 0) {
    return retval;
  }

  retval = display_port_mac(port);
  if (retval != 0) {
    return retval;
  }

  return 0;

  return 0;
}

void check_ports() {}
