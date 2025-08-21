#ifndef PORT_H
#define PORT_H

#include <stdint.h>
#include <rte_mempool.h>
#include <rte_ethdev.h>

#define RX_RING_SIZE 2048
#define TX_RING_SIZE 2048

#define LOG_AND_RETURN_ON_ERROR(retval, message_fmt, ...)                                                    \
  do {                                                                                                       \
    if (retval != 0) {                                                                                       \
      LOG_MAIN(INFO, message_fmt, ##__VA_ARGS__);                                                            \
      return retval;                                                                                         \
    }                                                                                                        \
  } while (0)

typedef enum { PORT_ROLE_LATENCY_RX, PORT_ROLE_LATENCY_TX } PortRole;

int setup_port(uint16_t port, struct rte_mempool* mbuf_pool);
void display_mac_address(uint16_t port_id);
int get_and_configure_dev_info(uint16_t port, struct rte_eth_conf* port_conf,
                               struct rte_eth_dev_info* dev_info);
int setup_rx_queues(uint16_t port, uint16_t rx_rings, uint16_t nb_rxd, struct rte_mempool* mbuf_pool);
int setup_tx_queues(uint16_t port, uint16_t nb_tx_queues, uint16_t nb_txd,
                    const struct rte_eth_conf* port_conf);
int start_port(uint16_t port, uint16_t num_queues);
int display_port_mac(uint16_t port);
int enable_promiscuous(uint16_t port);
void check_ports();
int configure_device(uint16_t port, struct rte_eth_conf* port_conf);
int log_port_mac_address(uint16_t port);

#endif // PORT_H