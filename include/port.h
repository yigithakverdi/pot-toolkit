#ifndef PORT_H
#define PORT_H
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <stdint.h>


int port_init(uint16_t port, struct rte_mempool *mbuf_pool);
void display_mac_address(uint16_t port_id);
void check_ports_available();
void setup_port(uint16_t port_id, struct rte_mempool *mbuf_pool, int is_rx);
int get_and_configure_dev_info(uint16_t port, struct rte_eth_conf *port_conf,
                               struct rte_eth_dev_info *dev_info);
int setup_rx_queues(uint16_t port, uint16_t rx_rings, uint16_t nb_rxd, struct rte_mempool *mbuf_pool);
int setup_tx_queues(uint16_t port, uint16_t tx_rings, uint16_t nb_txd, struct rte_eth_dev_info *dev_info,
                    struct rte_eth_conf *port_conf);
int start_port(uint16_t port);
int display_port_mac(uint16_t port);
int enable_promiscuous(uint16_t port);

#endif  // PORT_H