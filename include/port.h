#ifndef PORT_H
#define PORT_H

#define RX_RING_SIZE 2048
#define TX_RING_SIZE 2048

int port_init(uint16_t port, struct rte_mempool *mbuf_pool);
int get_and_configure_dev_info(uint16_t port, struct rte_eth_conf *port_conf,
                               struct rte_eth_dev_info *dev_info);
void checK_ports();

#endif  // PORT_H