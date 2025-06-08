#ifndef PORT_H
#define PORT_H

#include <stdint.h>
#include <rte_mempool.h>

int port_init(uint16_t port, struct rte_mempool *mbuf_pool);
void display_mac_address(uint16_t port_id);
void check_ports_available();
void setup_port(uint16_t port_id, struct rte_mempool *mbuf_pool, int is_rx);
#endif // PORT_H