#ifndef PORT_H
#define PORT_H

int port_init(uint16_t port, struct rte_mempool *mbuf_pool);
void checK_ports();

#endif // PORT_H