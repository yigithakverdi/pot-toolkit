#ifndef FORWARD_H
#define FORWARD_H

#include <stdint.h>
#include <rte_mbuf.h>     // For struct rte_mbuf
#include <rte_ether.h>    // For struct rte_ether_addr
#include <stdint.h>       // For uint16_t

int lcore_main_forward(void *arg);
void launch_lcore_forwarding(uint16_t *ports);
void send_packet_to(struct rte_ether_addr mac_addr, struct rte_mbuf *mbuf, uint16_t tx_port_id);

#endif // FORWARD_H