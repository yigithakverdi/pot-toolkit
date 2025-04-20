#include <stdint.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

void display_mac_address(uint16_t port_id);
int port_exists(uint16_t port_id);