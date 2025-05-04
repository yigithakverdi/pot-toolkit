#include "include/dpdk_utils.h"
#include "deps/dpdk/lib/ethdev/rte_ethdev.h"
#include "rte_ethdev.h"

void display_mac_address(uint16_t port_id) {
  struct rte_ether_addr mac_addr;

  // Retrieve the MAC address of the specified port
  rte_eth_macaddr_get(port_id, &mac_addr);

  // Display the MAC address
  printf("MAC address of port %u: %02X:%02X:%02X:%02X:%02X:%02X\n", port_id,
         mac_addr.addr_bytes[0], mac_addr.addr_bytes[1], mac_addr.addr_bytes[2],
         mac_addr.addr_bytes[3], mac_addr.addr_bytes[4],
         mac_addr.addr_bytes[5]);
}

int port_exists(uint16_t port_id) {
  if (rte_eth_dev_is_valid_port(port_id)) {
    printf("Port %u exists.\n", port_id);
  } else {
    printf("Port %u does not exist.\n", port_id);
  }
  return 0;
}