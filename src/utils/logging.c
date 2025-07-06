#include "utils/logging.h"
#include "utils/role.h"
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <rte_cycles.h>
#include <rte_dev.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

int dpdk_pot_logtype_main = 0;

void print_system_info() {
  printf("TSC frequency: %" PRIu64 " Hz\n", rte_get_tsc_hz());

  uint16_t nb_ports = rte_eth_dev_count_avail();
  printf("\n==== DPDK Port Information ====\n");
  printf("DPDK detected %u available port(s):\n", nb_ports);

  for (uint16_t port_id = 0; port_id < nb_ports; port_id++) {
    struct rte_eth_dev_info dev_info;
    struct rte_ether_addr mac_addr;
    struct rte_eth_link link;

    rte_eth_dev_info_get(port_id, &dev_info);
    rte_eth_macaddr_get(port_id, &mac_addr);
    rte_eth_link_get_nowait(port_id, &link);

    printf("Port %u:\n", port_id);
    printf("  Device name: %s\n", dev_info.device ? rte_dev_name(dev_info.device) : "N/A");
    printf("  Driver: %s\n", dev_info.driver_name ? dev_info.driver_name : "N/A");
    printf("  MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", mac_addr.addr_bytes[0], mac_addr.addr_bytes[1],
           mac_addr.addr_bytes[2], mac_addr.addr_bytes[3], mac_addr.addr_bytes[4], mac_addr.addr_bytes[5]);
    printf("  Link status: %s, Speed: %u Mbps, Duplex: %s\n", link.link_status ? "UP" : "DOWN",
           link.link_speed, link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX ? "full" : "half");
  }
  printf("==== End DPDK Port Information ====\n\n");
}

void print_startup_banner(enum role role, uint16_t rx_port, uint16_t tx_port) {
  printf("Starting %s role on port %u\n", get_role_name(role), rx_port);
  if (role == ROLE_TRANSIT) {
    printf("Transit node using second port %u\n", tx_port);
  }
}