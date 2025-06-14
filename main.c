#include <sys/types.h>
#include <rte_dev.h>

#include "common.h"
#include "port.h"
#include "pprocess.h"

int main(int argc, char *argv[]) {
  printf("Initializing next-hop table at startup\n");
  add_next_hop("2001:db8:0:1::2", "02:0c:b4:7a:8c:6d");
  add_next_hop("2001:db8:0:2::2", "02:0c:b4:7a:8c:6e");

  const char *role = "ingress";

  init_eal(argc, argv);
  check_ports_available();

  struct rte_mempool *mbuf_pool = create_mempool();
  register_tsc_dynfield();

  uint16_t port_id = 0;
  // uint16_t tx_port_id = 1;

  setup_port(port_id, mbuf_pool, 1);
  // setup_port(tx_port_id, mbuf_pool, 0);  // TX
  printf("TSC frequency: %" PRIu64 " Hz\n", rte_get_tsc_hz());

  // Print DPDK port info after EAL and before main logic
  uint16_t nb_ports = rte_eth_dev_count_avail();
  printf("\n==== DPDK Port Information ====" "\n");
  printf("DPDK detected %u available port(s):\n", nb_ports);
  // If you know the IPs, you can hardcode or load from config here:
  // Example for one port (expand as needed):
  const char *port_ipv4s[] = {"10.0.0.46"};
  const char *port_ipv6s[] = {"2600:1f18:abcd:1234::1"};
  for (uint16_t port_id_iter = 0; port_id_iter < nb_ports; port_id_iter++) {
    struct rte_eth_dev_info dev_info;
    struct rte_ether_addr mac_addr;
    struct rte_eth_link link;

    rte_eth_dev_info_get(port_id_iter, &dev_info);
    rte_eth_macaddr_get(port_id_iter, &mac_addr);
    rte_eth_link_get_nowait(port_id_iter, &link);

    printf("Port %u:\n", port_id_iter);
    printf("  Device name: %s\n", dev_info.device ? rte_dev_name(dev_info.device) : "N/A");
    printf("  Driver: %s\n", dev_info.driver_name ? dev_info.driver_name : "N/A");
    printf("  MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           mac_addr.addr_bytes[0], mac_addr.addr_bytes[1], mac_addr.addr_bytes[2],
           mac_addr.addr_bytes[3], mac_addr.addr_bytes[4], mac_addr.addr_bytes[5]);
    // Print known IPs if available
    if (port_id_iter < sizeof(port_ipv4s)/sizeof(port_ipv4s[0]))
      printf("  IPv4: %s\n", port_ipv4s[port_id_iter]);
    if (port_id_iter < sizeof(port_ipv6s)/sizeof(port_ipv6s[0]))
      printf("  IPv6: %s\n", port_ipv6s[port_id_iter]);
    printf("  Link status: %s, Speed: %u Mbps, Duplex: %s\n",
           link.link_status ? "UP" : "DOWN",
           link.link_speed,
           link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX ? "full" : "half");
  }
  printf("==== End DPDK Port Information ====" "\n\n");

  // uint16_t ports[2] = {port_id, tx_port_id};
  uint16_t ports[1] = {port_id};
  printf("Starting %s role on port %u\n", role, port_id);

  launch_lcore_forwarding(ports);

  return 0;
}