#include <rte_dev.h>
#include <sys/types.h>

#include "common.h"
#include "port.h"
#include "pprocess.h"

int main(int argc, char *argv[]) {
  printf("Initializing next-hop table at startup\n");
  // add_next_hop("2600:1f18:abcd:1234::1", "02:f5:27:51:bc:1d");
  add_next_hop("2a05:d014:dc7:12dc:9648:6bf3:e182:c7b4", "02:0c:b4:7a:8c:6e");

  // Find "--" to locate app-specific args
  int app_arg_start = 1;
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--") == 0) {
      app_arg_start = i + 1;
      break;
    }
  }

  // Parse app-specific args
  for (int i = app_arg_start; i < argc; ++i) {
    if (strcmp(argv[i], "--role") == 0 && i + 1 < argc) {
      if (strcmp(argv[i + 1], "ingress") == 0)
        global_role = ROLE_INGRESS;
      else if (strcmp(argv[i + 1], "transit") == 0)
        global_role = ROLE_TRANSIT;
      else if (strcmp(argv[i + 1], "egress") == 0)
        global_role = ROLE_EGRESS;
      i++;  // skip value
    }
  }

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
  printf(
      "\n==== DPDK Port Information ===="
      "\n");
  printf("DPDK detected %u available port(s):\n", nb_ports);

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
    printf("  MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", mac_addr.addr_bytes[0], mac_addr.addr_bytes[1],
           mac_addr.addr_bytes[2], mac_addr.addr_bytes[3], mac_addr.addr_bytes[4], mac_addr.addr_bytes[5]);
    // Print known IPs if available
    printf("  Link status: %s, Speed: %u Mbps, Duplex: %s\n", link.link_status ? "UP" : "DOWN",
           link.link_speed, link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX ? "full" : "half");
  }
  printf(
      "==== End DPDK Port Information ===="
      "\n\n");

  // uint16_t ports[2] = {port_id, tx_port_id};
  uint16_t ports[1] = {port_id};
  printf("Starting %u role on port %u\n", global_role, port_id);
  launch_lcore_forwarding(ports);

  return 0;
}