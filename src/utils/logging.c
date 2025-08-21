#include "utils/logging.h"
#include "utils/config.h"
#include "utils/role.h"
#include "headers.h"         // Add this for g_segments, g_segment_count, next_hops, etc.
#include "crypto.h"          // Add this for g_key_count
#include "node/controller.h" // Add this for g_node_index
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
#include <arpa/inet.h>       

// global storage for the current log file path
static char g_log_file_path[256] = {0};
int g_logging_enabled = 1; 

// new helper to retrieve the last created log file
const char* get_log_file_path(void) {
  return g_log_file_path;
}

int dpdk_pot_logtype_main = 0;

void print_system_info(AppConfig* config) {
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

  printf("==== Application Configuration ====\n");
  printf("Node type: %s\n", config->node.type ? config->node.type : "N/A");
  printf("Node role: %s\n", get_role_name(global_role));
  printf("Logging level: %s\n", config->node.log_level ? config->node.log_level : "N/A");
  printf("Topology segment list: %s\n", config->topology.segment_list ? config->topology.segment_list : "N/A");
  printf("Topology key locations: %s\n", config->topology.key_locations ? config->topology.key_locations : "N/A");
  printf("Number of transit nodes: %d\n", config->topology.num_transit);
  printf("==== End Application Configuration ====\n\n");

  printf("==== Environment Variables ====\n");
  printf("POT_NODE_TYPE: %s\n", getenv("POT_NODE_TYPE") ? getenv("POT_NODE_TYPE") : "NOT SET");
  printf("POT_NODE_INDEX: %s\n", getenv("POT_NODE_INDEX") ? getenv("POT_NODE_INDEX") : "NOT SET");
  printf("POT_NODE_LOG_LEVEL: %s\n", getenv("POT_NODE_LOG_LEVEL") ? getenv("POT_NODE_LOG_LEVEL") : "NOT SET");
  printf("POT_TOPOLOGY_NUM_TRANSIT_NODES: %s\n", getenv("POT_TOPOLOGY_NUM_TRANSIT_NODES") ? getenv("POT_TOPOLOGY_NUM_TRANSIT_NODES") : "NOT SET");
  printf("POT_SEGMENT_LIST_FILE: %s\n", getenv("POT_SEGMENT_LIST_FILE") ? getenv("POT_SEGMENT_LIST_FILE") : "NOT SET");
  printf("POT_KEYS_FILE: %s\n", getenv("POT_KEYS_FILE") ? getenv("POT_KEYS_FILE") : "NOT SET");
  printf("POT_TOPOLOGY_SEGMENT_LIST_PATH: %s\n", getenv("POT_TOPOLOGY_SEGMENT_LIST_PATH") ? getenv("POT_TOPOLOGY_SEGMENT_LIST_PATH") : "NOT SET");
  printf("POT_TOPOLOGY_KEY_LOCATIONS: %s\n", getenv("POT_TOPOLOGY_KEY_LOCATIONS") ? getenv("POT_TOPOLOGY_KEY_LOCATIONS") : "NOT SET");
  printf("==== End Environment Variables ====\n\n");

  printf("==== Runtime Information ====\n");
  printf("Global node index: %d\n", g_node_index);
  printf("Global role: %s (%d)\n", get_role_name(global_role), global_role);
  printf("Operation bypass bit: %d\n", operation_bypass_bit);
  printf("Loaded SRH segments: %d\n", g_segment_count);
  printf("Loaded POT keys: %d\n", g_key_count);
  printf("Next hop entries: %d\n", next_hop_count);
  printf("TSC dynfield offset: %d\n", tsc_dynfield_offset);
  printf("==== End Runtime Information ====\n\n");

  printf("==== Memory Information ====\n");
  if (g_segments != NULL) {
    printf("SRH segments memory: %p (allocated)\n", g_segments);
    printf("Segment list contents:\n");
    for (int i = 0; i < g_segment_count; i++) {
      char seg_str[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, &g_segments[i], seg_str, sizeof(seg_str));
      printf("  [%d]: %s\n", i, seg_str);
    }
  } else {
    printf("SRH segments memory: NOT ALLOCATED\n");
  }
  printf("==== End Memory Information ====\n\n");

  printf("==== Next Hop Table ====\n");
  if (next_hop_count > 0) {
    for (int i = 0; i < next_hop_count; i++) {
      char ipv6_str[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, &next_hops[i].ipv6, ipv6_str, sizeof(ipv6_str));
      printf("  [%d]: %s -> %02x:%02x:%02x:%02x:%02x:%02x\n",
             i, ipv6_str,
             next_hops[i].mac.addr_bytes[0], next_hops[i].mac.addr_bytes[1],
             next_hops[i].mac.addr_bytes[2], next_hops[i].mac.addr_bytes[3],
             next_hops[i].mac.addr_bytes[4], next_hops[i].mac.addr_bytes[5]);
    }
  } else {
    printf("  No next hop entries configured\n");
  }
  printf("==== End Next Hop Table ====\n\n");
}

void print_startup_banner(enum role role, uint16_t rx_port, uint16_t tx_port) {
  printf("Starting %s role on port %u\n", get_role_name(role), rx_port);
  if (role == ROLE_TRANSIT) {
    printf("Transit node using second port %u\n", tx_port);
  }
}
