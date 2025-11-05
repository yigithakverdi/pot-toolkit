#include "init.h"
#include "crypto.h"
#include "headers.h"
#include "node/controller.h"
#include "utils/logging.h"
#include "utils/utils.h"
#include <fcntl.h>
#include <getopt.h>
#include <openssl/md5.h>
#include <rte_ethdev.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int init_eal(int argc, char* argv[]) {
  LOG_MAIN(DEBUG, "Initializing DPDK EAL\n");

  // Initialize the Environment Abstraction Layer (EAL) for DPDK.
  // 'argc' and 'argv' are typically the command-line arguments passed
  // to the main function of the application. The EAL parses these
  // arguments to configure itself (e.g., --lcores, --socket-mem, -c, -n).
  int ret = rte_eal_init(argc, argv);
  if (ret < 0) rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
  return ret;
}

void init_ports(uint16_t port_id, struct rte_mempool* mbuf_pool, PortRole role) {
  if (setup_port(port_id, mbuf_pool) != 0) {
    rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", port_id);
  }

  // Note: Using software checksum calculation, so hardware offload capability checks are not needed

  // rte_eth_add_rx_callback(port_id, 0, add_timestamps, NULL);
  // LOG_MAIN(INFO, "Added RX timestamp callback to port %u\n", port_id);

  // rte_eth_add_tx_callback(port_id, 0, calc_latency, NULL);
  // LOG_MAIN(INFO, "Added TX latency calculation callback to port %u\n", port_id);

  // switch (role) {
  // case PORT_ROLE_LATENCY_RX:
  //   rte_eth_add_rx_callback(port_id, 0, add_timestamps, NULL);
  //   // rte_eth_add_tx_callback(port_id, 0, calc_latency, NULL);
  //   LOG_MAIN(INFO, "Added RX timestamp callback to port %u\n", port_id);
  //   break;
  // case PORT_ROLE_LATENCY_TX:
  //   rte_eth_add_tx_callback(port_id, 0, calc_latency, NULL);
  //   LOG_MAIN(INFO, "Added TX latency calculation callback to port %u\n", port_id);
  //   break;
  // }
}

struct rte_mempool* init_mempool() {
  LOG_MAIN(DEBUG, "Creating mbuf pool\n");

  struct rte_mempool* mbuf_pool =
      rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0,
                              RTE_MBUF_DEFAULT_BUF_SIZE + EXTRA_SPACE, rte_socket_id());

  LOG_MAIN(DEBUG, "Mbuf pool created: %p\n", mbuf_pool);

  // Check if the mempool creation was successful.
  // If rte_pktmbuf_pool_create returns NULL, it indicates a failure (e.g.,
  // insufficient huge page memory, invalid arguments). This is a fatal error
  // for a DPDK application as it cannot process packets without mbufs.
  if (mbuf_pool == NULL) rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

  // Return the pointer to the newly created mbuf pool. This pointer will be
  // used by the application to retrieve mbufs for packet I/O and processing.
  LOG_MAIN(DEBUG, "Mbuf pool created successfully\n");
  return mbuf_pool;
}

int init_topology(AppConfig* app_config) {

  // Guard, check if the environment variable POT_NODE_INDEX is set.
  // if (getenv("POT_NODE_INDEX") == NULL) {
  //   LOG_MAIN(ERR, "Environment variable POT_NODE_INDEX is not set\n");
  //   setenv("POT_NODE_INDEX", "0", 1); // Set a default value
  //   LOG_MAIN(INFO, "Setting default POT_NODE_INDEX=0\n");
  // }
  // Forcing the POT_NODE_INDEX from the global node index here regarding
  // the if it is set or not
  char node_index_str[16];
  snprintf(node_index_str, sizeof(node_index_str), "%d", g_node_index);
  setenv("POT_NODE_INDEX", node_index_str, 1);

  LOG_MAIN(DEBUG, "Initializing topology\n");

  // Default number of transit node is set to 1, this is applied to the topology.ini file
  // that will be generated here, later on, changing the number of transit nodes, or
  // changing anything on the transit.ini file after the first run, it will
  // change the configurations accordingly, so that the application can
  // adapt to the new topology.
  //
  // TODO instead of calling it and assigning it with a environment variable,
  // just use config_load_env to first load the environment as it is done
  // on the main.c then use global variables directly
  // int num_transit = getenv_int("POT_TOPOLOGY_NUM_TRANSIT_NODES");
  int num_transit = app_config->topology.num_transit;
  if (num_transit <= 0) {
    LOG_MAIN(ERR, "Invalid number of transit nodes: %d\n", num_transit);
    return -1;
  }

  // After the related ini files are created, topology.ini, node.ini etc.
  // next thing is to define the environment variables. These variables
  // in the end what the application uses, not the definitions under
  // ini files, the env variables, the ini files are basically a secondry
  // way of making the configuration easy.
  LOG_MAIN(DEBUG, "Topology initialized with %d transit nodes\n", num_transit);

  // Read the segments from the segment list file in the specified path, this
  // path is defined under env POT_SEGMENT_LIST_FILE
  const char* segment_list_path = getenv("POT_SEGMENT_LIST_FILE");
  if (segment_list_path == NULL) {
    LOG_MAIN(ERR, "Environment variable POT_SEGMENT_LIST_FILE is not set\n");
    return -1;
  }
  if (load_srh_segments(segment_list_path) < 0) {
    LOG_MAIN(ERR, "Failed to read segment list from %s\n", segment_list_path);
    return -1;
  }

  const char* keys_path = getenv("POT_KEYS_FILE");
  if (keys_path == NULL) {
    LOG_MAIN(ERR, "Ortam değişkeni POT_KEYS_FILE ayarlanmamış\n");
    return -1;
  }

  // For onion encryption 1 (ingress/egress) + transit
  int total_keys_needed = num_transit + 1;
  LOG_MAIN(DEBUG, "Total keys needed: %d\n", total_keys_needed);
  if (total_keys_needed > MAX_POT_NODES + 1) {
    LOG_MAIN(ERR, "Gerekli anahtar sayısı (%d) hard limiti (%d) aşıyor!\n", total_keys_needed,
             MAX_POT_NODES + 1);
    return -1;
  }

  if (load_pot_keys(keys_path, total_keys_needed) < 0) {
    LOG_MAIN(ERR, "Anahtar listesi okunamadı: %s\n", keys_path);
    return -1;
  }
  return 0;
}

int init_logging(const char* log_dir, const char* component_name, int log_level) {
  struct stat st = {0};
  if (stat(log_dir, &st) == -1) {
    if (mkdir(log_dir, 0700) != 0) {
      perror("Failed to create log directory");
      return -1;
    }
  }

  time_t t = time(NULL);
  struct tm tm = *localtime(&t);

  char hostname[128] = {0};
  gethostname(hostname, sizeof(hostname) - 1);

  char log_file_path[256];
  if (g_logging_enabled) {
    snprintf(log_file_path, sizeof(log_file_path), "%s/%s-%s-%d-%02d-%02d_%02d%02d%02d.log", log_dir,
             component_name, hostname, tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min,
             tm.tm_sec);
  }

  int fd = open(log_file_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
  if (fd < 0) {
    fprintf(stderr, "Error opening log file %s: %s\n", log_file_path, strerror(errno));
    return -1;
  }

  rte_log_set_global_level(log_level);
  rte_openlog_stream(fdopen(fd, "a"));

  dpdk_pot_logtype_main = rte_log_register("main");
  if (dpdk_pot_logtype_main < 0) {
    fprintf(stderr, "Error registering main log type\n");
    return -1;
  }

  rte_log_set_level(dpdk_pot_logtype_main, log_level);

  LOG_MAIN(INFO, "Logging initialized: %s\n", log_file_path);

  return 0;
}

void mac_from_name(const char* name, char* mac_str, size_t mac_str_len) {
  unsigned char hash[MD5_DIGEST_LENGTH];
  MD5((const unsigned char*)name, strlen(name), hash);
  snprintf(mac_str, mac_str_len, "02:%02x:%02x:%02x:%02x:%02x", hash[0], hash[1], hash[2], hash[3], hash[4]);
}

// void init_lookup_table() {
//   LOG_MAIN(DEBUG, "Initializing lookup table for next hops\n");
//   add_next_hop("2a05:d014:dc7:1209:8169:d7d9:3bcb:d2b3", "02:5f:68:c7:cc:cd");
//   add_next_hop("2a05:d014:dc7:12dc:9648:6bf3:e182:c7b4", "02:f5:27:51:bc:1d");

//   int num_transit = getenv_int("POT_TOPOLOGY_NUM_TRANSIT_NODES");
//   for (int i = 1; i <= num_transit; ++i) {
//       char ipv6[64], mac[32], veth_name[32];
//       snprintf(ipv6, sizeof(ipv6), "2001:db8:1::%x", i);
//       snprintf(veth_name, sizeof(veth_name), "veth_chain_%db", i-1); // match right_veth in script
//       mac_from_name(veth_name, mac, sizeof(mac));
//       add_next_hop(ipv6, mac);
//       LOG_MAIN(INFO, "Added next hop: IPv6 %s, MAC %s (veth: %s)\n", ipv6, mac, veth_name);
//   }
//   // Add iperf client/egress/server if needed
//   // Example for iperf client <-> ingress
//   char mac[32];
//   mac_from_name("veth_clib", mac, sizeof(mac));
//   add_next_hop("2001:db8:1::100", mac);
//   LOG_MAIN(INFO, "Added next hop: IPv6 2001:db8:1::100, MAC %s (veth: veth_clib)\n", mac);
//   // Example for egress <-> iperf server
//   mac_from_name("veth_srva", mac, sizeof(mac));
//   add_next_hop("2001:db8:1::200", mac);
//   LOG_MAIN(INFO, "Added next hop: IPv6 2001:db8:1::200, MAC %s (veth: veth_srva)\n", mac);
//   LOG_MAIN(DEBUG, "Lookup table initialization completed\n");

//   // add_next_hop("2001:db8:1::100", "56:2a:1a:a3:0c:30");
//   // add_next_hop("2001:db8:1::", "da:71:02:ee:a0:a3");

//   // add_next_hop("2001:db8:1::1", "02:b0:e0:ec:6e:a7");
//   // add_next_hop("2001:db8:1::1", "4a:b7:f6:b8:4c:fe");

//   // add_next_hop("2001:db8:1::2", "8e:a6:41:71:19:5c");
//   // add_next_hop("2001:db8:1::200", "b2:58:54:70:36:16");

//   LOG_MAIN(DEBUG, "Lookup table initialization completed\n");
// }

void init_lookup_table() {
  LOG_MAIN(DEBUG, "[DEBUG] Initializing lookup table for next hops...\n");
  // add_next_hop("2a05:d014:dc7:1209:8169:d7d9:3bcb:d2b3", "02:5f:68:c7:cc:cd");
  // add_next_hop("2a05:d014:dc7:12dc:9648:6bf3:e182:c7b4", "02:f5:27:51:bc:1d");
  // add_next_hop("2a05:d014:dc7:12a5:daf9:c563:8971:16f8", "02:f0:e2:02:7e:f3");
  // add_next_hop("2a05:d014:dc7:1201:4dbc:54b8:7649:1699", "02:c4:7f:5a:2f:bd");
  // add_next_hop("2a05:d014:dc7:1252:d3b9:c07f:f5a5:f25", "02:72:c1:67:18:b1");
  add_next_hop("2a05:d014:dc7:1281:7aa5:aa66:e3d1:d8a5", "02:56:e6:d5:57:05");
  add_next_hop("2a05:d014:dc7:1210:818e:dec3:7ed3:a935", "02:63:a9:59:f8:8f");

  int num_transit = getenv_int("POT_TOPOLOGY_NUM_TRANSIT_NODES");
  if (num_transit < 0) {
    num_transit = 1;
  }

  for (int i = 0; i < num_transit + 1; ++i) {
    char ipv6[64], mac[32], veth_name[32];

    // The IP suffix for the receiving end of link 'i' is (i * 2 + 2)
    int ip_suffix = (i * 2) + 2;
    snprintf(ipv6, sizeof(ipv6), "2001:db8:1::%d", ip_suffix);

    // The MAC address is based on the veth name 'veth_chain_{i}b'
    snprintf(veth_name, sizeof(veth_name), "veth_chain_%db", i);
    mac_from_name(veth_name, mac, sizeof(mac));

    add_next_hop(ipv6, mac);
    LOG_MAIN(INFO, "Added next hop: IPv6 %s, MAC %s (veth: %s)\n", ipv6, mac, veth_name);
  }

  // Add iperf client and server connections
  char mac[32];
  mac_from_name("veth_clib", mac, sizeof(mac));
  add_next_hop("2001:db8:1::100", mac);
  LOG_MAIN(INFO, "Added next hop: IPv6 2001:db8:1::100, MAC %s (veth: veth_clib)\n", mac);

  mac_from_name("veth_srvb", mac, sizeof(mac));
  add_next_hop("2001:db8:1::d1", mac);
  LOG_MAIN(INFO, "Added next hop: IPv6 2001:db8:1::d1, MAC %s (veth: veth_srvb)\n", mac);

  LOG_MAIN(DEBUG, "Lookup table initialization completed\n");
}

void register_tsc_dynfield() {
  LOG_MAIN(DEBUG, "Registering TSC dynamic field for mbufs\n");
  static const struct rte_mbuf_dynfield tsc_dynfield_desc = {
      .name = "dpdk_pot_dynfield_tsc",
      .size = sizeof(tsc_t),
      .align = alignof(tsc_t),
  };
  LOG_MAIN(DEBUG, "TSC dynamic field size: %zu, align: %zu\n", tsc_dynfield_desc.size,
           tsc_dynfield_desc.align);

  // Register a dynamic field for the Time Stamp Counter (TSC) within DPDK mbufs.
  // This allows storing a TSC value directly in each packet buffer (mbuf)
  // without modifying the core rte_mbuf structure.
  //
  // Check if the registration was successful. If not, terminate the application
  // as the ability to store TSC in mbufs is critical.
  tsc_dynfield_offset = rte_mbuf_dynfield_register(&tsc_dynfield_desc);
  if (tsc_dynfield_offset < 0) rte_exit(EXIT_FAILURE, "Cannot register mbuf field\n");
}
