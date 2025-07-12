#include "init.h"
#include "headers.h"
#include "utils/logging.h"
#include "utils/utils.h"
#include <fcntl.h>
#include <getopt.h>
#include <rte_ethdev.h>
#include <stdio.h>
#include <stdlib.h>
#include "crypto.h"
#include "node/controller.h"

void init_eal(int argc, char* argv[]) {
  LOG_MAIN(DEBUG, "Initializing DPDK EAL\n");

  // Initialize the Environment Abstraction Layer (EAL) for DPDK.
  // 'argc' and 'argv' are typically the command-line arguments passed
  // to the main function of the application. The EAL parses these
  // arguments to configure itself (e.g., --lcores, --socket-mem, -c, -n).
  int ret = rte_eal_init(argc, argv);
  if (ret < 0) rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
}

void init_ports(uint16_t port_id, struct rte_mempool* mbuf_pool, PortRole role) {
  if (setup_port(port_id, mbuf_pool) != 0) {
    rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", port_id);
  }

  switch (role) {
  case PORT_ROLE_LATENCY_RX:
    rte_eth_add_rx_callback(port_id, 0, add_timestamps, NULL);
    LOG_MAIN(INFO, "Added RX timestamp callback to port %u\n", port_id);
    break;
  case PORT_ROLE_LATENCY_TX:
    rte_eth_add_tx_callback(port_id, 0, calc_latency, NULL);
    LOG_MAIN(INFO, "Added TX latency calculation callback to port %u\n", port_id);
    break;
  }
}

struct rte_mempool* init_mempool() {
  LOG_MAIN(DEBUG, "Creating mbuf pool\n");

  struct rte_mempool* mbuf_pool =
      rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * rte_eth_dev_count_avail(), MBUF_CACHE_SIZE, 0,
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

int init_topology() {

  // Guard, check if the environment variable POT_NODE_INDEX is set.
  if (getenv("POT_NODE_INDEX") == NULL) {
    LOG_MAIN(ERR, "Environment variable POT_NODE_INDEX is not set\n");
    setenv("POT_NODE_INDEX", "0", 1); // Set a default value
    LOG_MAIN(INFO, "Setting default POT_NODE_INDEX=0\n");
  }

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
  int num_transit = getenv_int("POT_TOPOLOGY_NUM_TRANSIT_NODES");
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

  char log_file_path[256];
  snprintf(log_file_path, sizeof(log_file_path), "%s/%s-%d-%02d-%02d_%02d%02d%02d.log", log_dir,
           component_name, tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

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

  printf("Logging initialized: %s\n", log_file_path);
  LOG_MAIN(INFO, "Logging initialized: %s\n", log_file_path);

  return 0;
}

void init_lookup_table() {
  printf("DEBUG: Starting init_lookup_table\n");
  LOG_MAIN(DEBUG, "Initializing lookup table for next hops\n");
  
  add_next_hop("2a05:d014:dc7:1209:8169:d7d9:3bcb:d2b3", "02:5f:68:c7:cc:cd");
  add_next_hop("2a05:d014:dc7:12dc:9648:6bf3:e182:c7b4", "02:f5:27:51:bc:1d");
  
  printf("DEBUG: Second next hop added successfully\n");
  
  printf("DEBUG: init_lookup_table completed\n");
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
