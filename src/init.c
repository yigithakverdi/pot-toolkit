#include "init.h"
#include "utils/logging.h"
#include "utils/utils.h"
#include <getopt.h>
#include <rte_ethdev.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

  // TODO Rest of the logging initialization will be implemented here
  //  ...
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
  LOG_MAIN(DEBUG, "Initializing topology\n");

  // Default number of transit node is set to 1, this is applied to the topology.ini file
  // that will be generated here, later on, changing the number of transit nodes, or
  // changing anything on the transit.ini file after the first run, it will 
  // change the configurations accordingly, so that the application can
  // adapt to the new topology.
  int num_transit = 1;


  // TODO Implement the topology.ini file generation according to logic 
  // that is defined here programatically. 
  // ...

  // After the related ini files are created, topology.ini, node.ini etc.
  // next thing is to define the environment variables. These variables
  // in the end what the application uses, not the definitions under
  // ini files, the env variables, the ini files are basically a secondry
  // way of making the configuration easy. 
  LOG_MAIN(DEBUG, "Topology initialized with %d transit nodes\n", num_transit);
  



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