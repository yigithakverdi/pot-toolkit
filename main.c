#include "crypto.h"
#include "forward.h"
#include "headers.h"
#include "utils/config.h"
#include "init.h"
#include "port.h"
#include "utils/config.h"
#include "utils/role.h"
#include "utils/utils.h"
#include <rte_ethdev.h>

int main(int argc, char* argv[]) {

  // Initialize empty AppConfig structure later on will be filled with default values.
  AppConfig config;

  // Initialize the logging
  init_logging("/var/log/dpdk-pot", "pot", RTE_LOG_DEBUG);

  // Initialize the DPDK environment, the first thing application does is initializing the EAL
  // it sets up the infrastructure configurations that our DPDK apps needed to run, so it is
  // important to call this function first, in terms of both making sure everything is set up
  // correctly on EAL without any side effects caused by our app.
  int ret = init_eal(argc, argv);
  if(ret < 0) {
    rte_exit(EXIT_FAILURE, "Failed to initialize EAL\n");
  }

  argc -= ret; // Adjust argc to account for EAL arguments
  argv += ret; // Adjust argv to point to the application-specific arguments

  // Given the EAL, and configurations are set up, we check the available ports
  // and make sure that we have at least one port available to use, otherwise we exit the
  // application with an error message. And afterwards if everyhing works fine initializes the
  // ports, and sets up the memory pool for the mbufs.
  check_ports();

  // Initialize the memory pool, that is used for the mbufs, that are used to store the packets
  // that are received from the ports, and sent to the ports. The memory pool is a shared resource
  // that is used by the DPDK framework to allocate and deallocate memory for the mbufs.
  struct rte_mempool* mbuf_pool = init_mempool();
  register_tsc_dynfield();

  // Initialize the topology configurations, this is manily the transit node set up, number of
  // tranist nodes, in between ingress and egress nodes, however these creates topology.ini file
  // and node.ini files in a default location, these two crucical config files then point to the
  // segment_list, and key files that is used to define the core PoT processing logic
  config_init(&config);
  config_load_defaults(&config);
  config_load_env(&config);

  // Parse the arguments, it sets up environment variables, depending on the given arguments,
  // if optional arguments not given then default values are used, that are defined under .ini
  // files.
  //
  // NOTE the CLI arguments defined here overrides the previous default config loads, it also
  // overrides what is already defined on the environment, and updates the related changes.
  // after that sync the config with the environment variables.
  parse_args(&config, argc, argv);
  global_role = setup_node_role(config.node.type);
  sync_config_to_env(&config);

  // TODO before initializing the topology force the index of the current node from the
  // environment variable that is supplied when running the script `setup_container_veth.sh`
  // this script creates NODE_INDEX env variable for each container, normally, this should be
  // integrated through the controller node, that is responsible for Shamir Secret Sharing
  // and the key distribution, however, for now, we are forcing the node index through the
  // script `setup_container_veth.sh`
  // g_node_index = getenv_int("POT_NODE_INDEX");

  // Init topology after calling the default arguments load, and the parse args function, which
  // might overload the given default values
  if (init_topology(&config) < 0) {
    rte_exit(EXIT_FAILURE, "Failed to initialize topology\n");
  }

  // TODO set the global variable here for temporarly normaly they should be set 
  // in their respective fields, and contexts, however, for now, we are
  // setting them here, since we are not using the config struct in the rest of the
  // application, we are just using the global variables.
  num_transit_nodes = config.topology.num_transit;
  

  // Initialize the lookup table, that will be used to forward the packet to destined node
  // given the IPv6 info from SRH, that is then mapped to MAC address using this lookup table.
  init_lookup_table();

  // NOTE Define the ports, these are fixed, across each node type, ingress, transit and egress
  // since the ingress and egress assumed to be not using the second port, the definitions
  // assumed to be not affect the an access to a element that is not used
  // Determine available ports and handle single-port loopback in transit mode
  uint16_t port_count = rte_eth_dev_count_avail();
  uint16_t rx_port = 0;
  uint16_t tx_port = 1;
  if (global_role == ROLE_TRANSIT && port_count < 2 && config.virtual_machine == 1) {
    LOG_MAIN(INFO, "[INFO] Virtual machine mode is set up\n");
    LOG_MAIN(WARNING, "Transit mode with only %u port(s): using port %u for both RX and TX",
             port_count, rx_port);
    tx_port = rx_port;
  }
  uint16_t ports[2] = {rx_port, tx_port};
  init_ports(rx_port, mbuf_pool, 0);

  // After initializing the port with ID-0, we can set up the RX and TX queues
  // for the port. This is important for ensuring that packets can be received
  // and transmitted correctly.
  // rte_eth_add_rx_callback(0, 0, add_timestamps, NULL);
  // rte_eth_add_tx_callback(0, 0, calc_latency, NULL);

  // If the role of the node is transit then initialize the second port since it might
  // be used for the veth pairing in case of container setup, besides the VM setup
  LOG_MAIN(INFO, "Virtual machine mode is %s\n", config.virtual_machine ? "enabled" : "disabled");
  if (config.virtual_machine == 0 && (global_role == ROLE_INGRESS || global_role == ROLE_TRANSIT || global_role == ROLE_EGRESS)) { // Ingress also needs a TX port for the chain
    LOG_MAIN(INFO, "[INFO] Virtual machine mode is disabled shifting to container mode\n");
    if (tx_port != rx_port) {
      LOG_MAIN(INFO, "[INFO] Setting up second port %u for %s role\n", tx_port, 
               global_role == ROLE_INGRESS ? "ingress" : "transit");
      init_ports(tx_port, mbuf_pool, 1); // Pass 1 for TX role if you have TX callbacks
    } else {
      LOG_MAIN(INFO, "Single-port loopback mode: skipping init of port %u for TX", tx_port);
    }
  }

  // Print the system information, before starting the packet processing loop
  print_system_info(&config);

  // Start the packet processing loop after the flight checks:
  // ...
  // - Initialization of the EAL
  // - Initialization of the memory pool
  // - Initialization of the ports
  // - Initialization of the packet processing functions
  // launch_lcore_forwarding(ports);
  
  // Add memory validation before launching forwarding
  printf("DEBUG: Validating memory before launching forwarding\n");
  LOG_MAIN(DEBUG, "Mbuf pool pointer: %p\n", mbuf_pool);
  LOG_MAIN(DEBUG, "Available mbufs in pool: %u\n", rte_mempool_avail_count(mbuf_pool));
  LOG_MAIN(DEBUG, "In-use mbufs in pool: %u\n", rte_mempool_in_use_count(mbuf_pool));

  // Verify hugepage memory is available
  // printf("DEBUG: Checking hugepage memory\n");
  // const struct rte_memseg_list *msl;

  // Launch the packet processing loop
  launch_lcore_forwarding(ports);

  // Free the segment list in any case
  atexit(free_srh_segments);

  return 0;
}

