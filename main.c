#include "crypto.h"
#include "forward.h"
#include "headers.h"
#include "init.h"
#include "node/controller.h"
#include "port.h"
#include "utils/config.h"
#include "utils/role.h"
#include "utils/utils.h"

int main(int argc, char* argv[]) {

  // Initialize empty AppConfig structure later on will be filled with default values.
  AppConfig config;

  // Initialize the logging
  init_logging("/var/log/dpdk-pot", "pot", RTE_LOG_DEBUG);

  // Initialize the DPDK environment, the first thing application does is initializing the EAL
  // it sets up the infrastructure configurations that our DPDK apps needed to run, so it is
  // important to call this function first, in terms of both making sure everything is set up
  // correctly on EAL without any side effects caused by our app.
  init_eal(argc, argv);

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
  printf("DEBUG: After parse_args, config values:\n");
  printf("  node.type: %s\n", config.node.type ? config.node.type : "NULL");
  printf("  node.log_level: %s\n", config.node.log_level ? config.node.log_level : "NULL");
  printf("  topology.segment_list: %s\n", config.topology.segment_list ? config.topology.segment_list : "NULL");
  printf("  topology.key_locations: %s\n", config.topology.key_locations ? config.topology.key_locations : "NULL");
  printf("  topology.num_transit: %d\n", config.topology.num_transit);
  

  sync_config_to_env(&config);

  printf("DEBUG: After sync_config_to_env, environment variables:\n");
  printf("  POT_NODE_TYPE: %s\n", getenv("POT_NODE_TYPE") ? getenv("POT_NODE_TYPE") : "NULL");
  printf("  POT_SEGMENT_LIST_FILE: %s\n", getenv("POT_SEGMENT_LIST_FILE") ? getenv("POT_SEGMENT_LIST_FILE") : "NULL");
  printf("  POT_KEYS_FILE: %s\n", getenv("POT_KEYS_FILE") ? getenv("POT_KEYS_FILE") : "NULL");
  printf("  POT_TOPOLOGY_NUM_TRANSIT_NODES: %s\n", getenv("POT_TOPOLOGY_NUM_TRANSIT_NODES") ? getenv("POT_TOPOLOGY_NUM_TRANSIT_NODES") : "NULL");
  printf("  POT_NODE_INDEX: %s\n", getenv("POT_NODE_INDEX") ? getenv("POT_NODE_INDEX") : "NULL");


  // TODO before initializing the topology force the index of the current node from the
  // environment variable that is supplied when running the script `setup_container_veth.sh`
  // this script creates NODE_INDEX env variable for each container, normally, this should be
  // integrated through the controller node, that is responsible for Shamir Secret Sharing
  // and the key distribution, however, for now, we are forcing the node index through the
  // script `setup_container_veth.sh`
  g_node_index = getenv_int("POT_NODE_INDEX");

  // Init topology after calling the default arguments load, and the parse args function, which
  // might overload the given default values
  if (init_topology() < 0) {
    rte_exit(EXIT_FAILURE, "Failed to initialize topology\n");
  }

  // Initialize the lookup table, that will be used to forward the packet to destined node
  // given the IPv6 info from SRH, that is then mapped to MAC address using this lookup table.
  init_lookup_table();

  // NOTE Define the ports, these are fixed, across each node type, ingress, transit and egress
  // since the ingress and egress assumed to be not using the second port, the definitions
  // assumed to be not affect the an access to a element that is not used
  uint16_t rx_port = 0;
  uint16_t tx_port = 1;
  uint16_t ports[2] = {rx_port, tx_port};
  init_ports(rx_port, mbuf_pool, 0);

  // If the role of the node is transit then initialize the second port since it might
  // be used for the veth pairing in case of container setup, besides the VM setup
  if (global_role == ROLE_TRANSIT) {
    printf("[INFO] Setting up second port %u for transit role\n", tx_port);
    init_ports(tx_port, mbuf_pool, 1);
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
  printf("DEBUG: Checking hugepage memory\n");
  const struct rte_memseg_list *msl;

  // Free the segment list in any case
  // atexit(free_srh_segments);

  return 0;
}
