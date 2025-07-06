#include "crypto.h"
#include "headers.h"
#include "port.h"
#include "utils/config.h"
#include "utils/role.h"
#include "utils/utils.h"

int main(int argc, char* argv[]) {

  // Initialize the DPDK environment, the first thing application does is initializing the EAL
  // it sets up the infrastructure configurations that our DPDK apps needed to run, so it is
  // important to call this function first, in terms of both making sure everything is set up
  // correctly on EAL without any side effects caused by our app.
  init_eal(argc, argv);

  // Initialize the memory pool, that is used for the mbufs, that are used to store the packets
  // that are received from the ports, and sent to the ports. The memory pool is a shared resource
  // that is used by the DPDK framework to allocate and deallocate memory for the mbufs.
  init_mempool();
  register_tsc_dynfield();

  // Initialize the topology configurations, this is manily the transit node set up, number of
  // tranist nodes, in between ingress and egress nodes, however these creates topology.ini file
  // and node.ini files in a default location, these two crucical config files then point to the
  // segment_list, and key files that is used to define the core PoT processing logic
  AppConfig conf = config_load_defaults();
  config_load_env(&conf);

  // Parse the arguments, it sets up environment variables, depending on the given arguments,
  // if optional arguments not given then default values are used, that are defined under .ini
  // files.
  //
  // NOTE the CLI arguments defined here overrides the previous default config loads, it also
  // overrides what is already defined on the environment, and updates the related changes
  parse_args(argc, argv);

  // TODO Besides the environment variables, also set the global variables according to given
  // configurations these are mostly extern variables, and sometimes preprocessors, for
  // now the number of transit for global variable defined here
  const char* num_transit_env = getenv("APP_TOPOLOGY_NUM_TRANSIT_NODES");
  if (num_transit_env) {
    num_transit_nodes = atoi(num_transit_env);
  } else {
    // Ortam değişkeni yoksa, conf'daki son değere (default/ini) geri dön
    num_transit_nodes = conf.topology.num_transit;
  }
  printf("App will start with %d number of transit nodes.\n", num_transit_nodes);

  // Init topology after calling the default arguments load, and the parse args function, which
  // might overload the given default values
  if (init_topology() < 0) {
    rte_exit(EXIT_FAILURE, "Failed to initialize topology\n");
  }

  // Given the EAL, and configurations are set up, we check the available ports
  // and make sure that we have at least one port available to use, otherwise we exit the
  // application with an error message. And afterwards if everyhing works fine initializes the
  // ports, and sets up the memory pool for the mbufs.
  check_ports();

  // NOTE Define the ports, these are fixed, across each node type, ingress, transit and egress
  // since the ingress and egress assumed to be not using the second port, the definitions
  // assumed to be not affect the an access to a element that is not used
  uint16_t rx_port = 0;
  uint16_t tx_port = 1;
  init_ports(rx_port, tx_port, 0);

  // If the role of the node is transit then initialize the second port since it might
  // be used for the veth pairing in case of container setup, besides the VM setup
  if (global_role == ROLE_TRANSIT) {
    printf("[INFO] Setting up second port %u for transit role\n", tx_port);
    init_ports(tx_port, tx_port, 1);
  }

  // Print the system information, before starting the packet processing loop
  print_system_info(&conf);

  // Start the packet processing loop after the flight checks:
  // ...
  // - Initialization of the EAL
  // - Initialization of the memory pool
  // - Initialization of the ports
  // - Initialization of the packet processing functions

  // Free the segment list in any case
  atexit(free_srh_segments);

  return 0;
}