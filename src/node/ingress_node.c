#include "include/dpdk_utils.h"
#include "include/node/node_interface.h"
#include "include/packet_utils.h"
#include "include/pot/pot.h"

#include <rte_branch_prediction.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
  const struct node_config *config;

  uint16_t rx_port_id;
  uint16_t tx_port_id;

  uint16_t port_id;
  uint16_t tap_port_id;

  struct rte_mempool *mbuf_pool;

  // ... other configs can be added as needed
  // ...

} ingress_data_t;

// Implementing the node interfaces for ingress node
static int ingress_init(int argc, char **argv, const struct node_config *config,
                        void **node_specific_data) {
  printf("Initializing INGRESS node ... \n");

  // Allocating memory for ingress-specific data
  ingress_data_t *data = calloc(1, sizeof(ingress_data_t));
  if (!data) {
    perror("Failed to allocate memory for ingress data");
    return -1;
  }
  data->config = config;

  // Initialize the EAL
  int ret = rte_eal_init(argc, argv);
  if (ret < 0) {
    rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
  }

  // Check that there is at least one port available
  port_exists(data->port_id);

  // Create a memory pool to hold the mbufs
  data->mbuf_pool = rte_pktmbuf_pool_create(
      "MBUF_POOL", NUM_MBUFS * rte_eth_dev_count_avail(), MBUF_CACHE_SIZE, 0,
      RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

  if (data->mbuf_pool == NULL) {
    rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
  }

  // Initialzie the port
  port_init(data->port_id, data->mbuf_pool);
  port_init(data->tap_port_id, data->mbuf_pool);

  // Parse ingress-specific command-line arguments (if any)
  // Configure DPDK ports based on config
  // Initialize Proof of Transit state specific to ingress
  // ... implementation details
  // ...
  printf("Ingress DPDK Ports: RX=%d, TX=%d\n", data->port_id,
         data->tap_port_id); // Example
  printf("Ingress node initialized.\n");
}

static int ingress_run(void *node_specific_data) {
  ingress_data_t *data = (ingress_data_t *)node_specific_data;
  printf("Running INGRESS node on lcore %u\n", rte_lcore_id());

  volatile int running = 1;
  // Register signal handler or use DPDK's lcore quit flag

  while (running /* check application quit flag */) {
    // 1. Receive packets using DPDK (e.g., rte_eth_rx_burst) on
    // data->rx_port_id
    // 2. Process packets:
    //    - Apply ingress-specific logic
    //    - Call Proof of Transit library functions (e.g., add_pot_metadata)
    // 3. Send packets using DPDK (e.g., rte_eth_tx_burst) on data->tx_port_id
    // ... implementation details ...

    // Initialize the array of packet buffers
    struct rte_mbuf *bufs[BURST_SIZE];
    uint16_t nb_rx = rte_eth_rx_burst(data->port_id, 0, bufs, BURST_SIZE);

    // No packets received, continue to next iteration
    if (unlikely(nb_rx == 0)) {
      continue;
    }

    for (int i = 0; i < nb_rx; i++) {
      process_packet();
    }

    // Example check: if (rte_eal_get_lcore_state(rte_lcore_id()) == WAIT)
    // keep_running = 0; should_stop_processing() Implement this check based on
    // signals/DPDK state
    // if (true) {
    //   running = 0;
    // }
  }

  printf("Ingress node run loop finished.\n");
  return 0;
}

static void ingress_cleanup(void *node_specific_data) {
  ingress_data_t *data = (ingress_data_t *)node_specific_data;
  printf("Cleaning up INGRESS node...\n");

  if (data) {
    // Release DPDK resources (ports, queues)
    // Clean up PoT state
    // ... implementation details ...
    free(data);
  }
  printf("Ingress node cleanup complete.\n");
}

static void ingress_handle_signal(int signum, void *node_specific_data) {
  // ingress_data_t *data = (ingress_data_t *)node_specific_data; // If needed
  printf("INGRESS node received signal %d. Initiating shutdown...\n", signum);
  // Set a flag that ingress_run() checks to stop its loop gracefully
  // signal_shutdown_flag = 1; // Assume a global or accessible flag
}

// Make it visible outside this file if needed (e.g., if main.c directly
// references it) Otherwise, provide a getter function.
const node_operations_t ingress_ops = {
    .init = ingress_init,
    .run = ingress_run,
    .cleanup = ingress_cleanup,
    .handle_signal = ingress_handle_signal
    // Initialize other function pointers if defined
};

// Optional: Getter function if main.c doesn't directly link ingress_ops
const node_operations_t *get_ingress_operations() { return &ingress_ops; }