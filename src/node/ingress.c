#include "include/dpdk_utils.h"
#include "include/node/node_interface.h"
#include "include/packet_utils.h"
#include "include/pot/pot.h"

#include <rte_branch_prediction.h>
#include <rte_bus_pci.h>
#include <rte_dev.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_mempool.h>
#include <rte_os.h>
#include <rte_pci.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

RTE_LOG_REGISTER_DEFAULT(ingress, DEBUG);
#define RTE_LOGTYPE_INGRESS ingress
#define INGRESS_LOG(level, fmt, ...)                                           \
  RTE_LOG(level, INGRESS, "%s(): " fmt "\n", __func__, ##__VA_ARGS__)

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

  INGRESS_LOG(INFO, "Initializing INGRESS node...");
  ingress_data_t *data = calloc(1, sizeof(ingress_data_t));
  if (!data) {
    INGRESS_LOG(ERR, "Failed to allocate memory for ingress data");
    return -1;
  }
  data->config = config; // Config still has hardcoded port_id 0,
                         // tap_port_id 1
  INGRESS_LOG(DEBUG, "Config data: %p",
              config); // Using generic struct access for example

  // Initialize the EAL
  int ret = rte_eal_init(argc, argv);
  INGRESS_LOG(DEBUG, "EAL initialized with ret: %d", ret);
  if (ret < 0) {
    INGRESS_LOG(ERR, "Error initializing EAL: %s", rte_strerror(rte_errno));
    rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
  }

  // Adjust argc and argv for any application-specific EAL arguments if needed,
  // though for this function, we might not have app-specific args after EAL.
  // argc -= ret;
  // argv += ret;

  // --- Dynamically discover the vhost-user port ---
  uint16_t discovered_vhu_port_id = RTE_MAX_ETHPORTS;
  uint16_t nb_ports = rte_eth_dev_count_avail();
  INGRESS_LOG(INFO, "DPDK EAL found %u available ports.", nb_ports);

  if (nb_ports == 0) {
    INGRESS_LOG(ERR, "No DPDK ports available after EAL initialization.");
    // free(data);
    rte_exit(EXIT_FAILURE, "No DPDK ports found\n");
  }

  for (uint16_t i = 0; i < nb_ports; i++) {
    if (!rte_eth_dev_is_valid_port(i))
      continue;
    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(i, &dev_info);
    if (dev_info.driver_name &&
        strcmp(dev_info.driver_name, "net_virtio_user") == 0) {
      // Assuming the first virtio_user port found is the one we want for OVS
      discovered_vhu_port_id = i;
      INGRESS_LOG(INFO, "Found virtio_user port for OVS: ID %u, Driver: %s",
                  discovered_vhu_port_id, dev_info.driver_name);
      break;
    }
  }

  if (discovered_vhu_port_id == RTE_MAX_ETHPORTS) {
    INGRESS_LOG(ERR, "Could not find the virtio_user port (for OVS). Check "
                     "--vdev arguments.");
    // free(data);
    rte_exit(EXIT_FAILURE, "virtio_user port not found\n");
  }
  data->port_id =
      discovered_vhu_port_id; // IMPORTANT: Use the discovered port ID
  // --- End of dynamic discovery ---

  // For tap_port_id, if it's also from a --vdev (e.g., --vdev net_tap0,...),
  // you'd need similar discovery logic. For now, let's assume it might be
  // unused or refers to the original hardcoded config->tap_port_id for a
  // different test. If you passed config->tap_port_id to ingress_init, you can
  // use it: data->tap_port_id = config->tap_port_id; // Or however tap_port_id
  // is defined in node_config

  // Check that the discovered port exists (port_exists might be redundant if
  // discovery worked) port_exists(data->port_id); // You might want to adapt or
  // remove port_exists if discovery is robust

  data->mbuf_pool = rte_pktmbuf_pool_create(
      "MBUF_POOL",
      NUM_MBUFS * rte_eth_dev_count_avail(), // Or NUM_MBUFS for a single port
      MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
  INGRESS_LOG(DEBUG, "Created mbuf pool: %p", data->mbuf_pool);
  if (data->mbuf_pool == NULL) {
    INGRESS_LOG(ERR, "Cannot create mbuf pool: %s", rte_strerror(rte_errno));
    // free(data);
    rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
  }

  // Initialize the discovered vhost-user port
  INGRESS_LOG(INFO, "Initializing vhost-user port %u.", data->port_id);
  port_init(data->port_id, data->mbuf_pool);

  // Handle tap_port_id initialization if needed.
  // If data->tap_port_id is also supposed to be a DPDK port (e.g. from --vdev
  // net_tap0) it also needs dynamic discovery. If it's just a placeholder or
  // configured elsewhere, ensure port_init can handle it or it's correctly set
  // up. For the OVS test, this is secondary. For now, let's assume the original
  // tap_port_id from config is what you might want to use for it. If config is
  // `const struct node_config* config` and node_config has tap_port_id:
  // data->tap_port_id = ((ingress_config_t*)config)->tap_port_id; // Example if
  // casting needed INGRESS_LOG(INFO, "Attempting to initialize TAP port %u.",
  // data->tap_port_id); port_init(data->tap_port_id, data->mbuf_pool);

  INGRESS_LOG(INFO, "Ingress DPDK Ports: RX/TX (vhost-user)=%d", data->port_id);
  // If tap port is used: , TAP=%d\n", data->port_id, data->tap_port_id);
  INGRESS_LOG(INFO, "Ingress node initialized");
  *node_specific_data = data; // Assign data to output parameter
  return 0;
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