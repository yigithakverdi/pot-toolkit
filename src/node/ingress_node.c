#include "include/node/node_interface.h"
#include <rte_eal.h>                // Example for DPDK
#include <rte_ethdev.h>             // Example for DPDK
#include <signal.h>
#include <stdlib.h>
#include <stdio.h> // Include necessary headers

typedef struct {
    const struct node_config *config;

    uint16_t rx_port_id;
    uint16_t tx_port_id;

    // ... other configs can be added as needed
    // ...
    
} ingress_data_t;


// Implementing the node interfaces for ingress node
static int ingress_init(int argc, char **argv, const struct node_config *config, void **node_specific_data) {
    printf("Initializing INGRESS node ... \n");

    // Allocating memory for ingress-specific data
    ingress_data_t *data = calloc(1, sizeof(ingress_data_t));
    if (!data) {
        perror("Failed to allocate memory for ingress data");
        return -1;
    }
    data->config = config;

    // Parse ingress-specific command-line arguments (if any)
    // Configure DPDK ports based on config
    // Initialize Proof of Transit state specific to ingress
    // ... implementation details
    // ...
    printf("Ingress DPDK Ports: RX=%d, TX=%d\n", data->rx_port_id, data->tx_port_id); // Example
    printf("Ingress node initialized.\n");    
}


static int ingress_run(void *node_specific_data) {
    ingress_data_t *data = (ingress_data_t *) node_specific_data;
    printf("Running INGRESS node on lcore %u\n", rte_lcore_id());

    volatile int running = 1;
    // Register signal handler or use DPDK's lcore quit flag    

    while (running /* check application quit flag */) {
        // 1. Receive packets using DPDK (e.g., rte_eth_rx_burst) on data->rx_port_id
        // 2. Process packets:
        //    - Apply ingress-specific logic
        //    - Call Proof of Transit library functions (e.g., add_pot_metadata)
        // 3. Send packets using DPDK (e.g., rte_eth_tx_burst) on data->tx_port_id
        // ... implementation details ...

        // Example check: if (rte_eal_get_lcore_state(rte_lcore_id()) == WAIT) keep_running = 0;
        // should_stop_processing()
         if (true) { // Implement this check based on signals/DPDK state
              running = 0;
         }
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

// Make it visible outside this file if needed (e.g., if main.c directly references it)
// Otherwise, provide a getter function.
const node_operations_t ingress_ops = {
    .init = ingress_init,
    .run = ingress_run,
    .cleanup = ingress_cleanup,
    .handle_signal = ingress_handle_signal
    // Initialize other function pointers if defined
};


// Optional: Getter function if main.c doesn't directly link ingress_ops
const node_operations_t* get_ingress_operations() {
    return &ingress_ops;
}