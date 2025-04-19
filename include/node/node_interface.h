#ifndef NODE_TYPE_INTERFACE_H
#define NODE_TYPE_INTERFACE_H

#include <rte_eal.h>

// Forward declaration it since node_config is complex
struct node_config;

// Structure defining the operations for any node type
typedef struct {
    /**
     * @brief Initializes the node-specific components.
     *
     * @param argc Argument count passed to the application (after EAL parsing if using DPDK).
     * @param argv Argument vector passed to the application (after EAL parsing).
     * @param config Pointer to application configuration.
     * @param node_specific_data Pointer to a void pointer, allows the node to allocate and manage its own state.
     * @return 0 on success, negative error code on failure.
     */
    int (*init)(int argc, char **argv, const struct node_config *config, void **node_specific_data);

    /**
     * @brief Runs the main processing loop for the node.
     *
     * This function will likely contain the core packet processing logic,
     * calling DPDK rx/tx and Proof of Transit functions.
     *
     * @param node_specific_data Pointer to the node's private state data (allocated in init).
     * @return 0 on successful completion, non-zero on error or premature exit.
     */
    int (*run)(void *node_specific_data);

    /**
     * @brief Cleans up resources allocated by the node.
     *
     * @param node_specific_data Pointer to the node's private state data.
     */
    void (*cleanup)(void *node_specific_data);

    /**
     * @brief Handles specific signals (optional, e.g., for graceful shutdown).
     *
     * @param signum The signal number received.
     * @param node_specific_data Pointer to the node's private state data.
     */
    void (*handle_signal)(int signum, void *node_specific_data);

    // Add other common operations as needed, e.g.:
    // void (*print_stats)(void *node_specific_data);
    // int (*reconfigure)(void *node_specific_data, const struct node_config *new_config);

} node_operations_t;

// Enum for node types (optional but good practice)
typedef enum {
    NODE_TYPE_UNKNOWN = 0,
    NODE_TYPE_INGRESS,
    NODE_TYPE_EGRESS,
    NODE_TYPE_TRANSIT
} node_type_e;

#endif // NODE_TYPE_INTERFACE_H