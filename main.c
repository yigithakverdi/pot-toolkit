// Testing ground for the Nodes and all the configurations of the app is
// initialized here and then passed to the node instances
//
// Here the architecture of the current running POT landscape can be realized as
// well and the nodes can be initialized and run
//

#include "include/node/node_interface.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern node_operations_t ingress_ops;

typedef struct {
  uint16_t port_id;
  uint16_t tap_port_id;
  char *role;
} ingress_config_t;

int main(int argc, char **argv) {

  // If the provided argument node type is ingress, egress or transit, program
  // enters to the necessary conditions to intialize the necessary functions
  // that belong to that specific node type
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <node_type>\n", argv[0]);
    return EXIT_FAILURE;
  }

  // Egress node type
  if (strcmp(argv[1], "egress") == 0) {
    // Initialize egress related configurations, that will be passed to the
    // egress init functions
  }

  // Transit node type
  else if (strcmp(argv[1], "transit") == 0) {
    // Initialize transit related configurations, that will be passed to the
    // transit init functions
  }

  // Ingress node type
  else if (strcmp(argv[1], "ingress") == 0) {
    // Initialize ingress related configurations, that will be passed to the
    // ingress init functions

    // Initialize ingress related configurations, that will be passed to the
    // ingress init functions
    ingress_config_t config = {
        .port_id = 0,
        .tap_port_id = 1,
        .role = "ingress",
    };

    void *ingress_data = NULL;
    if (ingress_ops.init(argc, argv, (const struct node_config *)&config,
                         &ingress_data) != 0) {
      fprintf(stderr, "Failed to initialize ingress node\n");
      return EXIT_FAILURE;
    }

    // ingress_ops.run(ingress_data);
    // ingress_ops.cleanup(ingress_data);

  }

  else {
    fprintf(stderr, "Unknown node type: %s\n", argv[1]);
    return EXIT_FAILURE;
  }

  return 0;
}