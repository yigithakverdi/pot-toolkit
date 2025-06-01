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

  // Temporarly harcoding custom arguments and leaving the arugment parsing
  // related to EAL and DPDK.
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

  return 0;
}