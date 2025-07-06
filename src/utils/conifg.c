#include <arpa/inet.h>
#include <inttypes.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "utils/config.h"
#include "utils/logging.h"

AppConfig config_load_defaults() {
  AppConfig config;

  // Node default settings
  config.node.log_level = "info";
  config.node.type = strdup("transit");

  // Topology default settings
  config.topology.num_transit = 1; // Default number of transit nodes
  config.topology.key_locations = strdup("/etc/secret/key_locations.json");
  config.topology.segment_list = strdup("/etc/segment/segment_list.json");
  return config;
}

int read_segment_list(const char* file_path) {
  FILE* f = fopen(file_path, "r");
  if (!f) {
    perror("Failed to open segment list file");
    return -1;
  }

  // TODO implement the logic of reading the segment list from a file and returning
  //  it in the desired format.
  //  ...
}

// Helper function for loading the given environment variable, either from CLI arugments
// or from defaults.
void config_load_env(AppConfig* config) {
  const char* env_val;

  if ((env_val = getenv("APP_NODE_LOGGING_LEVEL"))) {
    free(config->node.log_level);
    config->node.log_level = strdup(env_val);
  }

  if ((env_val = getenv("APP_TOPOLOGY_SEGMENT_LIST_PATH"))) {
    free(config->topology.segment_list);
    config->topology.segment_list = strdup(env_val);
  }
  // ... repeat for all possible environment variables
}