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

// Global variable to indicate if running in a virtual machine
int g_is_virtual_machine = 0; 

void config_init(AppConfig* config) {
  config->node.log_level = NULL;
  config->node.type = NULL;
  config->topology.key_locations = NULL;
  config->topology.segment_list = NULL;

  // Sayısal değerleri sıfırla
  config->topology.num_transit = 0;
  config->virtual_machine = 0;     // Default: not running in a VM
  config->follow_flag = 0;         // Default: do not follow log
}

// AppConfig tarafından ayrılan tüm dinamik belleği serbest bırakır.
void config_destroy(AppConfig* config) {
  // Free the dynamically allocated strings in the AppConfig structure.
  // with the strdup function, we ensure that we only free memory
  // that was allocated with strdup, and not any other memory.
  free(config->node.log_level);
  free(config->node.type);
  free(config->topology.key_locations);
  free(config->topology.segment_list);

  // For safety, set pointers to NULL after freeing them
  config->node.log_level = NULL;
  config->node.type = NULL;
  // ...
}

// Loads default config values
void config_load_defaults(AppConfig* config) {
  // Node default settings
  free(config->node.log_level);
  config->node.log_level = strdup("info");

  free(config->node.type);
  config->node.type = strdup("transit");

  // Topology default settings
  config->topology.num_transit = 1;

  free(config->topology.key_locations);
  config->topology.key_locations = strdup("/etc/secret/pot_keys.txt");

  free(config->topology.segment_list);
  config->topology.segment_list = strdup("/etc/segment/segment_list.txt");
}

// For string env values, safely loads the value from the environment variable
// into the target pointer, freeing any previously allocated memory.
// If the environment variable is not set, the target pointer remains unchanged.
void load_string_from_env(char** target, const char* env_var_name) {
  const char* env_val = getenv(env_var_name);
  if (env_val) {
    free(*target);
    *target = strdup(env_val);
  }
}

// Main function to load configuration from environment variables.
void config_load_env(AppConfig* config) {
  load_string_from_env(&config->node.log_level, "APP_NODE_LOG_LEVEL");
  load_string_from_env(&config->topology.segment_list, "APP_TOPOLOGY_SEGMENT_LIST_PATH");
  load_string_from_env(&config->topology.key_locations, "APP_TOPOLOGY_KEY_LOCATIONS");

  // Safer for integer values:
  // Read the number of transit nodes from the environment variable.
  // If the variable is not set or has an invalid value, it will not change the
  // default value set in config_load_defaults.
  const char* env_val_num_transit = getenv("APP_TOPOLOGY_NUM_TRANSIT_NODES");
  if (env_val_num_transit) {
    char* endptr;
    errno = 0; // Hata kontrolü için errno'yu sıfırla
    long val = strtol(env_val_num_transit, &endptr, 10);

    // Error handling:
    // 1. Was there an error during conversion (e.g., overflow)?
    // 2. Was the entire string converted to a number?
    if (errno == 0 && *endptr == '\0' && env_val_num_transit != endptr) {
      config->topology.num_transit = (int)val;
    } else {
      fprintf(stderr, "WARN: Invalid value for APP_TOPOLOGY_NUM_TRANSIT_NODES: '%s'. Using previous value.\n",
              env_val_num_transit);
    }
  }
}

void sync_config_to_env(AppConfig* config) {
  // Convert numerical values to strings and set environment variables
  char num_transit_str[16];
  snprintf(num_transit_str, sizeof(num_transit_str), "%d", config->topology.num_transit);
  setenv("POT_TOPOLOGY_NUM_TRANSIT_NODES", num_transit_str, 1);

  // Sync string values if needed
  if (config->node.type) setenv("POT_NODE_TYPE", config->node.type, 1);
  if (config->node.log_level) setenv("POT_NODE_LOG_LEVEL", config->node.log_level, 1);
  if (config->topology.segment_list) {
    setenv("POT_TOPOLOGY_SEGMENT_LIST_PATH", config->topology.segment_list, 1);
    setenv("POT_SEGMENT_LIST_FILE", config->topology.segment_list, 1);
  }
  if (config->topology.key_locations) {
    setenv("POT_TOPOLOGY_KEY_LOCATIONS", config->topology.key_locations, 1);
    // Add this line to fix the segmentation fault
    setenv("POT_KEYS_FILE", config->topology.key_locations, 1);
  }
}

// Loads all the config settings in the following order:
// 1. Initializes the AppConfig struct to a safe state.
// 2. Loads compile-time defaults.
// 3. Optionally loads configuration from a file (not recommended for production).
// 4. Loads environment variables (highest priority).
// 5. Optionally validates that all required settings are set.
//    This step is optional but recommended for ensuring the application has all necessary configurations.
// Returns 0 on success, -1 on failure.
int load_app_config(AppConfig* config) {

  // 1. Initialization: Set all pointers to NULL and numeric values to 0.
  config_init(config);

  // 2. Step: Load compile-time defaults.
  config_load_defaults(config);

  // (OPTIONAL BUT RECOMMENDED) Step 3: Load configuration from a file.
  // config_load_file(config, "/etc/app/config.toml");
  // This layer overrides defaults but can be overridden by environment variables.

  // Step 4: Load environment variables (highest priority).
  config_load_env(config);

  // (OPTIONAL) Step 5: Verify that all required settings have been set
  // if (config->topology.key_locations == NULL) {
  //    fprintf(stderr, "ERROR: Mandatory config 'key_locations' is not set!\n");
  //    return -1;
  // }

  return 0;
}