#ifndef CONFIG_H
#define CONFIG_H

typedef struct {
  char* key_locations;
  char* segment_list;
  int num_transit;
} TopologyConfig;

typedef struct {
  char* log_level;
  char* log_file;
  char* type;
} NodeConfig;

typedef struct {
  TopologyConfig topology;
  NodeConfig node;
} AppConfig;

void config_load_env(AppConfig* config);
AppConfig config_load_defaults();

#endif // CONFIG_H