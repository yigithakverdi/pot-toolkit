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
  struct {
    char *type;
    char *log_level;
    char *log_file;
  } node;
  struct {
    char *segment_list;
    char *key_locations;
    int num_transit;
  } topology;
  int follow_flag;
} AppConfig;

int load_app_config(AppConfig* config);
void config_load_env(AppConfig* config);
void load_string_from_env(char** target, const char* env_var_name);
void config_load_defaults(AppConfig* config);
void config_destroy(AppConfig* config);
void sync_config_to_env(AppConfig* config);

#endif // CONFIG_H