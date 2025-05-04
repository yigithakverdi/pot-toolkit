// Main config logic will be handled in an order way, the program will look at
// the default system service location for default configurations, that are
// generated in the initial running phase, if the user have defined separate
// custom config files under /home/user/ under the .pot directory respecting the
// basic system service structure defined under docs then the program will use
// those configs, in the last option users can overwrite the configs by
// providing the configs file in JSON format in the specified structure on the
// existing configs under these dot files
// ...
// ...
// Here is the hierarchy of the config files
// 1) config file provided by the user through command line as option --config
// 2) config file provided by the user through the default system service
//    location 
// 3) default config file created at initial running phase under system
//    file locations
//


// NOTE temporarly hardocoding the configurations here to see if the app
//      successfully runs, this will be replaced by the config file
//      parsing logic later on

#define DEFAULT_NODE_ROOT "/usr/local/pot"
#define DEFAULT_CONFIG_DIR "conf/pot.conf"

typedef struct {
  char *role;
  int rx_port_id;
  int tx_port_id;
  char *config_file_path;
} app_config;

app_config *parse_json_config(const char *file_path) {}
app_config *load_application_config(const char *config_path_cli) {}