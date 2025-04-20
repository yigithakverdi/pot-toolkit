// Main config logic will be handled in an order way, the program will look at the default
// system service location for default configurations, that are generated in the initial 
// running phase, if the user have defined separate custom config files under /home/user/
// under the .pot directory respecting the basic system service structure defined under
// docs then the program will use those configs, in the last option users can 
// overwrite the configs by providing the configs file in JSON format in the specified
// structure on the existing configs under these dot files
// ...
// ...
// Here is the hierarchy of the config files
// 1) config file provided by the user through command line as option --config
// 2) config file provided by the user through the default system service location
// 3) default config file created at initial running phase under system file locations
//
//

#define DEFAULT_SYSTEM_CONFIG_PATH "/etc/pot/node_config.json"
#define ENV_VAR_NAME "POT_CONFIG_PATH"
#define DEFAULT_CONFIG_PATH "/home/user/.pot/node_config.json"

#include "deps/cjson/cjson.h"

typedef struct {
    char* role;
    int rx_port_id;
    int tx_port_id;
    char* config_file_path;
} app_config;

app_config* parse_json_config(const char* file_path) {

}