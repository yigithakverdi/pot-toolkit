#include "utils/role.h"

enum role setup_node_role(const char *role_str) {
    if(strcmp(role_str, "client") == 0) {
        global_role = ROLE_CLIENT;
    } else if(strcmp(role_str, "server") == 0) {
        global_role = ROLE_SERVER;
    } else if(strcmp(role_str, "proxy") == 0) {
        global_role = ROLE_PROXY;
    } else {
        global_role = ROLE_UNDEFINED; 
    }
    return global_role;
}