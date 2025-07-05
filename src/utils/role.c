#include "utils/role.h"

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

// Default value of the global_role since it is defined as `extern` it expects a definition
// somwehere in the code.
enum role global_role = ROLE_UNDEFINED;

enum role setup_node_role(const char *role_str) {
  if (strcmp(role_str, "ingress") == 0) {
    global_role = ROLE_INGRESS;
  } else if (strcmp(role_str, "egress") == 0) {
    global_role = ROLE_EGRESS;
  } else if (strcmp(role_str, "transit") == 0) {
    global_role = ROLE_TRANSIT;
  } else {
    global_role = ROLE_UNDEFINED;
  }
  return global_role;
}

const char *get_role_name(enum role r) {
  switch (r) {
    case ROLE_INGRESS: return "INGRESS";
    case ROLE_TRANSIT: return "TRANSIT";
    case ROLE_EGRESS: return "EGRESS";
    default: return "UNKNOWN";
  }
}