#ifndef ROLE_H
#define ROLE_H

// Defines the possible application roles that determine packet processing behavior.
// The global_role variable (declared as extern here and defined elsewhere)
// is set during initialization based on command-line arguments.
// This role setting affects packet processing logic throughout the application.
extern enum role global_role;
enum role {
  ROLE_UNDEFINED = 0,  // Undefined role, used for error handling
  ROLE_INGRESS,        // Client role, typically sends packets
  ROLE_EGRESS,         // Server role, typically receives packets
  ROLE_TRANSIT         // Proxy role, forwards packets between client and server
};

// Function that will setup the node role, it will additionally set up the environment variables
// and global_role.
enum role setup_node_role(const char *role_str);

// To obtain the role name as string
const char *get_role_name(enum role role);

#endif ROLE_H