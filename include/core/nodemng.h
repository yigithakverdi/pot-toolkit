#ifndef NODEMNG_H
#define NODEMNG_H

#include <stdint.h>

extern enum role global_role;
enum role {
  ROLE_INGRESS,
  ROLE_TRANSIT,
  ROLE_EGRESS,
};

#endif  // NODEMNG_H