#ifndef LOGGING_H
#define LOGGING_H

#include <rte_common.h>
#include <rte_log.h>

#include "core/nodemng.h"

// Log types
extern int dpdk_pot_logtype_main;
extern int dpdk_pot_logtype_dataplane;
extern int dpdk_pot_logtype_control;
extern int dpdk_pot_logtype_crypto;

// Initialize logging system
int init_logging(const char *log_dir, const char *component_name, int log_level);

// Get role name as string
const char *get_role_name(enum role r);

// Macros for logging - Replace these definitions
#define LOG_MAIN(level, fmt, args...) \
    rte_log(RTE_LOG_##level, dpdk_pot_logtype_main, "%s: " fmt, __func__, ##args)

#define LOG_DP(level, fmt, args...) \
    rte_log(RTE_LOG_##level, dpdk_pot_logtype_dataplane, "%s: " fmt, __func__, ##args)

#define LOG_CONTROL(level, fmt, args...) \
    rte_log(RTE_LOG_##level, dpdk_pot_logtype_control, "%s: " fmt, __func__, ##args)

#define LOG_CRYPTO(level, fmt, args...) \
    rte_log(RTE_LOG_##level, dpdk_pot_logtype_crypto, "%s: " fmt, __func__, ##args)

// Remove this duplicate definition
// #define LOG_MAIN(level, fmt, args...) RTE_LOG(level, main, "%s: " fmt, __func__, ##args)

// Performance-sensitive logging - also update this
#define PERF_LOG_DP(level, fmt, args...)                        \
  do {                                                          \
    if (rte_log_get_level(dpdk_pot_logtype_dataplane) >= RTE_LOG_##level) \
      rte_log(RTE_LOG_##level, dpdk_pot_logtype_dataplane, "%s: " fmt, __func__, ##args);  \
  } while (0)
#endif  // LOGGING_H