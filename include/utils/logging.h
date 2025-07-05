#ifndef LOGGING_H
#define LOGGING_H

#include <rte_common.h>
#include <rte_log.h>

// Log types
extern int dpdk_pot_logtype_main;
extern int dpdk_pot_logtype_data;
extern int dpdk_pot_logtype_control;
extern int dpdk_pot_logtype_security;

int init_logging(const char *log_dir, const char *component_name, int log_level);

#define LOG_MAIN(level, fmt, args...) \
  rte_log(RTE_LOG_##level, dpdk_pot_logtype_main, "%s: " fmt, __func__, ##args)

#define LOG_DP(level, fmt, args...) \
  rte_log(RTE_LOG_##level, dpdk_pot_logtype_data, "%s: " fmt, __func__, ##args)

#define LOG_CONTROL(level, fmt, args...) \
  rte_log(RTE_LOG_##level, dpdk_pot_logtype_control, "%s: " fmt, __func__, ##args)

#define LOG_CRYPTO(level, fmt, args...) \
  rte_log(RTE_LOG_##level, dpdk_pot_logtype_security, "%s: " fmt, __func__, ##args)

#endif  // LOGGING_H