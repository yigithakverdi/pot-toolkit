#ifndef LOGGING_H
#define LOGGING_H

#include <rte_common.h>
#include <rte_log.h>

// Log types
extern int dpdk_pot_logtype_main;
extern int dpdk_pot_logtype_data;
extern int dpdk_pot_logtype_control;
extern int dpdk_pot_logtype_security;
extern int g_logging_enabled;

void print_system_info();

// Get the path of the last created log file
const char* get_log_file_path(void);

#define LOG_MAIN(level, fmt, ...) \
  do { \
    if (g_logging_enabled) { \
      rte_log(RTE_LOG_##level, dpdk_pot_logtype_main, "%s: " fmt, __func__, ##__VA_ARGS__); \
    } \
  } while (0)

#define LOG_DP(level, fmt, args...) \
  rte_log(RTE_LOG_##level, dpdk_pot_logtype_data, "%s: " fmt, __func__, ##args)

#define LOG_CONTROL(level, fmt, args...) \
  rte_log(RTE_LOG_##level, dpdk_pot_logtype_control, "%s: " fmt, __func__, ##args)

#define LOG_CRYPTO(level, fmt, args...) \
  rte_log(RTE_LOG_##level, dpdk_pot_logtype_security, "%s: " fmt, __func__, ##args)

#endif  // LOGGING_H