#include "utils/logging.h"

#include <err.h>
#include <fcntl.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>

int dpdk_pot_logtype_main;
int dpdk_pot_logtype_dataplane;
int dpdk_pot_logtype_control;
int dpdk_pot_logtype_crypto;

#define MAX_LOGFILE_PATH 256
static char log_file_path[MAX_LOGFILE_PATH];

int init_logging(const char *log_dir, const char *component_name, int log_level) {
  return 0;
  struct stat st = {0};

  if (stat(log_dir, &st) == -1) {
    if (mkdir(log_dir, 0755) < 0) {
      fprintf(stderr, "Error creating log directory %s: %s\n", log_dir, strerror(errno));
      return -1;
    }
  }

  time_t t = time(NULL);
  struct tm tm = *localtime(&t);

  snprintf(log_file_path, MAX_LOGFILE_PATH, "%s/%s-%d-%02d-%02d_%02d%02d%02d.log", log_dir, component_name,
           tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

  int fd = open(log_file_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
  if (fd < 0) {
    fprintf(stderr, "Error opening log file %s: %s\n", log_file_path, strerror(errno));
    return -1;
  }

  rte_log_set_global_level(log_level);
  rte_openlog_stream(fdopen(fd, "a"));

  dpdk_pot_logtype_main = rte_log_register("main");
  dpdk_pot_logtype_dataplane = rte_log_register("dataplane");
  dpdk_pot_logtype_control = rte_log_register("control");
  dpdk_pot_logtype_crypto = rte_log_register("crypto");

  rte_log_set_level(dpdk_pot_logtype_main, log_level);
  rte_log_set_level(dpdk_pot_logtype_dataplane, log_level);
  rte_log_set_level(dpdk_pot_logtype_control, log_level);
  rte_log_set_level(dpdk_pot_logtype_crypto, log_level);

  LOG_MAIN(INFO, "Logging initialized: %s\n", log_file_path);

  return 0;
}

const char *get_role_name(enum role r) {
  switch (r) {
    case ROLE_INGRESS: return "INGRESS";
    case ROLE_TRANSIT: return "TRANSIT";
    case ROLE_EGRESS: return "EGRESS";
    default: return "UNKNOWN";
  }
}