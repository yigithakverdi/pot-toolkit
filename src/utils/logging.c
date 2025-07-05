#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

int init_logging(const char *log_dir, const char *component_name, int log_level) {
  struct stat st = {0};
  if (stat(log_dir, &st) == -1) {
    if (mkdir(log_dir, 0700) != 0) {
      perror("Failed to create log directory");
      return -1;
    }
  }

  time_t t = time(NULL);
  struct tm tm = *localtime(&t);

  //TODO Rest of the logging initialization will be implemented here
  // ...

}