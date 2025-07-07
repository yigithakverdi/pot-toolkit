#include "utils/utils.h"
#include "headers.h"

#include <stdlib.h>

#include "utils/config.h"
#include "utils/logging.h"
#include "utils/role.h"

int tsc_dynfield_offset = 0;

int getenv_int(const char* name) {
  const char* val = getenv(name);
  if (val == NULL) {
    return 0; // Default value if not set
  }

  char* endptr;
  long result = strtol(val, &endptr, 10);

  if (*endptr != '\0' || endptr == val) {
    // Conversion error or empty string
    return 0; // Default value if invalid
  }

  return (int)result;
}

void parse_args(AppConfig* config, int argc, char* argv[]) {
  static struct option long_options[] = {
      // name              has_arg            flag  val
      {"type", required_argument, 0, 't'},
      {"log-level", required_argument, 0, 'l'},
      {"log-file", required_argument, 0, 'f'},
      {"segment-list", required_argument, 0, 's'},
      {"key-locations", required_argument, 0, 'k'},
      {"num-transit", required_argument, 0, 'n'},
      {"help", no_argument, 0, 'h'},
      {0, 0, 0, 0} // Dizi sonunu belirtir
  };

  int opt_index = 0;
  int c;

  // Kısa opsiyon string'i
  const char* short_options = "t:l:f:s:k:n:h";

  while ((c = getopt_long(argc, argv, short_options, long_options, &opt_index)) != -1) {
    switch (c) {
    case 't': // --type veya -t
      free(config->node.type);
      config->node.type = strdup(optarg);
      break;

    case 'l': // --log-level veya -l
      free(config->node.log_level);
      config->node.log_level = strdup(optarg);
      break;

    case 'f': // --log-file veya -f
      free(config->node.log_file);
      config->node.log_file = strdup(optarg);
      break;

    case 's': // --segment-list veya -s
      free(config->topology.segment_list);
      config->topology.segment_list = strdup(optarg);
      break;

    case 'k': // --key-locations veya -k
      free(config->topology.key_locations);
      config->topology.key_locations = strdup(optarg);
      break;

    case 'n': // --num-transit veya -n
      config->topology.num_transit = atoi(optarg);
      break;

    case 'h': // --help veya -h
      printf("Usage: %s [options]\n\n", argv[0]);
      printf("Node Options:\n");
      printf("  -t, --type <type>             Set the node type (e.g., 'transit', 'edge').\n");
      printf("  -l, --log-level <level>         Set the log level (e.g., 'debug', 'info').\n");
      printf("  -f, --log-file <path>           Specify a log file path.\n\n");
      printf("Topology Options:\n");
      printf("  -s, --segment-list <path>     Specify the segment list file.\n");
      printf("  -k, --key-locations <path>    Specify the key locations file.\n");
      printf("  -n, --num-transit <number>    Set the number of transit nodes.\n\n");
      printf("Other Options:\n");
      printf("  -h, --help                      Show this help message.\n");
      exit(EXIT_SUCCESS);
      break;

    case '?': // Bilinmeyen opsiyon veya eksik argüman
      fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
      exit(EXIT_FAILURE);
      break;

    default: abort();
    }
  }
}

uint16_t add_timestamps(uint16_t port __rte_unused, uint16_t qidx __rte_unused, struct rte_mbuf** pkts,
                        uint16_t nb_pkts, uint16_t max_pkts __rte_unused, void* _ __rte_unused) {
  unsigned i;
  uint64_t now = rte_rdtsc();

  for (i = 0; i < nb_pkts; i++) *tsc_field(pkts[i]) = now;
  return nb_pkts;
}

struct latency_numbers_t latency_numbers = {0, 0, 0};
uint16_t calc_latency(uint16_t port, uint16_t qidx __rte_unused, struct rte_mbuf** pkts, uint16_t nb_pkts,
                      void* _ __rte_unused) {
  uint64_t cycles = 0;
  uint64_t queue_ticks = 0;
  uint64_t now = rte_rdtsc();
  uint64_t ticks;
  unsigned i;

  for (i = 0; i < nb_pkts; i++) {
    cycles += now - *tsc_field(pkts[i]);
  }

  latency_numbers.total_cycles += cycles;
  latency_numbers.total_pkts += nb_pkts;

  double latency_us = (double)latency_numbers.total_cycles / rte_get_tsc_hz() * 1e6;
  latency_numbers.total_cycles = 0;
  latency_numbers.total_queue_cycles = 0;
  latency_numbers.total_pkts = 0;

  return nb_pkts;
}