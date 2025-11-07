#include "utils/utils.h"
#include "headers.h"
#include "utils/role.h"

#include <stdlib.h>

#include "utils/config.h"
#include "node/controller.h"
#include "utils/logging.h"

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
      {"follow", no_argument, 0, 'F'}, // --follow, shorthand -F
      {"type", required_argument, 0, 't'},
      {"log-level", required_argument, 0, 'l'},
      {"log-file", required_argument, 0, 'f'},
      {"segment-list", required_argument, 0, 's'},
      {"key-locations", required_argument, 0, 'k'},
      {"num-transit", required_argument, 0, 'n'},
      {"node-index", required_argument, 0, 'i'},
      {"cipher-type", required_argument, 0, 'c'},
      {"no-logging", no_argument, 0, 1},
      {"help", no_argument, 0, 'h'},
      {"virtual-machine", no_argument, 0, 'v'},
      {"simple-forward", no_argument, 0, 'sf'},
      {0, 0, 0, 0} // Dizi sonunu belirtir
  };

  int opt_index = 0;
  int c;

  // Kısa opsiyon string'i
  const char* short_options = "t:l:f:s:k:n:i:c:hFv"; // added c for --cipher-type

  while ((c = getopt_long(argc, argv, short_options, long_options, &opt_index)) != -1) {
    switch (c) {
    case 'F': // --follow
      config->follow_flag = 1;
      break;
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

    case 'v': // --virtual-machine veya -v
      config->virtual_machine = 1;
      g_is_virtual_machine = 1;
      break;

    case 'sf': // --virtual-machine veya -v
      config->simple_forward = 1;
      g_simple_forward = 1;
      break;      

    case 1: // --no-logging
      g_logging_enabled = 0;
      break;

    case 'i': // --node-index veya -i
      g_node_index = atoi(optarg);
      if (g_node_index < 0) {
        fprintf(stderr, "Invalid node index: %s\n", optarg);
        exit(EXIT_FAILURE);
      }
      break;

    case 'n': // --num-transit veya -n
      config->topology.num_transit = atoi(optarg);
      break;

    case 'c': // --cipher-type veya -c
      {
        int cipher_val = atoi(optarg);
        if (cipher_val < 0 || cipher_val > 3) {
          fprintf(stderr, "Invalid cipher type: %s (valid range: 0-3)\n", optarg);
          fprintf(stderr, "  0: DES (8 bytes) - INSECURE\n");
          fprintf(stderr, "  1: AES-128-CTR (16 bytes)\n");
          fprintf(stderr, "  2: AES-256-CTR (32 bytes)\n");
          fprintf(stderr, "  3: ChaCha20 (32 bytes)\n");
          exit(EXIT_FAILURE);
        }
        config->cipher_type = (cipher_type_t)cipher_val;
      }
      break;

    case 'h': // --help veya -h
      printf("Usage: %s [options]\n\n", argv[0]);
      printf("Node Options:\n");
      printf("  -t, --type <type>             Set the node type (e.g., 'transit', 'edge').\n");
      printf("  -l, --log-level <level>         Set the log level (e.g., 'debug', 'info').\n");
      printf("  -f, --log-file <path>           Specify a log file path.\n");
      printf("  -i, --node-index <index>        Set the node index.\n\n");
      printf("Topology Options:\n");
      printf("  -s, --segment-list <path>     Specify the segment list file.\n");
      printf("  -k, --key-locations <path>    Specify the key locations file.\n");
      printf("  -n, --num-transit <number>    Set the number of transit nodes.\n\n");
      printf("Encryption Options:\n");
      printf("  -c, --cipher-type <0-3>       Set encryption cipher type:\n");
      printf("                                  0: DES (8 bytes) - INSECURE, benchmark only\n");
      printf("                                  1: AES-128-CTR (16 bytes)\n");
      printf("                                  2: AES-256-CTR (32 bytes) [default]\n");
      printf("                                  3: ChaCha20 (32 bytes)\n\n");
      printf("Other Options:\n");
      printf("  -F, --follow                    Follow log output.\n");
      printf("  -v, --virtual-machine           Running in virtual machine mode.\n");
      printf("      --simple-forward            Enable simple forwarding.\n");
      printf("      --no-logging                Disable logging.\n");
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

#define LATENCY_BATCH_SIZE 1000
static double latency_buffer[LATENCY_BATCH_SIZE];
static int latency_buffer_index = 0;

uint16_t calc_latency(uint16_t port, uint16_t qidx __rte_unused, struct rte_mbuf** pkts, uint16_t nb_pkts,
                      void* _ __rte_unused) {

  LOG_MAIN(DEBUG, "Transit packet is IPv6, processing headers.\n");                        
  uint64_t cycles = 0;
  uint64_t now = rte_rdtsc();
  unsigned i;

  for (i = 0; i < nb_pkts; i++) {
    cycles += now - *tsc_field(pkts[i]);
  }

  latency_numbers.total_cycles += cycles;
  latency_numbers.total_pkts += nb_pkts;

  if (latency_numbers.total_pkts > 0) {
    double latency_us = (double)latency_numbers.total_cycles / rte_get_tsc_hz() * 1e6;
    // Buffer the average latency
    latency_buffer[latency_buffer_index++] = latency_us / latency_numbers.total_pkts;
    // Reset counters
    latency_numbers.total_cycles = 0;
    latency_numbers.total_queue_cycles = 0;
    latency_numbers.total_pkts = 0;
    // Write to file in batches
    if (latency_buffer_index >= LATENCY_BATCH_SIZE) {
      char log_path[128];
      snprintf(log_path, sizeof(log_path), "/tmp/latency_%s-%d.log", get_role_name(global_role), g_node_index);
      FILE *f = fopen(log_path, "a");
      if (f) {
        for (int j = 0; j < LATENCY_BATCH_SIZE; ++j) {
          fprintf(f, "%.3f\n", latency_buffer[j]);
        }
        fclose(f);
      }
      latency_buffer_index = 0;
    }
  }

  return nb_pkts;
}