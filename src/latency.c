#include <include/latency.h>

static uint16_t add_timestamps(uint16_t port __rte_unused, uint16_t qidx __rte_unused, struct rte_mbuf **pkts,
                               uint16_t nb_pkts, uint16_t max_pkts __rte_unused, void *_ __rte_unused) {
  unsigned i;
  uint64_t now = rte_rdtsc();

  for (i = 0; i < nb_pkts; i++) *tsc_field(pkts[i]) = now;
  return nb_pkts;
}

static uint16_t calc_latency(uint16_t port, uint16_t qidx __rte_unused, struct rte_mbuf **pkts,
                             uint16_t nb_pkts, void *_ __rte_unused) {
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

  printf("Latency = %" PRIu64 " cycles\n", latency_numbers.total_cycles / latency_numbers.total_pkts);

  printf("number of packets: %" PRIu64 "\n", latency_numbers.total_pkts);

  double latency_us =
      (double)latency_numbers.total_cycles / rte_get_tsc_hz() * 1e6;  // Convert to microseconds

  printf("Latency: %.3f µs\n", latency_us);

  latency_numbers.total_cycles = 0;
  latency_numbers.total_queue_cycles = 0;
  latency_numbers.total_pkts = 0;

  return nb_pkts;
}