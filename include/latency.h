#ifndef LATENCY_H
#define LATENCY_H

#include "common.h"
#include <rte_mbuf.h>
#include <stdint.h>

typedef uint64_t tsc_t;

extern int tsc_dynfield_offset;
static inline tsc_t *tsc_field(struct rte_mbuf *mbuf) {
  return RTE_MBUF_DYNFIELD(mbuf, tsc_dynfield_offset, tsc_t *);
}

uint16_t add_timestamps(uint16_t port, uint16_t qidx, struct rte_mbuf **pkts, uint16_t nb_pkts,
                        uint16_t max_pkts, void *user_param);

uint16_t calc_latency(uint16_t port, uint16_t qidx, struct rte_mbuf **pkts, uint16_t nb_pkts,
                      void *user_param);

struct latency_numbers_t {
    uint64_t total_cycles;
    uint64_t total_queue_cycles;
    uint64_t total_pkts;
};

extern struct latency_numbers_t latency_numbers;

#endif  // LATENCY_H