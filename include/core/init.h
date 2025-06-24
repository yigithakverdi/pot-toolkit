#ifndef INIT_H
#define INIT_H

#include "core/init.h"

#include <rte_mbuf_core.h>
#include <rte_mbuf_dyn.h>
#include <stdlib.h>
#include <rte_eal.h>         // For rte_eal_init
#include <rte_mempool.h>     // For rte_pktmbuf_pool_create
#include <rte_ethdev.h>      // For rte_eth_dev_count_avail

#include "utils/common.h"
#include "latency.h"         // For tsc_t type

struct rte_mempool *create_mempool();
void init_eal(int argc, char *argv[]);
void register_tsc_dynfield();

#endif // INIT_H