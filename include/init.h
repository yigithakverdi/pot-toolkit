#ifndef INIT_H
#define INIT_H

#include "port.h"
#include "utils/config.h"
#include "utils/logging.h"
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define EXTRA_SPACE 128

void init_eal(int argc, char* argv[]);
void init_ports(uint16_t port_id, struct rte_mempool* mbuf_pool, PortRole role);
int init_logging(const char* log_dir, const char* component_name, int log_level);
struct rte_mempool* init_mempool();
int init_topology();
void register_tsc_dynfield();

#endif // INIT_H