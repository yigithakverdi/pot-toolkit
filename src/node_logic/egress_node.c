#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_mempool.h>
#include <rte_ethdev.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

struct rte_mempool *MBUF_POOL;
uint16_t PORT_ID = 0;
uint16_t TX_PORT_ID = 1;


int run() {
    printf("Egress node running on lcore %u\n", rte_lcore_id());

    while(1) {
        printf("Egress node processing packets on port %u\n", PORT_ID);        
        sleep(1); // Here is the main node logic
    }
    
    return 0;
}
