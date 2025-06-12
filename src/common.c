#include "common.h"

#include <rte_log.h>

#include "pprocess.h"

int operation_bypass_bit = 0;
int tsc_dynfield_offset = -1;

// Prints a human-readable IPv4 address with a label for context, converting the given 32-bit
// address to dotted-decimal notation and displaying it alongside the provided label; if the conversion
// fails, an error message is printed.
void print_ipv4_address(uint32_t ipv4_addr, const char *label) {
  struct in_addr addr;
  addr.s_addr = ipv4_addr;
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &addr, buf, sizeof(buf)) != NULL) {
    RTE_LOG(INFO, USER1, "%s: %s\n", label, buf);
  } else {
    RTE_LOG(ERR, USER1, "inet_ntop failed: %s\n", strerror(errno));
  }
}

static void hex_dump(const void *data, size_t size) {
  const unsigned char *p = data;
  for (size_t i = 0; i < size; i++) {
    printf("%02x ", p[i]);
    if ((i + 1) % 16 == 0) printf("\n");
  }
  if (size % 16 != 0) printf("\n");
}

void send_packet_to(struct rte_ether_addr mac_addr, struct rte_mbuf *mbuf, uint16_t tx_port_id) {
  struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

  if (rte_is_broadcast_ether_addr(&eth_hdr->dst_addr) != 1) {
    rte_ether_addr_copy(&eth_hdr->dst_addr, &eth_hdr->src_addr);
    rte_ether_addr_copy(&mac_addr, &eth_hdr->dst_addr);
  }

  if (rte_eth_tx_burst(tx_port_id, 0, &mbuf, 1) == 0) {
    RTE_LOG(ERR, USER1, "Error sending packet\n");
    rte_pktmbuf_free(mbuf);
  } else {
    RTE_LOG(INFO, USER1, "IPV6 packet sent to: %02X:%02X:%02X:%02X:%02X:%02X\n",
            eth_hdr->dst_addr.addr_bytes[0], eth_hdr->dst_addr.addr_bytes[1], eth_hdr->dst_addr.addr_bytes[2],
            eth_hdr->dst_addr.addr_bytes[3], eth_hdr->dst_addr.addr_bytes[4],
            eth_hdr->dst_addr.addr_bytes[5]);
  }
  rte_pktmbuf_free(mbuf);
}

// DPDK mbufs are used to represent network packets. Sometimes, you need to attach extra
// information to each packet (for example, a timestamp counter, which tsc_t likely
// represents).
//
// Rather than modifying the mbuf structure globally (which is not recommended), DPDK
// allows you to register dynamic fields at runtime. This is safer and more flexible.
//
// Here in this case the dynamic field is used to store a timestamp counter (tsc_t) for
// each packet.
void register_tsc_dynfield() {
  static const struct rte_mbuf_dynfield tsc_dynfield_desc = {
      .name = "dpdk_pot_dynfield_tsc",
      .size = sizeof(tsc_t),
      .align = alignof(tsc_t),
  };
  tsc_dynfield_offset = rte_mbuf_dynfield_register(&tsc_dynfield_desc);
  if (tsc_dynfield_offset < 0) rte_exit(EXIT_FAILURE, "Cannot register mbuf field\n");
}

// The `init_eal` function initializes the DPDK Environment Abstraction Layer (EAL).
// It is responsible for setting up the DPDK environment, including memory management,
// device management, and other low-level operations required for DPDK applications.
//
// Here the functions takes the command line arguments `argc` and `argv` to configure the EAL
// it simply calls the `rte_eal_init` function, which is part of the DPDK library
// if the initialization fails, it exits the program with an error message
void init_eal(int argc, char *argv[]) {
  int ret = rte_eal_init(argc, argv);
  if (ret < 0) rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
}

// Creates a DPDK memory pool (mbuf pool) for packet buffers. The pool is sized
// based on the number of available Ethernet devices and NUM_MBUFS. If the pool
// cannot be created, the function exits the program with an error. Returns a
// pointer to the created mempool.
struct rte_mempool *create_mempool() {
  struct rte_mempool *mbuf_pool =
      rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * rte_eth_dev_count_avail(), MBUF_CACHE_SIZE, 0,
                              RTE_MBUF_DEFAULT_BUF_SIZE + EXTRA_SPACE, rte_socket_id());
  if (mbuf_pool == NULL) rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
  return mbuf_pool;
}