#include "pprocess.h"
#include "common.h"

// Function to add a custom header to the packet
static inline enum role determine_role(uint16_t rx_port_id, uint16_t tx_port_id) {
  if (rx_port_id == tx_port_id)
    return ROLE_TRANSIT;
  else if (rx_port_id < tx_port_id)
    return ROLE_INGRESS;
  else
    return ROLE_EGRESS;
}

// Helper: process a single packet for ingress
static inline void process_ingress_packet(struct rte_mbuf *mbuf) {
  struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
  uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
  switch (ether_type) {
    case RTE_ETHER_TYPE_IPV4:
      switch (operation_bypass_bit) {
        case 0: add_custom_header4(mbuf); break;
        case 1:
          // Bypass all operations
          break;
        case 2: add_custom_header4_only(mbuf); break;
        default: break;
      }
      break;
    default: break;
  }
}

static inline void process_ingress(struct rte_mbuf **pkts, uint16_t nb_rx) {
  for (uint16_t i = 0; i < nb_rx; i++) {
    process_ingress_packet(pkts[i]);
  }
}

// Helper: process a single packet for transit
static inline void process_transit_packet(struct rte_mbuf *mbuf) {
  struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
  uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
  switch (ether_type) {
    case RTE_ETHER_TYPE_IPV4:
      switch (operation_bypass_bit) {
        case 0:
          process_ip4(mbuf, 1, eth_hdr, 0);  // 1 as nb_rx, 0 as index placeholder
          break;
        case 1:
          // Bypass all operations
          break;
        case 2: remove_headers_only(mbuf); break;
        default: break;
      }
      break;
    default: break;
  }
}

static inline void process_transit(struct rte_mbuf **pkts, uint16_t nb_rx) {
  for (uint16_t i = 0; i < nb_rx; i++) {
    process_transit_packet(pkts[i]);
  }
}

// Helper: process a single packet for egress
static inline void process_egress_packet(struct rte_mbuf *mbuf) {
  struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
  uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
  switch (ether_type) {
    case RTE_ETHER_TYPE_IPV4:
      switch (operation_bypass_bit) {
        case 0: remove_headers(mbuf); break;
        case 1:
          // Bypass all operations
          break;
        case 2: remove_headers_only(mbuf); break;
        default: break;
      }
      break;
    default: break;
  }
}

static inline void process_egress(struct rte_mbuf **pkts, uint16_t nb_rx) {
  for (uint16_t i = 0; i < nb_rx; i++) {
    process_egress_packet(pkts[i]);
  }
}

void lcore_main_forward(void *arg) {
  // Parse arguments (ports) from input.
  uint16_t *ports = (uint16_t *)arg;
  uint16_t rx_port_id = ports[0];
  // uint16_t tx_port_id = ports[1];

  // Main processing loop.
  while (1) {
    struct rte_mbuf *pkts[BURST_SIZE];
    uint16_t nb_rx = rte_eth_rx_burst(rx_port_id, 0, pkts, BURST_SIZE);

    if (nb_rx == 0) continue;
    printf("Received %u packets on port %u\n", nb_rx, rx_port_id); 

    // enum role cur_role = determine_role(rx_port_id, tx_port_id);

    // Route packet batch to the appropriate processing logic.
    // switch (cur_role) {
    //   case ROLE_INGRESS: process_ingress(pkts, nb_rx); break;
    //   case ROLE_TRANSIT: process_transit(pkts, nb_rx); break;
    //   case ROLE_EGRESS: process_egress(pkts, nb_rx); break;
    //   default: break;
    // }

    // Send processed packets out.
    // uint16_t nb_tx = rte_eth_tx_burst(tx_port_id, 0, pkts, nb_rx);

    // Free any unsent packets.
    // if (nb_tx < nb_rx) {
    //   uint16_t i;
    //   for (i = nb_tx; i < nb_rx; i++) rte_pktmbuf_free(pkts[i]);
    // }
  }
}