#include "common.h"

int main(int argc, char *argv[]) {

  const char *role = "ingress";
  
  init_eal(argc, argv);
  check_ports_available();
  struct rte_mempool *mbuf_pool = create_mempool();
  register_tsc_dynfield();

  //   uint16_t port_id = 0, tx_port_id = 1;
  //   setup_port(port_id, mbuf_pool, 1);     // RX
  //   setup_port(tx_port_id, mbuf_pool, 0);  // TX
  //   printf("TSC frequency: %" PRIu64 " Hz\n", rte_get_tsc_hz());
  //   uint16_t ports[2] = {port_id, tx_port_id};
  //   launch_lcore_forwarding(ports);

  return 0;
}