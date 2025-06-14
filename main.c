#include <sys/types.h>

#include "common.h"
#include "port.h"
#include "pprocess.h"

int main(int argc, char *argv[]) {

  printf("Initializing next-hop table at startup\n");
  add_next_hop("2001:db8:0:1::2", "02:0c:b4:7a:8c:6d");
  add_next_hop("2001:db8:0:2::2", "02:0c:b4:7a:8c:6e");

  const char *role = "ingress";

  init_eal(argc, argv);
  check_ports_available();
  struct rte_mempool *mbuf_pool = create_mempool();
  register_tsc_dynfield();

  uint16_t port_id = 0;
  // uint16_t tx_port_id = 1;

  setup_port(port_id, mbuf_pool, 1);
  // setup_port(tx_port_id, mbuf_pool, 0);  // TX
  printf("TSC frequency: %" PRIu64 " Hz\n", rte_get_tsc_hz());

  // uint16_t ports[2] = {port_id, tx_port_id};
  uint16_t ports[1] = {port_id};
  printf("Starting %s role on port %u\n", role, port_id);

  launch_lcore_forwarding(ports);

  return 0;
}