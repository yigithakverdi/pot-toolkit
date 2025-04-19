#include "include/pot/pot.h"

// Initialize a port
static int port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
  struct rte_eth_conf port_conf = {0};
  const uint16_t rx_rings = 1, tx_rings = 1;
  int retval;
  uint16_t q;

  // Configure the Ethernet device
  retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
  if (retval != 0)
    return retval;

  // Allocate and set up RX queues
  for (q = 0; q < rx_rings; q++) {
    retval = rte_eth_rx_queue_setup(
        port, q, RX_RING_SIZE, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
    if (retval < 0)
      return retval;
  }

  // Allocate and set up TX queues
  for (q = 0; q < tx_rings; q++) {
    retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
                                    rte_eth_dev_socket_id(port), NULL);
    if (retval < 0)
      return retval;
  }

  // Start the Ethernet port
  retval = rte_eth_dev_start(port);
  if (retval < 0)
    return retval;

  // Enable RX in promiscuous mode for the port
  rte_eth_promiscuous_enable(port);

  return 0;
}

int decrypt_pvf(uint8_t *k_pot_in, uint8_t *nonce, uint8_t pvf_out[32]) {
  // k_pot_in is a 2d array of strings holding statically allocated keys for the
  // nodes. In this proof of concept there is only one middle node and an egress
  // node so the shape is [2][key-length]
  uint8_t plaintext[128];
  int cipher_len = 32;
  printf("\n----------Decrypting----------\n");
  int dec_len = decrypt(pvf_out, cipher_len, k_pot_in, nonce, plaintext);
  printf("Dec len %d\n", dec_len);
  printf("original text is:\n");
  for (int j = 0; j < 32; j++) {
    printf("%02x", pvf_out[j]);
  }
  printf("\n");
  memcpy(pvf_out, plaintext, 32);
  printf("Decrypted text is : \n");
  BIO_dump_fp(stdout, (const char *)pvf_out, dec_len);
}