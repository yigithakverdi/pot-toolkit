#include <stdint.h>
#include <rte_ethdev.h>

#include "packet_utils.h"
#include "dpdk_utils.h"
#include "crypto_utils.h"

#define SID_NO 2

struct pot_tlv
{
    uint8_t type;               // Type field (1 byte)
    uint8_t length;             // Length field (1 byte)
    uint8_t reserved;           // Reserved field (1 byte)
    uint8_t nonce_length;       // Nonce Length field (1 byte)
    uint32_t key_set_id;        // Key Set ID (4 bytes)
    uint8_t nonce[16];          // Nonce (variable length)
    uint8_t encrypted_hmac[32]; // Encrypted HMAC (variable length)
};

// Initialize a port
static int port_init(uint16_t port, struct rte_mempool *mbuf_pool);
int decrypt_pvf(uint8_t *k_pot_in, uint8_t *nonce, uint8_t pvf_out[32]);
void encrypt_pvf(uint8_t k_pot_in[SID_NO][HMAC_MAX_LENGTH], uint8_t *nonce, uint8_t hmac_out[32]);