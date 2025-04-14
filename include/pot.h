#include <stdint.h>

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