#include <stdint.h>
#include <rte_ethdev.h>

#define HMAC_MAX_LENGTH 32

int calculate_hmac(uint8_t *src_addr,               // Source IPv6 address (16 bytes)
                   const struct ipv6_srh *srh,      // Pointer to the IPv6 Segment Routing Header (SRH)
                   const struct hmac_tlv *hmac_tlv, // Pointer to the HMAC TLV
                   uint8_t *key,                    // Pre-shared key
                   size_t key_len,                  // Length of the pre-shared key
                   uint8_t *hmac_out);              // Output buffer for the HMAC (32 bytes)

                
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);