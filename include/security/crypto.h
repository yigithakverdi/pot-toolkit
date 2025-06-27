#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>
#include <openssl/rand.h>  // Add this for RAND_bytes
#include <string.h>
#include <ctype.h>

#include "utils/common.h"
// HMAC calculation
int calculate_hmac(uint8_t *src_addr, const struct ipv6_srh *srh, const struct hmac_tlv *hmac_tlv,
                   uint8_t *key, size_t key_len, uint8_t *hmac_out);

int generate_nonce(uint8_t nonce[NONCE_LENGTH]);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv,
            unsigned char *plaintext);
void encrypt_pvf(uint8_t k_pot_in[SID_NO][HMAC_MAX_LENGTH], uint8_t *nonce, uint8_t hmac_out[32]);
int decrypt_pvf(uint8_t k_pot_in[SID_NO][HMAC_MAX_LENGTH], uint8_t *nonce, uint8_t pvf_out[32]);

/**
 * Reads an encryption key corresponding to a given IPv6 address from a key-value store file.
 *
 * @param file_path  Path to the key-value store file.
 * @param ipv6_addr  IPv6 address (in string format) used as the key in the store.
 * @param key_out    Buffer to store the retrieved encryption key.
 * @param key_out_len Length of the key_out buffer.
 *
 * @return 0 on success, non-zero on error.
 */
int read_encryption_key(const char *file_path, const char *ipv6_addr, uint8_t *key_out, size_t key_out_len);

#endif  // CRYPTO_H