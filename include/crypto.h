#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include "common.h"

// HMAC calculation
int calculate_hmac(uint8_t *src_addr, const struct ipv6_srh *srh,
                   const struct hmac_tlv *hmac_tlv, uint8_t *key,
                   size_t key_len, uint8_t *hmac_out);

int generate_nonce(uint8_t nonce[NONCE_LENGTH]);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);
void encrypt_pvf(uint8_t k_pot_in[SID_NO][HMAC_MAX_LENGTH], uint8_t *nonce,
                 uint8_t hmac_out[32]);
int decrypt_pvf(uint8_t k_pot_in[SID_NO][HMAC_MAX_LENGTH], uint8_t *nonce,
                uint8_t pvf_out[32]);

#endif // CRYPTO_H