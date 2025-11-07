#ifndef CRYPTO_H
#define CRYPTO_H

#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "headers.h"

#define HMAC_OUTPUT_LENGTH 32   // SHA-256 HMAC output is always 32 bytes
#define HMAC_KEY_LENGTH 8      // Key length for encryption (64 bytes)
#define HMAC_MAX_LENGTH HMAC_KEY_LENGTH  // Keep for backward compatibility
#define NONCE_LENGTH 16
#define SID_NO 4
#define HMAC_KEY_HEX_LENGTH (HMAC_KEY_LENGTH * 2)

extern uint8_t k_pot_in[MAX_POT_NODES + 1][HMAC_MAX_LENGTH];
extern uint8_t g_key_count;
extern int num_transit_nodes;

// Cipher type configuration for benchmarking different key lengths
typedef enum {
    CIPHER_DES_8,           // 8 bytes (64-bit) - INSECURE, for benchmark only
    CIPHER_AES_128_CTR,     // 16 bytes (128-bit)
    CIPHER_AES_256_CTR,     // 32 bytes (256-bit)
    CIPHER_CHACHA20         // 32 bytes (256-bit)
} cipher_type_t;

extern cipher_type_t g_cipher_type;

void set_cipher_type(cipher_type_t type);
const EVP_CIPHER* get_current_cipher(void);
int get_current_key_size(void);

// HMAC calculation
int calculate_hmac(uint8_t* src_addr, const struct ipv6_srh* srh, const struct hmac_tlv* hmac_tlv,
                   uint8_t* key, size_t key_len, uint8_t* hmac_out);

int generate_nonce(uint8_t nonce[NONCE_LENGTH]);
int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key, unsigned char* iv,
            unsigned char* ciphertext);
int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv,
            unsigned char* plaintext);
void encrypt_pvf(uint8_t k_pot_in[SID_NO][HMAC_MAX_LENGTH], uint8_t* nonce, uint8_t hmac_out[32]);
int decrypt_pvf(uint8_t k_pot_in[SID_NO][HMAC_MAX_LENGTH], uint8_t* nonce, uint8_t pvf_out[32]);
int compare_hmac(struct hmac_tlv* hmac, uint8_t* hmac_out, struct rte_mbuf* mbuf);
int load_pot_keys(const char* filepath, int keys_to_load);
void log_hex_data(const char* label, const uint8_t* data, size_t len);
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
int read_encryption_key(const char* file_path, const char* ipv6_addr, uint8_t* key_out, size_t key_out_len);

#endif // CRYPTO_H