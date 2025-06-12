#include <crypto.h>

int calculate_hmac(uint8_t *src_addr,                // Source IPv6 address (16 bytes)
                   const struct ipv6_srh *srh,       // Pointer to the IPv6 Segment Routing Header (SRH)
                   const struct hmac_tlv *hmac_tlv,  // Pointer to the HMAC TLV
                   uint8_t *key,                     // Pre-shared key
                   size_t key_len,                   // Length of the pre-shared key
                   uint8_t *hmac_out)                // Output buffer for the HMAC (32 bytes)
{
  // Input text buffer for HMAC computation
  size_t segment_list_len = sizeof(srh->segments);

  size_t input_len = 16 + 1 + 1 + 2 + 4 + segment_list_len;  // IPv6 Source + Last Entry + Flags
                                                             // + Length + Key ID + Segment List

  uint8_t input[input_len];

  // Fill the input buffer
  size_t offset = 0;
  memcpy(input + offset, src_addr, 16);  // IPv6 Source Address
  offset += 16;

  input[offset++] = srh->last_entry;  // Last Entry
  input[offset++] = srh->flags;       // Flags (D-bit + Reserved)

  input[offset++] = 0;  // Placeholder for Length (2 bytes, can be zero for this step)
  input[offset++] = 0;

  memcpy(input + offset, &hmac_tlv->hmac_key_id,
         sizeof(hmac_tlv->hmac_key_id));  // HMAC Key ID
  offset += sizeof(hmac_tlv->hmac_key_id);

  memcpy(input + offset, srh->segments, segment_list_len);  // Segment List
  offset += segment_list_len;

  // Perform HMAC computation using OpenSSL
  unsigned int hmac_len;
  uint8_t *digest = HMAC(EVP_sha256(), key, key_len, input, input_len, NULL, &hmac_len);

  if (!digest) {
    rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1, "HMAC computation failed\n");
    return -1;
  }

  // Truncate or pad the HMAC to 32 bytes
  if (hmac_len > HMAC_MAX_LENGTH) {
    memcpy(hmac_out, digest, HMAC_MAX_LENGTH);
  } else {
    memcpy(hmac_out, digest, hmac_len);
    memset(hmac_out + hmac_len, 0,
           HMAC_MAX_LENGTH - hmac_len);  // Pad with zeros
  }

  return 0;  // Success
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv,
            unsigned char *plaintext) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;

  if (!(ctx = EVP_CIPHER_CTX_new())) {
    printf("Context creation failed\n");
  }
  // Use counter mode
  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv)) {
    printf("Decryption initialization failed\n");
  }
  if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
    printf("Decryption update failed\n");
  }
  plaintext_len = len;

  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
    printf("Decryption finalization failed\n");
  }
  plaintext_len += len;

  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}

int decrypt_pvf(uint8_t k_pot_in[SID_NO][HMAC_MAX_LENGTH], uint8_t *nonce, uint8_t pvf_out[32]) {
  // k_pot_in is a 2d array of strings holding statically allocated keys for the
  // nodes. In this proof of concept there is only one middle node and an egress
  // node so the shape is [2][key-length]
  uint8_t plaintext[128];
  int cipher_len = 32;
  printf("\n----------Decrypting----------\n");
  // Use the first key for decryption (adjust as needed)
  int dec_len = decrypt(pvf_out, cipher_len, k_pot_in[0], nonce, plaintext);
  printf("Dec len %d\n", dec_len);
  printf("original text is:\n");
  for (int j = 0; j < 32; j++) {
    printf("%02x", pvf_out[j]);
  }
  printf("\n");
  memcpy(pvf_out, plaintext, 32);
  printf("Decrypted text is : \n");
  BIO_dump_fp(stdout, (const char *)pvf_out, dec_len);
  return 0;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  if (!(ctx = EVP_CIPHER_CTX_new())) {
    printf("Context creation failed\n");
  }
  // Use counter mode
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv)) {
    printf("Encryption initialization failed\n");
  }
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
    printf("Encryption update failed\n");
  }
  ciphertext_len = len;

  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
    printf("Encryption finalization failed\n");
  }
  ciphertext_len += len;

  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
}

void encrypt_pvf(uint8_t k_pot_in[SID_NO][HMAC_MAX_LENGTH], uint8_t *nonce, uint8_t hmac_out[32]) {
  // k_pot_in is a 2d array of strings holding statically allocated keys for the
  // nodes. In this proof of concept there is only one middle node and an egress
  // node so the shape is [2][key-length]
  uint8_t ciphertext[128];
  printf("\n----------Encrypting----------\n");
  for (int i = 0; i < SID_NO; i++) {
    for (int j = 0; j < HMAC_MAX_LENGTH; j++) {
      printf("%02x", hmac_out[j]);
    }
    encrypt(hmac_out, HMAC_MAX_LENGTH, k_pot_in[i], nonce, ciphertext);
    memcpy(hmac_out, ciphertext, 32);
  }
}

int generate_nonce(uint8_t nonce[NONCE_LENGTH]) {
  if (RAND_bytes(nonce, NONCE_LENGTH) != 1) {
    printf("Error: Failed to generate random nonce.\n");
    return 1;
  }
  // printf("Generated Nonce: ");
  for (int i = 0; i < NONCE_LENGTH; i++) {
    printf("%02x", nonce[i]);
  }
  // printf("\n");
  return 0;
}

/**
 * Converts a single hex character to its integer value.
 * Returns -1 if the character is not a valid hex digit.
 */
static int hex_char_to_int(char c) {
  if ('0' <= c && c <= '9')
    return c - '0';
  else if ('a' <= c && c <= 'f')
    return c - 'a' + 10;
  else if ('A' <= c && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

/**
 * Parses a hex string into a byte array.
 *
 * @param hex_str   The string containing hex digits.
 * @param buf       The output buffer to store bytes.
 * @param buf_len   Length of the output buffer.
 *
 * @return Number of bytes written if successful, -1 on error.
 */
static int hex_string_to_bytes(const char *hex_str, uint8_t *buf, size_t buf_len) {
  size_t hex_len = strlen(hex_str);

  // Hex string must have even number of characters
  if (hex_len % 2 != 0) return -1;
  size_t bytes_needed = hex_len / 2;

  if (bytes_needed > buf_len) return -1;

  for (size_t i = 0; i < bytes_needed; i++) {
    int high = hex_char_to_int(hex_str[2 * i]);
    int low = hex_char_to_int(hex_str[2 * i + 1]);
    if (high < 0 || low < 0) return -1;
    buf[i] = (high << 4) | low;
  }
  return (int)bytes_needed;
}

/**
 * Reads an encryption key corresponding to a given IPv6 address from a key-value store file.
 *
 * The key file is expected to be structured as follows:
 *
 *   # Optional comments start with #
 *   <IPv6_address> <encryption_key_in_hex>
 *
 * For example:
 *   2001:db8:1::1 00112233445566778899aabbccddeeff
 *
 * @param file_path  Path to the key-value store file.
 * @param ipv6_addr  IPv6 address (in string format) used as the key in the store.
 * @param key_out    Buffer to store the retrieved encryption key.
 * @param key_out_len Length of the key_out buffer.
 *
 * @return 0 on success, non-zero on error.
 */
int read_encryption_key(const char *file_path, const char *ipv6_addr, uint8_t *key_out, size_t key_out_len) {
  FILE *f = fopen(file_path, "r");
  if (!f) {
    perror("Failed to open key file");
    return -1;
  }

  char line[256];
  int ret = -1;
  while (fgets(line, sizeof(line), f) != NULL) {
    // Skip lines that are empty or comments.
    char *p = line;
    while (*p && isspace((unsigned char)*p)) {
      p++;
    }
    if (*p == '#' || *p == '\0' || *p == '\n') continue;

    // Remove any newline character.
    line[strcspn(line, "\n")] = '\0';

    // Tokenize the line: first token is IPv6 address, second token is hex key.
    char *token = strtok(line, " \t");
    if (!token) continue;
    if (strcmp(token, ipv6_addr) != 0) continue;

    char *key_str = strtok(NULL, " \t");
    if (!key_str) {
      ret = -1;
      break;
    }
    // Convert the hex representation to raw bytes.
    if (hex_string_to_bytes(key_str, key_out, key_out_len) < 0) {
      ret = -1;
    } else {
      ret = 0;
    }
    break;
  }

  fclose(f);
  return ret;
}