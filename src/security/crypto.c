#include "security/crypto.h"

#include <openssl/hmac.h>

#include "utils/logging.h"
int calculate_hmac(uint8_t *src_addr, const struct ipv6_srh *srh, const struct hmac_tlv *hmac_tlv,
                   uint8_t *key, size_t key_len, uint8_t *hmac_out) {
  // Calculate the length of the segment list within the SRH.
  // This is crucial for determining how much data to include in the HMAC calculation.
  size_t segment_list_len = sizeof(srh->segments);
  LOG_MAIN(DEBUG, "Calculating HMAC: Segment list length = %zu bytes.\n", segment_list_len);

  // Calculate the total length of the input data for the HMAC function.
  // This sum accounts for:
  // - 16 bytes: IPv6 Source Address
  // - 1 byte: SRH Last Entry
  // - 1 byte: SRH Flags
  // - 2 bytes: Reserved field (assuming a specific structure alignment or padding within SRH)
  // - 4 bytes: HMAC Key ID from hmac_tlv
  // - segment_list_len: The actual segment list from SRH
  // Any discrepancy here will lead to incorrect HMAC calculations and verification failures.
  size_t input_len = 16 + 1 + 1 + 2 + 4 + segment_list_len;
  LOG_MAIN(DEBUG, "Calculating HMAC: Total input length = %zu bytes.\n", input_len);
  uint8_t input[input_len];

  size_t offset = 0;
  memcpy(input + offset, src_addr, 16);
  offset += 16;
  LOG_MAIN(DEBUG, "Calculating HMAC: Copied Source Address (16 bytes). Offset: %zu\n", offset);

  input[offset++] = srh->last_entry;
  input[offset++] = srh->flags;
  LOG_MAIN(DEBUG, "Calculating HMAC: Copied SRH Last Entry and Flags (2 bytes). Offset: %zu\n", offset);

  // Copy 2 bytes of reserved/padding field.
  // This assumes a specific layout for the input to HMAC which includes these two zeroed bytes.
  // This padding is crucial for consistency between HMAC calculation and verification.
  input[offset++] = 0;
  input[offset++] = 0;
  LOG_MAIN(DEBUG, "Calculating HMAC: Added 2 reserved bytes. Offset: %zu\n", offset);

  memcpy(input + offset, &hmac_tlv->hmac_key_id, sizeof(hmac_tlv->hmac_key_id));
  offset += sizeof(hmac_tlv->hmac_key_id);
  LOG_MAIN(DEBUG, "Calculating HMAC: Copied HMAC Key ID (%zu bytes). Offset: %zu",
           sizeof(hmac_tlv->hmac_key_id), offset);

  memcpy(input + offset, srh->segments, segment_list_len);
  offset += segment_list_len;
  LOG_MAIN(DEBUG, "Calculating HMAC: Copied SRH Segments (%zu bytes). Offset: %zu", segment_list_len, offset);

  // Perform the actual HMAC calculation using OpenSSL's HMAC function.
  // EVP_sha256() specifies SHA-256 as the hash algorithm.
  // key: The secret key used for HMAC.
  // key_len: The length of the secret key.
  // input: The data over which the HMAC is calculated.
  // input_len: The length of the input data.
  // NULL: Context for streaming HMAC (not used here).
  // &hmac_len: Pointer to store the actual length of the generated HMAC digest.
  unsigned int hmac_len;
  uint8_t *digest = HMAC(EVP_sha256(), key, key_len, input, input_len, NULL, &hmac_len);

  // Check if the HMAC calculation failed.
  // If `digest` is NULL, it indicates an error in the HMAC function call.
  if (!digest) {
    LOG_MAIN(ERR, "HMAC calculation failed: digest is NULL.");
    return -1;
  }
  LOG_MAIN(DEBUG, "HMAC calculated successfully. Digest length: %u bytes.", hmac_len);

  // Copy the generated HMAC digest to the output buffer (`hmac_out`).
  // This handles cases where the calculated HMAC length might be less than `HMAC_MAX_LENGTH`.
  // If `hmac_len` is greater than `HMAC_MAX_LENGTH`, it copies only up to `HMAC_MAX_LENGTH` bytes.
  // If `hmac_len` is less than `HMAC_MAX_LENGTH`, it copies the digest and then
  // pads the remaining bytes of `hmac_out` with zeros to ensure a consistent output size.
  if (hmac_len > HMAC_MAX_LENGTH) {
    LOG_MAIN(WARNING, "Calculated HMAC length (%u) exceeds HMAC_MAX_LENGTH (%d), truncating.", hmac_len,
             HMAC_MAX_LENGTH);
    memcpy(hmac_out, digest, HMAC_MAX_LENGTH);
  } else {
    memcpy(hmac_out, digest, hmac_len);
    memset(hmac_out + hmac_len, 0, HMAC_MAX_LENGTH - hmac_len);
    LOG_MAIN(DEBUG, "Copied HMAC digest (%u bytes) to output, padded with zeros if necessary.", hmac_len);
  }

  LOG_MAIN(DEBUG, "HMAC calculation completed successfully.");
  return 0;
}

static int hex_char_to_int(char c) {
  if ('0' <= c && c <= '9')
    return c - '0';
  else if ('a' <= c && c <= 'f')
    return c - 'a' + 10;
  else if ('A' <= c && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static int hex_string_to_bytes(const char *hex_str, uint8_t *buf, size_t buf_len) {
  size_t hex_len = strlen(hex_str);

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

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv,
            unsigned char *plaintext) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;

  // Create a new cipher context. This context holds all the necessary
  // information for the cryptographic operation (algorithm, key, IV, mode, etc.).
  // If creation fails, it's a fatal error as decryption cannot proceed.
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    LOG_MAIN(ERR, "Decryption context creation failed.");
    printf("Context creation failed\n");
    return -1;
  }
  LOG_MAIN(DEBUG, "Decryption context created successfully.");

  // Initialize the decryption operation.
  // EVP_aes_256_ctr(): Specifies AES-256 in Counter (CTR) mode. CTR mode is a stream cipher,
  // which means it doesn't require padding and works on arbitrary lengths of data.
  // NULL: No engine is used (default OpenSSL implementation).
  // key: The 256-bit (32-byte) secret key for decryption.
  // iv: The Initialization Vector (IV). For CTR mode, this is often called a nonce,
  // and must be unique for each encryption with the same key to ensure security.
  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv)) {
    LOG_MAIN(ERR, "Decryption initialization failed.");
    printf("Decryption initialization failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  LOG_MAIN(DEBUG, "Decryption initialized with AES-256-CTR.");

  // Perform the decryption for the main part of the ciphertext.
  // plaintext: Output buffer where the decrypted data will be written.
  // &len: Will store the number of bytes decrypted in this call.
  // ciphertext: Input buffer containing the encrypted data.
  // ciphertext_len: The length of the input ciphertext.
  if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
    LOG_MAIN(ERR, "Decryption update failed.");
    printf("Decryption update failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  plaintext_len = len;
  LOG_MAIN(DEBUG, "Decryption update successful. Plaintext length so far: %d bytes.", plaintext_len);

  // Finalize the decryption operation.
  // For stream ciphers like CTR, this typically handles any remaining internal buffers
  // but doesn't usually add padding or remove it. For block ciphers, it would handle padding.
  // plaintext + len: Pointer to where any final decrypted bytes should be appended.
  // &len: Will store the number of bytes decrypted in this final step.
  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
    LOG_MAIN(ERR, "Decryption finalization failed.");
    printf("Decryption finalization failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  plaintext_len += len;
  LOG_MAIN(DEBUG, "Decryption finalization successful. Total plaintext length: %d bytes.", plaintext_len);

  // Free the cipher context. This is crucial to release resources
  // allocated by OpenSSL and prevent memory leaks.
  EVP_CIPHER_CTX_free(ctx);
  LOG_MAIN(DEBUG, "Decryption context freed.");

  return plaintext_len;
}

int decrypt_pvf(uint8_t k_pot_in[][HMAC_MAX_LENGTH], uint8_t *nonce, uint8_t pvf_out[32]) {
  // Declare a buffer to hold the decrypted plaintext.
  // The size 128 is chosen to be sufficiently large to accommodate the expected decrypted data (32 bytes
  // HMAC).
  uint8_t plaintext[128];

  // Set the length of the ciphertext to be decrypted, which is 32 bytes (HMAC_MAX_LENGTH).
  int cipher_len = 32;
  LOG_MAIN(DEBUG, "Decrypting PVF: Ciphertext length = %d bytes.", cipher_len);

  // Call the generic `decrypt` function to perform the AES-256-CTR decryption.
  // - pvf_out: Input buffer containing the encrypted PVF data (the HMAC).
  // - cipher_len: Length of the encrypted PVF data.
  // - k_pot_in[0]: The decryption key. This implies that the first key in the `k_pot_in` array
  //   is used for decryption at this stage.
  // - nonce: The Initialization Vector (Nonce) used during encryption, crucial for CTR mode.
  // - plaintext: Output buffer where the decrypted data will be stored.
  int dec_len = decrypt(pvf_out, cipher_len, k_pot_in[0], nonce, plaintext);

  // Check if the decryption function returned an error.
  // Although the current `decrypt` function returns `-1` on error, this `if` block
  // could be extended to handle `dec_len` being less than 0.
  if (dec_len < 0) {
    LOG_MAIN(ERR, "PVF decryption failed for incoming data.");

    // This function currently returns 0 on success, so a non-zero value
    // might indicate an error here if the return type were changed.
    return -1;
  }
  LOG_MAIN(DEBUG, "PVF decryption successful. Decrypted length: %d bytes.", dec_len);

  // Copy the decrypted plaintext (which is the HMAC) back into the `pvf_out` buffer.
  // This overwrites the original encrypted data with its decrypted version,
  // making it ready for HMAC verification.
  memcpy(pvf_out, plaintext, 32);
  LOG_MAIN(DEBUG, "Decrypted HMAC copied back to pvf_out buffer.");

  return 0;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  // Create a new cipher context. This context is essential for the encryption operation.
  // If `EVP_CIPHER_CTX_new()` returns NULL, it indicates a failure (e.g., out of memory).
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    LOG_MAIN(ERR, "Encryption context creation failed.");
    printf("Context creation failed\n");
    return -1;
  }
  LOG_MAIN(DEBUG, "Encryption context created successfully.");

  // Initialize the encryption operation.
  // EVP_aes_256_ctr(): Specifies AES-256 in Counter (CTR) mode. CTR is a stream cipher.
  // NULL: No specific OpenSSL engine is used.
  // key: The 256-bit (32-byte) secret key for encryption.
  // iv: The Initialization Vector (IV), also known as a nonce in CTR mode. It must be unique
  //     for each encryption performed with the same key to ensure cryptographic security.
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv)) {
    LOG_MAIN(ERR, "Encryption initialization failed.");
    printf("Encryption initialization failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  LOG_MAIN(DEBUG, "Encryption initialized with AES-256-CTR.");

  // Perform the encryption for the main part of the plaintext.
  // ciphertext: Output buffer where the encrypted data will be written.
  // &len: Will store the number of bytes encrypted in this particular call.
  // plaintext: Input buffer containing the data to be encrypted.
  // plaintext_len: The length of the input plaintext.
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
    LOG_MAIN(ERR, "Encryption update failed.");
    printf("Encryption update failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  ciphertext_len = len;
  LOG_MAIN(DEBUG, "Encryption update successful. Ciphertext length so far: %d bytes.", ciphertext_len);

  // Finalize the encryption operation.
  // For stream ciphers like CTR, this typically processes any remaining internal data
  // but doesn't add padding (as block ciphers would).
  // ciphertext + len: Pointer to where any final encrypted bytes should be appended.
  // &len: Will store the number of bytes encrypted in this final step.
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
    LOG_MAIN(ERR, "Encryption finalization failed.");
    printf("Encryption finalization failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  ciphertext_len += len;
  LOG_MAIN(DEBUG, "Encryption finalization successful. Total ciphertext length: %d bytes.", ciphertext_len);

  // Free the cipher context. This is vital to release all cryptographic resources
  // and prevent memory leaks.
  EVP_CIPHER_CTX_free(ctx);
  LOG_MAIN(DEBUG, "Encryption context freed.");

  return ciphertext_len;
}

void encrypt_pvf(uint8_t k_pot_in[][HMAC_MAX_LENGTH], uint8_t *nonce, uint8_t hmac_out[32]) {
  // Declare a temporary buffer to hold the HMAC value during the iterative encryption process.
  // Its size is HMAC_MAX_LENGTH (32 bytes).
  uint8_t buffer[HMAC_MAX_LENGTH];

  // Copy the initial HMAC value (which is to be encrypted) into the temporary buffer.
  // This `buffer` will be updated with the result of each encryption round.
  memcpy(buffer, hmac_out, HMAC_MAX_LENGTH);
  LOG_MAIN(DEBUG, "PVF Encryption: Initial HMAC copied to buffer. Length: %d bytes.", HMAC_MAX_LENGTH);

  // This loop performs a "double encryption" or an iterative encryption process.
  // The loop runs twice (from i=1 down to 0). This suggests a two-layer encryption
  // where the output of one encryption is fed as input to the next, likely using
  // different keys from the `k_pot_in` array.
  for (int i = 1; i >= 0; i--) {
    LOG_MAIN(DEBUG, "PVF Encryption: Starting round %d with key_pot_in[%d].", 2 - i, i);

    // Perform the encryption.
    // - buffer: The plaintext for this round (initially the HMAC, then the result of the previous round).
    // - HMAC_MAX_LENGTH: Length of the plaintext.
    // - k_pot_in[i]: The encryption key for the current round. This uses different keys for each round
    //   (k_pot_in[1] for the first round, k_pot_in[0] for the second).
    // - nonce: The Initialization Vector (Nonce), which must be consistent across rounds and unique per
    // packet.
    // - hmac_out: The output buffer where the ciphertext of the current round will be placed.
    int enc_len = encrypt(buffer, HMAC_MAX_LENGTH, k_pot_in[i], nonce, hmac_out);

    // Check if the encryption failed.
    // If enc_len is negative, it indicates an error in the `encrypt` function.
    if (enc_len < 0) {
      LOG_MAIN(ERR, "PVF Encryption round %d failed.", 2 - i);

      // In a real application, you might want to handle this error more gracefully,
      // e.g., free the mbuf and return from the parent function.
      return;
    }
    LOG_MAIN(DEBUG, "PVF Encryption round %d successful. Ciphertext length: %d bytes.", 2 - i, enc_len);

    // Copy the ciphertext from the current round (`hmac_out`) back into `buffer`.
    // This prepares `buffer` to be the plaintext input for the next encryption round.
    memcpy(buffer, hmac_out, HMAC_MAX_LENGTH);
    LOG_MAIN(DEBUG, "PVF Encryption: Ciphertext copied to buffer for next round.");
  }
  LOG_MAIN(DEBUG, "PVF Encryption: All rounds completed. Final encrypted HMAC in hmac_out.");
}

int generate_nonce(uint8_t nonce[NONCE_LENGTH]) {
  // Generate cryptographically secure random bytes for the nonce.
  // RAND_bytes() is an OpenSSL function that fills the specified buffer with
  // cryptographically secure pseudo-random bytes.
  // nonce: The buffer to fill with random bytes.
  // NONCE_LENGTH: The number of random bytes to generate (size of the nonce).
  // Returns 1 on success, 0 or -1 on failure.
  if (RAND_bytes(nonce, NONCE_LENGTH) != 1) {
    // If RAND_bytes fails, it indicates a problem with the random number generator.
    // This is a security-critical failure, as non-random nonces can compromise encryption.
    LOG_MAIN(ERR, "Failed to generate cryptographically secure nonce.");
    return 1;
  }
  LOG_MAIN(DEBUG, "Successfully generated %d-byte nonce.", NONCE_LENGTH);
  return 0;
}

int read_encryption_key(const char *file_path, const char *ipv6_addr, uint8_t *key_out, size_t key_out_len) {
  // Attempt to open the key file in read mode ("r").
  // If the file cannot be opened (e.g., file not found, permissions issue),
  // log an error with `perror` (which adds system error details) and return.
  FILE *f = fopen(file_path, "r");
  if (!f) {
    LOG_MAIN(ERR, "Failed to open key file at %s.", file_path);
    perror("Failed to open key file");
    return -1;
  }
  LOG_MAIN(DEBUG, "Opened key file at %s successfully.", file_path);

  char line[256];
  int ret = -1;

  // Loop through each line of the file until the end of the file (NULL is returned by fgets).
  while (fgets(line, sizeof(line), f) != NULL) {
    LOG_MAIN(DEBUG, "Reading line from key file: %s", line);
    char *p = line;
    while (*p && isspace((unsigned char)*p)) {
      p++;
    }
    if (*p == '#' || *p == '\0' || *p == '\n') {
      LOG_MAIN(DEBUG, "Skipping comment or empty line.");
      continue;
    }

    // Remove the trailing newline character from the line, if present.
    // strcspn finds the first occurrence of '\n' and replaces it with '\0'.
    line[strcspn(line, "\n")] = '\0';
    LOG_MAIN(DEBUG, "Processed line (no newline): %s", line);

    // Tokenize the line to extract the IPv6 address part.
    // strtok() splits the string based on space or tab delimiters.
    char *token = strtok(line, " \t");
    if (!token) {
      LOG_MAIN(DEBUG, "No token found on line, continuing.");
      continue;
    }
    LOG_MAIN(DEBUG, "First token (IPv6 address) found: %s", token);

    // Compare the extracted IPv6 address string with the target `ipv6_addr`.
    // If they don't match, this line is not the one we're looking for, so continue to the next.
    if (strcmp(token, ipv6_addr) != 0) {
      LOG_MAIN(DEBUG, "IPv6 address '%s' does not match target '%s'.", token, ipv6_addr);
      continue;
    }
    LOG_MAIN(INFO, "Matching IPv6 address '%s' found in key file.", ipv6_addr);

    char *key_str = strtok(NULL, " \t");
    if (!key_str) {
      LOG_MAIN(ERR, "Key string not found for IPv6 address '%s'.", ipv6_addr);
      ret = -1;
      break;
    }
    LOG_MAIN(DEBUG, "Key string found: %s", key_str);

    // Convert the hexadecimal key string into its binary byte representation.
    // `hex_string_to_bytes` is assumed to be an external function for this conversion.
    // `key_out` is the buffer to store the binary key, `key_out_len` is its max length.
    if (hex_string_to_bytes(key_str, key_out, key_out_len) < 0) {
      LOG_MAIN(ERR, "Failed to convert hex key string '%s' to bytes.", key_str);
      ret = -1;
    } else {
      LOG_MAIN(INFO, "Successfully read encryption key for IPv6 address '%s'.", ipv6_addr);
      ret = 0;
    }
    break;
  }

  fclose(f);
  LOG_MAIN(DEBUG, "Key file %s closed.", file_path);

  return ret;
}