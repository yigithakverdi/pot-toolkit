#include "crypto.h"

#include <ctype.h>
#include <openssl/hmac.h>
#include <stdlib.h>

#include "utils/logging.h"

uint8_t g_key_count = 0;
int num_transit_nodes = 0;
uint8_t k_pot_in[MAX_POT_NODES + 1][HMAC_MAX_LENGTH];

int load_pot_keys(const char* filepath, int keys_to_load) {
  FILE* file = fopen(filepath, "r");
  if (!file) {
    perror("Hata: Anahtar dosyası açılamadı");
    return -1;
  }

  // Her satırı okumak için yeterli büyüklükte bir tampon.
  // +2: newline ve null terminator için
  char line[HMAC_KEY_HEX_LENGTH + 2];
  g_key_count = 0;

  while (fgets(line, sizeof(line), file) && g_key_count < keys_to_load) {
    // Satır sonundaki newline karakterini kaldır
    line[strcspn(line, "\n")] = 0;

    // Boş satırları atla
    if (strlen(line) == 0) {
      continue;
    }

    // Hex string uzunluğu doğru mu? (örn: 16 byte için 32 karakter)
    if (strlen(line) != HMAC_KEY_HEX_LENGTH) {
      LOG_MAIN(WARNING, "Geçersiz anahtar uzunluğu, satır atlanıyor: %s\n", line);
      continue;
    }

    // Hex string'i byte dizisine çevir
    for (int i = 0; i < HMAC_MAX_LENGTH; i++) {
      char byte_str[3] = {line[i * 2], line[i * 2 + 1], '\0'};
      k_pot_in[g_key_count][i] = (uint8_t)strtol(byte_str, NULL, 16);
    }
    g_key_count++;
  }

  fclose(file);

  if (g_key_count == 0) {
    LOG_MAIN(WARNING, "%s dosyasından geçerli anahtar okunamadı\n", filepath);
    return -1;
  }

  LOG_MAIN(INFO, "%s dosyasından %u adet PoT anahtarı başarıyla yüklendi\n", filepath, g_key_count);
  return 0;
}

int calculate_hmac(uint8_t* src_addr, const struct ipv6_srh* srh, const struct hmac_tlv* hmac_tlv,
                   uint8_t* key, size_t key_len, uint8_t* hmac_out) {
  // Calculate the length of the segment list within the SRH.
  // This is crucial for determining how much data to include in the HMAC calculation.
  // size_t segment_list_len = sizeof(srh->segments);
  // size_t segment_list_len = srh->hdr_ext_len * 8;
  // LOG_MAIN(DEBUG, "Calculating HMAC: Segment list length = %zu bytes.\n", segment_list_len);
  LOG_MAIN(DEBUG, "--- HMAC Input Verification ---\n");
  char addr_str[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, src_addr, addr_str, sizeof(addr_str));
  LOG_MAIN(DEBUG, "HMAC INPUT | %-18s: %s\n", "Source Addr", addr_str);

  // 2. Log the critical SRH fields
  LOG_MAIN(DEBUG, "HMAC INPUT | %-18s: %u\n", "SRH Last Entry", srh->last_entry);
  LOG_MAIN(DEBUG, "HMAC INPUT | %-18s: %u\n", "SRH Flags", srh->flags);
  LOG_MAIN(DEBUG, "HMAC INPUT | %-18s: %u\n", "SRH Segments Left", srh->segments_left);

  // 3. Log the HMAC Key ID
  LOG_MAIN(DEBUG, "HMAC INPUT | %-18s: 0x%08x\n", "HMAC Key ID", rte_be_to_cpu_32(hmac_tlv->hmac_key_id));  


  size_t total_srh_size = (srh->hdr_ext_len * 8) + 8;
  size_t segment_list_len = total_srh_size - sizeof(struct ipv6_srh);
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
  // 5. Log the secret key being used
  log_hex_data("Secret Key", key, key_len);
  LOG_MAIN(DEBUG, "---------------------------------\n");  
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
  LOG_MAIN(DEBUG, "Calculating HMAC: Copied HMAC Key ID (%zu bytes). Offset: %zu\n",
           sizeof(hmac_tlv->hmac_key_id), offset);

  // memcpy(input + offset, srh->segments, segment_list_len);
  // offset += segment_list_len;
  // LOG_MAIN(DEBUG, "Calculating HMAC: Copied SRH Segments (%zu bytes). Offset: %zu\n", segment_list_len,
  //          offset);
  const struct in6_addr *segments = (const struct in6_addr *)((const uint8_t *)srh + sizeof(struct ipv6_srh));
  int num_segments = segment_list_len / sizeof(struct in6_addr);
  for (int i = 0; i < num_segments; i++) {
      inet_ntop(AF_INET6, &segments[i], addr_str, sizeof(addr_str));
      char label[32];
      if(g_logging_enabled) {
        sprintf(label, "Segment[%d]\n", i);
      }
      LOG_MAIN(DEBUG, "HMAC INPUT | %-18s: %s\n", label, addr_str);
  }

  memcpy(input + offset, segments, segment_list_len);
  offset += segment_list_len;
  LOG_MAIN(DEBUG, "Calculating HMAC: Copied SRH Segments (%zu bytes). Offset: %zu\n", segment_list_len,
           offset);  

  // Perform the actual HMAC calculation using OpenSSL's HMAC function.
  // EVP_sha256() specifies SHA-256 as the hash algorithm.
  // key: The secret key used for HMAC.
  // key_len: The length of the secret key.
  // input: The data over which the HMAC is calculated.
  // input_len: The length of the input data.
  // NULL: Context for streaming HMAC (not used here).
  // &hmac_len: Pointer to store the actual length of the generated HMAC digest.
  unsigned int hmac_len;
  uint8_t* digest = HMAC(EVP_sha256(), key, key_len, input, input_len, NULL, &hmac_len);

  // Check if the HMAC calculation failed.
  // If `digest` is NULL, it indicates an error in the HMAC function call.
  if (!digest) {
    LOG_MAIN(ERR, "HMAC calculation failed: digest is NULL.\n");
    return -1;
  }
  LOG_MAIN(DEBUG, "HMAC calculated successfully. Digest length: %u bytes.\n", hmac_len);

  // Copy the generated HMAC digest to the output buffer (`hmac_out`).
  // This handles cases where the calculated HMAC length might be less than `HMAC_MAX_LENGTH`.
  // If `hmac_len` is greater than `HMAC_MAX_LENGTH`, it copies only up to `HMAC_MAX_LENGTH` bytes.
  // If `hmac_len` is less than `HMAC_MAX_LENGTH`, it copies the digest and then
  // pads the remaining bytes of `hmac_out` with zeros to ensure a consistent output size.
  if (hmac_len > HMAC_OUTPUT_LENGTH) {
    LOG_MAIN(WARNING, "Calculated HMAC length (%u) exceeds HMAC_OUTPUT_LENGTH (%d), truncating.\n", hmac_len,
             HMAC_OUTPUT_LENGTH);
    memcpy(hmac_out, digest, HMAC_OUTPUT_LENGTH);
  } else {
    memcpy(hmac_out, digest, hmac_len);
    LOG_MAIN(DEBUG, "Copied HMAC digest (%u bytes) to output.\n", hmac_len);
  }

  // Log the calculated HMAC for debugging
  log_hex_data("Calculated HMAC", hmac_out, HMAC_OUTPUT_LENGTH);

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

void log_hex_data(const char* label, const uint8_t* data, size_t len) {
    char hex_str[len * 3 + 1];
    for (size_t i = 0; i < len; i++) {
      if(g_logging_enabled) {
        sprintf(hex_str + i * 3, "%02x ", data[i]);
      }
    }
    hex_str[len * 3] = '\0';
    LOG_MAIN(DEBUG, "HMAC INPUT | %-18s: %s\n", label, hex_str);
}

static int hex_string_to_bytes(const char* hex_str, uint8_t* buf, size_t buf_len) {
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

int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv,
            unsigned char* plaintext) {
  EVP_CIPHER_CTX* ctx;
  int len;
  int plaintext_len;

  // Create a new cipher context. This context holds all the necessary
  // information for the cryptographic operation (algorithm, key, IV, mode, etc.).
  // If creation fails, it's a fatal error as decryption cannot proceed.
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    LOG_MAIN(ERR, "Decryption context creation failed.\n");
    LOG_MAIN(ERR, "Context creation failed\n");
    return -1;
  }
  LOG_MAIN(DEBUG, "Decryption context created successfully.\n");

  // Initialize the decryption operation.
  // EVP_des_cbc(): Specifies AES-256 in Counter (CTR) mode. CTR mode is a stream cipher,
  // which means it doesn't require padding and works on arbitrary lengths of data.
  // NULL: No engine is used (default OpenSSL implementation).
  // key: The 256-bit (32-byte) secret key for decryption.
  // iv: The Initialization Vector (IV). For CTR mode, this is often called a nonce,
  // and must be unique for each encryption with the same key to ensure security.
  if (1 != EVP_DecryptInit_ex(ctx, EVP_des_cbc(), NULL, key, iv)) {
    LOG_MAIN(ERR, "Decryption initialization failed.\n");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  LOG_MAIN(DEBUG, "Decryption initialized with AES-256-CTR.\n");

  // Perform the decryption for the main part of the ciphertext.
  // plaintext: Output buffer where the decrypted data will be written.
  // &len: Will store the number of bytes decrypted in this call.
  // ciphertext: Input buffer containing the encrypted data.
  // ciphertext_len: The length of the input ciphertext.
  if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
    LOG_MAIN(ERR, "Decryption update failed.\n");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  plaintext_len = len;
  LOG_MAIN(DEBUG, "Decryption update successful. Plaintext length so far: %d bytes.\n", plaintext_len);

  // Finalize the decryption operation.
  // For stream ciphers like CTR, this typically handles any remaining internal buffers
  // but doesn't usually add padding or remove it. For block ciphers, it would handle padding.
  // plaintext + len: Pointer to where any final decrypted bytes should be appended.
  // &len: Will store the number of bytes decrypted in this final step.
  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
    LOG_MAIN(ERR, "Decryption finalization failed.\n");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  plaintext_len += len;
  LOG_MAIN(DEBUG, "Decryption finalization successful. Total plaintext length: %d bytes.\n", plaintext_len);

  // Free the cipher context. This is crucial to release resources
  // allocated by OpenSSL and prevent memory leaks.
  EVP_CIPHER_CTX_free(ctx);
  LOG_MAIN(DEBUG, "Decryption context freed.\n");

  return plaintext_len;
}

int decrypt_pvf(uint8_t k_pot_in[][HMAC_MAX_LENGTH], uint8_t* nonce, uint8_t pvf_out[32]) {
  uint8_t plaintext[128];
  int cipher_len = HMAC_OUTPUT_LENGTH;
  LOG_MAIN(DEBUG, "Decrypting PVF: Ciphertext length = %d bytes.\n", cipher_len);

  // Decrypt onion-style: loop from 0 to num_transit_nodes (egress to last transit)
  memcpy(plaintext, pvf_out, cipher_len);
  LOG_MAIN(DEBUG, "Number of transit nodes: %d\n", num_transit_nodes);
  for (int i = 0; i <= num_transit_nodes; i++) {
    int dec_len = decrypt(plaintext, cipher_len, k_pot_in[i], nonce, pvf_out);
    if (dec_len < 0) {
      LOG_MAIN(ERR, "PVF decryption failed at layer %d.\n", i);
      return -1;
    }
    LOG_MAIN(DEBUG, "PVF decryption layer %d successful.\n", i);
    memcpy(plaintext, pvf_out, cipher_len);
  }
  LOG_MAIN(DEBUG, "PVF decryption: All layers completed. Final decrypted HMAC in pvf_out.\n");
  return 0;
}

int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key, unsigned char* iv,
            unsigned char* ciphertext) {
  EVP_CIPHER_CTX* ctx;
  int len;
  int ciphertext_len;

  // Create a new cipher context. This context is essential for the encryption operation.
  // If `EVP_CIPHER_CTX_new()` returns NULL, it indicates a failure (e.g., out of memory).
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    LOG_MAIN(ERR, "Encryption context creation failed.\n");
    LOG_MAIN(ERR, "Context creation failed\n");
    return -1;
  }
  LOG_MAIN(DEBUG, "Encryption context created successfully.\n");

  // Initialize the encryption operation.
  // EVP_des_cbc(): Specifies AES-256 in Counter (CTR) mode. CTR is a stream cipher.
  // NULL: No specific OpenSSL engine is used.
  // key: The 256-bit (32-byte) secret key for encryption.
  // iv: The Initialization Vector (IV), also known as a nonce in CTR mode. It must be unique
  //     for each encryption performed with the same key to ensure cryptographic security.
  if (1 != EVP_EncryptInit_ex(ctx, EVP_des_cbc(), NULL, key, iv)) {
    LOG_MAIN(ERR, "Encryption initialization failed.\n");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  LOG_MAIN(DEBUG, "Encryption initialized with AES-256-CTR.\n");

  // Perform the encryption for the main part of the plaintext.
  // ciphertext: Output buffer where the encrypted data will be written.
  // &len: Will store the number of bytes encrypted in this particular call.
  // plaintext: Input buffer containing the data to be encrypted.
  // plaintext_len: The length of the input plaintext.
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
    LOG_MAIN(ERR, "Encryption update failed.\n");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  ciphertext_len = len;
  LOG_MAIN(DEBUG, "Encryption update successful. Ciphertext length so far: %d bytes.\n", ciphertext_len);

  // Finalize the encryption operation.
  // For stream ciphers like CTR, this typically processes any remaining internal data
  // but doesn't add padding (as block ciphers would).
  // ciphertext + len: Pointer to where any final encrypted bytes should be appended.
  // &len: Will store the number of bytes encrypted in this final step.
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
    LOG_MAIN(ERR, "Encryption finalization failed.\n");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  ciphertext_len += len;
  LOG_MAIN(DEBUG, "Encryption finalization successful. Total ciphertext length: %d bytes.\n", ciphertext_len);

  // Free the cipher context. This is vital to release all cryptographic resources
  // and prevent memory leaks.
  EVP_CIPHER_CTX_free(ctx);
  LOG_MAIN(DEBUG, "Encryption context freed.\n");

  return ciphertext_len;
}

// void encrypt_pvf(uint8_t k_pot_in[][HMAC_MAX_LENGTH], uint8_t* nonce, uint8_t hmac_out[32]) {
//   uint8_t buffer[HMAC_MAX_LENGTH];
//   memcpy(buffer, hmac_out, HMAC_MAX_LENGTH);
//   LOG_MAIN(DEBUG, "PVF Encryption: Initial HMAC copied to buffer. Length: %d bytes.\n", HMAC_MAX_LENGTH);

//   // Loop from num_transit_nodes down to 0 (onion encryption)
//   for (int i = num_transit_nodes; i >= 0; i--) {
//     LOG_MAIN(DEBUG, "PVF Encryption: Starting round %d with key_pot_in[%d].\n", num_transit_nodes - i + 1,
//     i); int enc_len = encrypt(buffer, HMAC_MAX_LENGTH, k_pot_in[i], nonce, hmac_out); if (enc_len < 0) {
//       LOG_MAIN(ERR, "PVF Encryption round %d failed.\n", num_transit_nodes - i + 1);
//       return;
//     }
//     LOG_MAIN(DEBUG, "PVF Encryption round %d successful. Ciphertext length: %d bytes.\n",
//              num_transit_nodes - i + 1, enc_len);
//     memcpy(buffer, hmac_out, HMAC_MAX_LENGTH);
//     LOG_MAIN(DEBUG, "PVF Encryption: Ciphertext copied to buffer for next round.\n");
//   }
//   LOG_MAIN(DEBUG, "PVF Encryption: All rounds completed. Final encrypted HMAC in hmac_out.\n");
// }

void encrypt_pvf(uint8_t k_pot_in[][HMAC_MAX_LENGTH], uint8_t* nonce, uint8_t hmac_out[32]) {
  uint8_t buffer[HMAC_OUTPUT_LENGTH];
  memcpy(buffer, hmac_out, HMAC_OUTPUT_LENGTH);

  // 1. First, encrypt the innermost layer with the Egress key (k[0])
  int enc_len = encrypt(buffer, HMAC_OUTPUT_LENGTH, k_pot_in[0], nonce, hmac_out);
  if (enc_len < 0) { 
    return;
  }
  memcpy(buffer, hmac_out, HMAC_OUTPUT_LENGTH);

  // 2. Then, encrypt outward with the transit keys in order (k[1], k[2], ...)
  // This creates the onion layers in the correct order.
  LOG_MAIN(DEBUG, "Number of transit nodes: %d\n", num_transit_nodes);
  for (int i = 1; i <= num_transit_nodes; i++) {

    // Log the key being used for this round
    char key_hex[HMAC_MAX_LENGTH * 2 + 1];
    for (int j = 0; j < HMAC_MAX_LENGTH; j++) {
      sprintf(key_hex + j * 2, "%02x", k_pot_in[i][j]);
    }
    key_hex[HMAC_MAX_LENGTH * 2] = '\0';
    LOG_MAIN(DEBUG, "PVF Encryption round %d using key: %s\n", i + 1, key_hex);

    enc_len = encrypt(buffer, HMAC_OUTPUT_LENGTH, k_pot_in[i], nonce, hmac_out);
    if (enc_len < 0) { 
      return;
    }
    LOG_MAIN(DEBUG, "PVF Encryption round %d successful. Ciphertext length: %d bytes.\n",
         i + 1, enc_len);
    
    // Log the HMAC after encryption
    log_hex_data("HMAC after encryption", hmac_out, HMAC_OUTPUT_LENGTH);
    
    memcpy(buffer, hmac_out, HMAC_OUTPUT_LENGTH);
  }
  LOG_MAIN(DEBUG, "PVF Encryption: All rounds completed.\n");
}

int compare_hmac(struct hmac_tlv* hmac, uint8_t* hmac_out, struct rte_mbuf* mbuf) {
  LOG_MAIN(DEBUG, "Comparing HMAC for mbuf %p\n", mbuf);

  // Compares the received HMAC value (from the packet's hmac_tlv structure)
  // with a newly computed HMAC value (hmac_out).
  // memcmp() performs a byte-by-byte comparison of two memory blocks.
  // hmac->hmac_value: The HMAC value extracted from the incoming packet's HMAC TLV.
  // hmac_out: The HMAC value that was *calculated* by the local device based on the packet's content.
  // 32: The size in bytes of the HMAC hash. This assumes a fixed HMAC length (e.g., HMAC-SHA256 output is 32
  // bytes). If the two HMAC values do not match (memcmp returns non-zero), it indicates tampering or an
  // error.
  if (memcmp(hmac->hmac_value, hmac_out, 32) != 0) {
    // If the HMACs do not match, the packet is considered invalid or compromised.
    // The mbuf is immediately freed, preventing it from being processed further and
    // returning its memory to the pool. This is a security measure to drop invalid packets.
    rte_pktmbuf_free(mbuf);
    LOG_MAIN(ERR, "HMAC mismatch for mbuf %p\n", mbuf);
    return 0;
  } else {
    LOG_MAIN(DEBUG, "HMAC match for mbuf %p\n", mbuf);
    return 1;
  }
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
    LOG_MAIN(ERR, "Failed to generate cryptographically secure nonce.\n");
    return 1;
  }
  LOG_MAIN(DEBUG, "Successfully generated %d-byte nonce.\n", NONCE_LENGTH);
  return 0;
}

int read_encryption_key(const char* file_path, const char* ipv6_addr, uint8_t* key_out, size_t key_out_len) {
  // Attempt to open the key file in read mode ("r").
  // If the file cannot be opened (e.g., file not found, permissions issue),
  // log an error with `perror` (which adds system error details) and return.
  FILE* f = fopen(file_path, "r");
  if (!f) {
    LOG_MAIN(ERR, "Failed to open key file at %s.\n", file_path);
    perror("Failed to open key file");
    return -1;
  }
  LOG_MAIN(DEBUG, "Opened key file at %s successfully.\n", file_path);

  char line[256];
  int ret = -1;

  // Loop through each line of the file until the end of the file (NULL is returned by fgets).
  while (fgets(line, sizeof(line), f) != NULL) {
    LOG_MAIN(DEBUG, "Reading line from key file: %s\n", line);
    char* p = line;
    while (*p && isspace((unsigned char)*p)) {
      p++;
    }
    if (*p == '#' || *p == '\0' || *p == '\n') {
      LOG_MAIN(DEBUG, "Skipping comment or empty line.\n");
      continue;
    }

    // Remove the trailing newline character from the line, if present.
    // strcspn finds the first occurrence of '\n' and replaces it with '\0'.
    line[strcspn(line, "\n")] = '\0';
    LOG_MAIN(DEBUG, "Processed line (no newline): %s\n", line);

    // Tokenize the line to extract the IPv6 address part.
    // strtok() splits the string based on space or tab delimiters.
    char* token = strtok(line, " \t");
    if (!token) {
      LOG_MAIN(DEBUG, "No token found on line, continuing.\n");
      continue;
    }
    LOG_MAIN(DEBUG, "First token (IPv6 address) found: %s\n", token);

    // Compare the extracted IPv6 address string with the target `ipv6_addr`.
    // If they don't match, this line is not the one we're looking for, so continue to the next.
    if (strcmp(token, ipv6_addr) != 0) {
      LOG_MAIN(DEBUG, "IPv6 address '%s' does not match target '%s'.\n", token, ipv6_addr);
      continue;
    }
    LOG_MAIN(INFO, "Matching IPv6 address '%s' found in key file.\n", ipv6_addr);

    char* key_str = strtok(NULL, " \t");
    if (!key_str) {
      LOG_MAIN(ERR, "Key string not found for IPv6 address '%s'.\n", ipv6_addr);
      ret = -1;
      break;
    }
    LOG_MAIN(DEBUG, "Key string found: %s\n", key_str);

    // Convert the hexadecimal key string into its binary byte representation.
    // `hex_string_to_bytes` is assumed to be an external function for this conversion.
    // `key_out` is the buffer to store the binary key, `key_out_len` is its max length.
    if (hex_string_to_bytes(key_str, key_out, key_out_len) < 0) {
      LOG_MAIN(ERR, "Failed to convert hex key string '%s' to bytes.\n", key_str);
      ret = -1;
    } else {
      LOG_MAIN(INFO, "Successfully read encryption key for IPv6 address '%s'.\n", ipv6_addr);
      ret = 0;
    }
    break;
  }

  fclose(f);
  LOG_MAIN(DEBUG, "Key file %s closed.\n", file_path);

  return ret;
}