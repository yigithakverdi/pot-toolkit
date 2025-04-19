#include "include/crypto_utils.h"

int calculate_hmac(uint8_t *src_addr, // Source IPv6 address (16 bytes)
                   const struct ipv6_srh
                       *srh, // Pointer to the IPv6 Segment Routing Header (SRH)
                   const struct hmac_tlv *hmac_tlv, // Pointer to the HMAC TLV
                   uint8_t *key,                    // Pre-shared key
                   size_t key_len,    // Length of the pre-shared key
                   uint8_t *hmac_out) // Output buffer for the HMAC (32 bytes)
{
  // Input text buffer for HMAC computation
  size_t segment_list_len = sizeof(srh->segments);

  size_t input_len =
      16 + 1 + 1 + 2 + 4 + segment_list_len; // IPv6 Source + Last Entry + Flags
                                             // + Length + Key ID + Segment List

  uint8_t input[input_len];

  // Fill the input buffer
  size_t offset = 0;
  memcpy(input + offset, src_addr, 16); // IPv6 Source Address
  offset += 16;

  input[offset++] = srh->last_entry; // Last Entry
  input[offset++] = srh->flags;      // Flags (D-bit + Reserved)

  input[offset++] =
      0; // Placeholder for Length (2 bytes, can be zero for this step)
  input[offset++] = 0;

  memcpy(input + offset, &hmac_tlv->hmac_key_id,
         sizeof(hmac_tlv->hmac_key_id)); // HMAC Key ID
  offset += sizeof(hmac_tlv->hmac_key_id);

  memcpy(input + offset, srh->segments, segment_list_len); // Segment List
  offset += segment_list_len;

  // Perform HMAC computation using OpenSSL
  unsigned int hmac_len;
  uint8_t *digest =
      HMAC(EVP_sha256(), key, key_len, input, input_len, NULL, &hmac_len);

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
           HMAC_MAX_LENGTH - hmac_len); // Pad with zeros
  }

  return 0; // Success
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
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
  if (1 !=
      EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
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

int compare_hmac(struct hmac_tlv *hmac, uint8_t *hmac_out,
                 struct rte_mbuf *mbuf) {
  if (memcmp(hmac->hmac_value, hmac_out, HMAC_MAX_LENGTH) != 0) {
    printf("The decrypted hmac is not the same as the computed hmac\n");
    printf("dropping the packet\n");
    rte_pktmbuf_free(mbuf);
    return 0;
  } else {
    printf("The transit of the packet is verified\n");
    // forward it to the tap interface so iperf can catch it
    return 1;
  }
}