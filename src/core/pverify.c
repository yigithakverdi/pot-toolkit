#include "core/pverify.h"

#include <stdio.h>

#include "utils/common.h"
#include "utils/logging.h"

int compare_hmac(struct hmac_tlv *hmac, uint8_t *hmac_out, struct rte_mbuf *mbuf) {
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