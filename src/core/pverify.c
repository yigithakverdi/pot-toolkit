#include "core/pverify.h"

#include <stdio.h>

#include "utils/common.h"

int compare_hmac(struct hmac_tlv *hmac, uint8_t *hmac_out, struct rte_mbuf *mbuf) {
  if (memcmp(hmac->hmac_value, hmac_out, 32) != 0) {
    rte_pktmbuf_free(mbuf);
    return 0;
  } else {
    return 1;
  }
}