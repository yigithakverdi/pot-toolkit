#include "core/pverify.h"

#include <stdio.h>

#include "utils/common.h"

int compare_hmac(struct hmac_tlv *hmac, uint8_t *hmac_out, struct rte_mbuf *mbuf) {
  if (memcmp(hmac->hmac_value, hmac_out, 32) != 0) {
    printf("The decrypted hmac is not the same as the computed hmac\n");
    printf("dropping the packet\n");
    rte_pktmbuf_free(mbuf);
    return 0;
  } else {
    printf("The transit of the packet is verified\n");
    return 1;
  }
}