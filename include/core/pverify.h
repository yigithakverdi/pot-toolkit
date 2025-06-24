#ifndef PVERIFY_H
#define PVERIFY_H

#include <stdint.h>
#include "utils/common.h"

int compare_hmac(struct hmac_tlv *hmac, uint8_t *hmac_out, struct rte_mbuf *mbuf);

#endif // PVERIFY_H