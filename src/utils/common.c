#include <rte_log.h>

#include "utils/common.h"

int operation_bypass_bit = 0;
int tsc_dynfield_offset = -1;

uint8_t k_pot_in[SID_NO][HMAC_MAX_LENGTH] = {
    // egress key (16 bytes), pad with zeros if HMAC_MAX_LENGTH > 16
    {0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x30, 0x4b, 0x6c, 0x7d, 0x8e, 0x9f, 0xa0,
     0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0},
    // transit key (16 bytes), pad with zeros if needed
    {0xd8, 0xf9, 0xcd, 0xe1, 0xab, 0x34, 0x5c, 0xd0, 0xef, 0x67, 0x89, 0xab, 0x12, 0xcd, 0xef, 0x34,
     0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0}};