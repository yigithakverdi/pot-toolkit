#include <stdint.h>

#define HMAC_MAX_LENGTH 32


struct ipv6_srh {
    uint8_t next_header;
    uint8_t hdr_ext_len;
    uint8_t routing_type;
    uint8_t segments_left;
    uint8_t flags;
    uint8_t tag[3];
    uint8_t reserved[3];
    uint8_t segments[0];
};