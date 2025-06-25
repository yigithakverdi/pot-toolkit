#include "utils/debug.h"

#include <arpa/inet.h>
#include <inttypes.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <stdint.h>
#include <sys/socket.h>

void hex_dump(const void *data, size_t size) {
  printf("!!!!! ");
  const unsigned char *p = data;
  for (size_t i = 0; i < size; i++) {
    printf("%02x ", p[i]);
    if ((i + 1) % 16 == 0) printf("\n");
  }
  if (size % 16 != 0) printf("\n");
}

// Utility: Print offset and hex for a structure
void print_offset_and_hex(const char *label, const void *base, const void *ptr, size_t len) {
  printf("!!!!! ");
  // printf("%s offset: %ld\n", label, (const uint8_t *)ptr - (const uint8_t *)base);
  // printf("%s hex dump:\n", label);
  // hex_dump(ptr, len);
}

void print_ipv6_address(const struct in6_addr *ipv6_addr, const char *label) {
  printf("!!!!! ");
  char addr_str[INET6_ADDRSTRLEN];  // Buffer for human-readable address

  // Convert the IPv6 binary address to a string
  if (inet_ntop(AF_INET6, ipv6_addr, addr_str, sizeof(addr_str)) != NULL) {
    printf("%s: %s\n", label, addr_str);
  } else {
    perror("inet_ntop");
  }
}

// Prints a human-readable IPv4 address with a label for context, converting the given 32-bit
// address to dotted-decimal notation and displaying it alongside the provided label; if the conversion
// fails, an error message is printed.
void print_ipv4_address(uint32_t ipv4_addr, const char *label) {
  printf("!!!!! ");
  struct in_addr addr;
  addr.s_addr = ipv4_addr;
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &addr, buf, sizeof(buf)) != NULL) {
    // RTE_LOG(INFO, USER1, "%s: %s\n", label, buf);
  } else {
    // RTE_LOG(ERR, USER1, "inet_ntop failed: %s\n", strerror(errno));
  }
}