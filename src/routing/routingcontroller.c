#include <stdio.h>
#include "routing/routecontroller.h"
#include "utils/common.h"
#include <arpa/inet.h>

void add_next_hop(const char *ipv6_str, const char *mac_str) {
  if (next_hop_count >= MAX_NEXT_HOPS) return;
  inet_pton(AF_INET6, ipv6_str, &next_hops[next_hop_count].ipv6);
  sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &next_hops[next_hop_count].mac.addr_bytes[0],
         &next_hops[next_hop_count].mac.addr_bytes[1], &next_hops[next_hop_count].mac.addr_bytes[2],
         &next_hops[next_hop_count].mac.addr_bytes[3], &next_hops[next_hop_count].mac.addr_bytes[4],
         &next_hops[next_hop_count].mac.addr_bytes[5]);
  next_hop_count++;
}

struct rte_ether_addr *lookup_mac_for_ipv6(struct in6_addr *ipv6) {
  for (int i = 0; i < next_hop_count; i++) {
    if (memcmp(&next_hops[i].ipv6, ipv6, sizeof(struct in6_addr)) == 0) return &next_hops[i].mac;
  }
  return NULL;
}