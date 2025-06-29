#include <arpa/inet.h>
#include <stdio.h>

#include "routing/routecontroller.h"
#include "utils/logging.h"
#include "utils/common.h"

void add_next_hop(const char *ipv6_str, const char *mac_str) {
  // Check if the maximum number of next hops has been reached.
  // If so, log a warning and return to prevent buffer overflow.
  if (next_hop_count >= MAX_NEXT_HOPS) {
    LOG_MAIN(WARNING, "Cannot add next hop: MAX_NEXT_HOPS (%d) reached.", MAX_NEXT_HOPS);
    return;
  }

  // Convert the IPv6 address string (e.g., "fe80::1") into its binary representation
  // and store it in the next_hops array at the current count.
  // inet_pton() returns 1 on success.
  if (inet_pton(AF_INET6, ipv6_str, &next_hops[next_hop_count].ipv6) != 1) {
    LOG_MAIN(ERR, "Failed to convert IPv6 string '%s' to binary address.", ipv6_str);
    return;
  }

  // Convert the MAC address string (e.g., "00:11:22:33:44:55") into its binary representation
  // and store it in the next_hops array.
  // sscanf() parses the hexadecimal bytes separated by colons.
  // %hhx reads a single byte as a hexadecimal value.
  sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &next_hops[next_hop_count].mac.addr_bytes[0],
         &next_hops[next_hop_count].mac.addr_bytes[1], &next_hops[next_hop_count].mac.addr_bytes[2],
         &next_hops[next_hop_count].mac.addr_bytes[3], &next_hops[next_hop_count].mac.addr_bytes[4],
         &next_hops[next_hop_count].mac.addr_bytes[5]);

  // Increment the count of registered next hops.
  LOG_MAIN(INFO, "Added next hop: IPv6 %s, MAC %s. Total next hops: %d.", ipv6_str, mac_str,
           next_hop_count + 1);  
  next_hop_count++;
}

struct rte_ether_addr *lookup_mac_for_ipv6(struct in6_addr *ipv6) {
  LOG_MAIN(DEBUG, "Looking up MAC for IPv6 address %s...",
           inet_ntop(AF_INET6, ipv6, (char[INET6_ADDRSTRLEN]){0},
                     INET6_ADDRSTRLEN));

  for (int i = 0; i < next_hop_count; i++) {

    // Compare the target IPv6 address with each stored IPv6 address in the next_hops array.
    // memcmp() performs a byte-by-byte comparison.
    // If the addresses match (memcmp returns 0), the corresponding MAC address is found.
    if (memcmp(&next_hops[i].ipv6, ipv6, sizeof(struct in6_addr)) == 0) {
      LOG_MAIN(DEBUG, "Found MAC %02x:%02x:%02x:%02x:%02x:%02x for IPv6 %s.", next_hops[i].mac.addr_bytes[0],
               next_hops[i].mac.addr_bytes[1], next_hops[i].mac.addr_bytes[2], next_hops[i].mac.addr_bytes[3],
               next_hops[i].mac.addr_bytes[4], next_hops[i].mac.addr_bytes[5],
               inet_ntop(AF_INET6, ipv6, (char[INET6_ADDRSTRLEN]){0}, INET6_ADDRSTRLEN));
      return &next_hops[i].mac;
    }
  }

  // If the loop completes without finding a matching IPv6 address, return NULL.
  // This indicates that no corresponding MAC address is registered for the given IPv6.
  LOG_MAIN(WARNING, "No MAC found for IPv6 address %s.",
           inet_ntop(AF_INET6, ipv6, (char[INET6_ADDRSTRLEN]){0}, INET6_ADDRSTRLEN));
  return NULL;
}

struct rte_ether_addr *lookup_mac_for_ipv6(struct in6_addr *ipv6) {
  LOG_MAIN(DEBUG, "Looking up MAC for IPv6 address %s...",
           inet_ntop(AF_INET6, ipv6, (char[INET6_ADDRSTRLEN]){0}, INET6_ADDRSTRLEN));
  for (int i = 0; i < next_hop_count; i++) {
    LOG_MAIN(DEBUG, "Checking next hop %d: IPv6 %s",
             i, inet_ntop(AF_INET6, &next_hops[i].ipv6, (char[INET6_ADDRSTRLEN]){0}, INET6_ADDRSTRLEN));
    if (memcmp(&next_hops[i].ipv6, ipv6, sizeof(struct in6_addr)) == 0) return &next_hops[i].mac;
  }
  return NULL;
}