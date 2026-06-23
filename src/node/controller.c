#include <arpa/inet.h>
#include <stdio.h>

#include "node/controller.h"
#include "utils/logging.h"
#include "headers.h"

int g_node_index = -1;

#define PRIME 53ULL // Using the small prime from the IETF draft example

typedef struct {
    uint64_t x;             // Node's public ID / X-coordinate
    uint64_t share_poly1;   // Node's secret Y-coordinate share
    uint64_t lpc;           // Node's calculated weighting factor
} pot_node_profile_t;

// Standard Extended Euclidean Algorithm to calculate modular inverse: (1 / a) mod m
uint64_t mod_inverse(int64_t a, int64_t m) {
    int64_t m0 = m, t, q;
    int64_t x0 = 0, x1 = 1;

    if (m == 1) return 0;

    while (a > 1) {
        q = a / m;
        t = m;
        m = a % m;
        a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    if (x1 < 0) x1 += m0;
    return (uint64_t)x1;
}

// Central Provisioning Function
void provision_pot_path(uint64_t secret, uint64_t* x_coords, int num_nodes, pot_node_profile_t* profiles) {
    // Hardcoded polynomial coefficients for POLY-1: 3x^2 + 3x + secret
    uint64_t coeff_a = 3;
    uint64_t coeff_b = 3;

    // 1. Generate Secret Shares (Y-coordinates) for each node
    for (int i = 0; i < num_nodes; i++) {
        uint64_t x = x_coords[i];
        profiles[i].x = x;

        // Evaluate POLY-1(x) = (a*x^2 + b*x + secret) mod PRIME
        uint64_t term1 = (coeff_a * ((x * x) % PRIME)) % PRIME;
        uint64_t term2 = (coeff_b * x) % PRIME;
        profiles[i].share_poly1 = (term1 + term2 + secret) % PRIME;
    }

    // 2. Calculate Lagrange Polynomial Constants (LPC weights) for each node
    for (int i = 0; i < num_nodes; i++) {
        uint64_t lpc = 1;

        for (int j = 0; j < num_nodes; j++) {
            if (i == j) continue; // Skip matching node

            uint64_t num = x_coords[j];
            uint64_t den;

            // Handle modular subtraction to prevent negative underflow
            if (x_coords[j] >= x_coords[i]) {
                den = x_coords[j] - x_coords[i];
            } else {
                den = PRIME - (x_coords[i] - x_coords[j]);
            }

            // Term = (num * (1 / den)) mod PRIME
            uint64_t inv_den = mod_inverse(den, PRIME);
            uint64_t term = (num * inv_den) % PRIME;

            // Accumulate into total LPC weight for this node
            lpc = (lpc * term) % PRIME;
        }
        profiles[i].lpc = lpc;
    }
}

void add_next_hop(const char* ipv6_str, const char* mac_str) {
  // Check if the maximum number of next hops has been reached.
  // If so, log a warning and return to prevent buffer overflow.
  if (next_hop_count >= MAX_NEXT_HOPS) {
    LOG_MAIN(WARNING, "Cannot add next hop: MAX_NEXT_HOPS (%d) reached.\n", MAX_NEXT_HOPS);
    return;
  }

  // Convert the IPv6 address string (e.g., "fe80::1") into its binary representation
  // and store it in the next_hops array at the current count.
  // inet_pton() returns 1 on success.
  if (inet_pton(AF_INET6, ipv6_str, &next_hops[next_hop_count].ipv6) != 1) {
    LOG_MAIN(ERR, "Failed to convert IPv6 string '%s' to binary address.\n", ipv6_str);
    return;
  }

  // Convert the MAC address string (e.g., "00:11:22:33:44:55") into its binary representation
  // and store it in the next_hops array.
  // sscanf() parses the hexadecimal bytes separated by colons.
  // %hhx reads a single byte as a hexadecimal value.
  sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n", &next_hops[next_hop_count].mac.addr_bytes[0],
         &next_hops[next_hop_count].mac.addr_bytes[1], &next_hops[next_hop_count].mac.addr_bytes[2],
         &next_hops[next_hop_count].mac.addr_bytes[3], &next_hops[next_hop_count].mac.addr_bytes[4],
         &next_hops[next_hop_count].mac.addr_bytes[5]);

  // Increment the count of registered next hops.
  LOG_MAIN(INFO, "Added next hop: IPv6 %s, MAC %s. Total next hops: %d.\n", ipv6_str, mac_str,
           next_hop_count + 1);
  next_hop_count++;
}

struct rte_ether_addr* lookup_mac_for_ipv6(struct in6_addr* ipv6) {
  LOG_MAIN(DEBUG, "Looking up MAC for IPv6 address %s...\n",
           inet_ntop(AF_INET6, ipv6, (char[INET6_ADDRSTRLEN]){0}, INET6_ADDRSTRLEN));

  for (int i = 0; i < next_hop_count; i++) {

    // Compare the target IPv6 address with each stored IPv6 address in the next_hops array.
    // memcmp() performs a byte-by-byte comparison.
    // If the addresses match (memcmp returns 0), the corresponding MAC address is found.
    if (memcmp(&next_hops[i].ipv6, ipv6, sizeof(struct in6_addr)) == 0) {
      LOG_MAIN(DEBUG, "Found MAC %02x:%02x:%02x:%02x:%02x:%02x for IPv6 %s.\n",
               next_hops[i].mac.addr_bytes[0], next_hops[i].mac.addr_bytes[1], next_hops[i].mac.addr_bytes[2],
               next_hops[i].mac.addr_bytes[3], next_hops[i].mac.addr_bytes[4], next_hops[i].mac.addr_bytes[5],
               inet_ntop(AF_INET6, ipv6, (char[INET6_ADDRSTRLEN]){0}, INET6_ADDRSTRLEN));
      return &next_hops[i].mac;
    }
  }

  // If the loop completes without finding a matching IPv6 address, return NULL.
  // This indicates that no corresponding MAC address is registered for the given IPv6.
  LOG_MAIN(WARNING, "No MAC found for IPv6 address %s.\n",
           inet_ntop(AF_INET6, ipv6, (char[INET6_ADDRSTRLEN]){0}, INET6_ADDRSTRLEN));
  return NULL;
}
