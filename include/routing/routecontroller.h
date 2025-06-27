#ifndef ROUTECONTROLLER_H
#define ROUTECONTROLLER_H

#include <netinet/in.h>   // For struct in6_addr
#include <rte_ether.h>    // For struct rte_ether_addr

void add_next_hop(const char *ipv6_str, const char *mac_str);
struct rte_ether_addr *lookup_mac_for_ipv6(struct in6_addr *ipv6);

#endif // ROUTECONTROLLER_H