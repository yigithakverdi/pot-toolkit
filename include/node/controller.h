#ifndef CONTROLLER_H
#define CONTROLLER_H

#include <netinet/in.h>   
#include <rte_ether.h>    

void add_next_hop(const char *ipv6_str, const char *mac_str);
struct rte_ether_addr *lookup_mac_for_ipv6(struct in6_addr *ipv6);

#endif // CONTROLLER_H