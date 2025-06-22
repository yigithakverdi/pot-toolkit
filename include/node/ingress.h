#ifndef INGRESS_H
#define INGRESS_H

#include <arpa/inet.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include <rte_mbuf_dyn.h>
#include <stdalign.h>
#include <stdint.h>


/**
 * @brief Processes incoming packets on the ingress role.
 *
 * This function iterates over an array of received packets and processes each packet
 * by calling process_ingress_packet() with the packet and the receiving port identifier.
 *
 * @param pkts Array of pointers to rte_mbuf structures representing the received packets.
 * @param nb_rx The number of packets in the pkts array.
 * @param rx_port_id The identifier of the ingress port from which the packets were received.
 */
static inline void process_ingress(struct rte_mbuf **pkts, uint16_t nb_rx, uint16_t rx_port_id);


/**
 * @brief Processes an incoming packet on an ingress port.
 *
 * This function inspects and processes a packet contained in an rte_mbuf structure.
 * It performs the following operations:
 *  - Prints an initial hex dump, packet length, segment count, and tailroom/data length details.
 *  - Determines if the packet is an IPv6 packet based on the Ethernet header:
 *      - If the packet is not IPv6, the packet is logged and freed.
 *  - Checks if the destination MAC address is a multicast or broadcast address:
 *      - If so, additional packet details (including IPv6 and UDP/TCP header info) are printed and
 *        the packet is subsequently dropped.
 *  - For IPv6 packets, the function behavior depends on an operation bypass flag:
 *      - Case 0:
 *          - Adds a custom header to the packet.
 *          - Realigns header pointers and prints offsets for the Segment Routing Header (SRH),
 *            HMAC TLV, and POT TLV.
 *          - Extracts and prints the destination IPv6 address.
 *          - Computes an HMAC using a forced ingress IPv6 address and packet data, then embeds the
 *            computed HMAC into the SRH.
 *          - Generates a nonce and encrypts a PVF that is inserted into the POT TLV.
 *          - Determines the next-hop information by updating the IPv6 header's destination address,
 *            resolving the next-hop MAC address, and finally forwarding the packet.
 *      - Case 1:
 *          - Bypasses all processing operations.
 *      - Case 2:
 *          - Adds the custom header only.
 *
 * @param mbuf Pointer to the rte_mbuf structure that holds the packet to be processed.
 * @param rx_port_id The identifier for the ingress port on which the packet was received.
 */
static inline void process_ingress_packet(struct rte_mbuf *mbuf, uint16_t rx_port_id);

#endif // INGRESS_H