#ifndef TRANSIT_H
#define TRANSIT_H

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
 * @brief Process transit packets and handle segment routing.
 *
 * This function is responsible for processing incoming transit packets in a DPDK-based
 * packet processing application. It primarily handles IPv6 packets with Segment Routing
 * Headers (SRH) and performs the following tasks:
 *
 * - Limits the packet length for processing (e.g., 64 bytes for dumping purposes).
 * - Retrieves the Ethernet header and normalizes the EtherType.
 * - Checks if the destination MAC is multicast and drops such packets.
 * - For IPv6 packets:
 *     - Extracts the IPv6 header and the subsequent SRH.
 *     - Validates key SRH fields (such as 'next_header' and 'routing_type').
 *     - Extracts TLV structures including embedded HMAC values.
 *     - Converts the destination IPv6 address to a human-readable string for logging.
 *     - Decrypts the HMAC and updates the associated TLV fields.
 *     - Verifies the existence of additional segments:
 *         - If segments remain, decrements the segments_left counter.
 *         - Updates the IPv6 destination address to the next segment value.
 *         - Resolves the next hop's MAC address via a lookup.
 *         - Forwards the packet if the lookup is successful.
 *         - Frees the packet if no segments remain or if errors occur during processing.
 *
 * @param pkts Array of pointers to rte_mbuf structures representing incoming packets.
 * @param nb_rx The number of packets in the pkts array.
 */
void process_transit(struct rte_mbuf **pkts, uint16_t nb_rx);

/**
 * process_transit - Processes an array of received packets.
 *
 * This function iterates over the provided array of packet pointers
 * and calls process_transit_packet for each packet.
 *
 * @pkts: Pointer to an array of rte_mbuf pointers containing the received packets.
 * @nb_rx: Number of packets in the pkts array.
 *
 * // Iterates over each packet in the array
 * // Calls process_transit_packet for each packet, passing the packet and its index
 */
static inline void process_transit_packet(struct rte_mbuf *mbuf, int i);
#endif // TRANSIT_H