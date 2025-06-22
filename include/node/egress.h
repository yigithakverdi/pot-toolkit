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
 * @brief Processes an egress packet contained within the provided mbuf.
 *
 * This function carries out multiple operations on the specified packet buffer (mbuf) to prepare
 * and forward a packet exiting the node. The operations executed include:
 *
 * - Displaying an initial hex dump of the packet (e.g., the first 64 bytes) for debugging.
 * - Logging key attributes such as packet length, the number of segments, and tailroom.
 * - Extracting and processing Ethernet and IPv6 headers if the packet is an IPv6 packet.
 * - Detecting the presence of a Segment Routing Header (SRH) and, if found:
 *   - Logging the SRH and associated TLVs (e.g., HMAC and POT TLVs) in hexadecimal for debugging.
 *   - Decrypting a Packet Validation Field (PVF) using an encryption key, and verifying it against an expected HMAC.
 *   - Handling any failures (e.g., decryption or HMAC verification failure) by dropping the packet.
 * - Removing protocol-specific headers after successful verification.
 * - Forwarding the packet to the configured destination (e.g., an iperf server) with appropriate logging.
 *
 * @param mbuf Pointer to a struct rte_mbuf representing the packet to be processed.
 *
 * @note The function uses an operational bypass flag to decide whether to fully process the packet or
 * simply bypass the operational logic.
 *
 * @warning In case of errors (such as network address translation or HMAC mismatches), the packet is dropped,
 * and the mbuf is freed.
 */
static inline void process_egress_packet(struct rte_mbuf *mbuf);


/**
 * @brief Processes an array of packets for egress.
 *
 * This function iterates through the provided array of packet buffers and processes each packet
 * for egress using the process_egress_packet function.
 *
 * @param pkts Pointer to an array of packet buffers.
 * @param nb_rx The number of packets (buffers) in the array.
 */
static inline void process_egress(struct rte_mbuf **pkts, uint16_t nb_rx);

#endif // TRANSIT_H