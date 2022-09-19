// SPDX-License-Identifier: EPL-2.0

#ifndef AH_IP_H_
#define AH_IP_H_

/**
 * Internet Protocol (IP) utilities.
 * @file
 *
 * The Internet Protocol serves as foundation for several other important
 * networking protocols, such as TCP (see tcp.h) and UDP (see udp.h). Extending
 * protocols use the IP addressing schema when specifying message recipients.
 *
 * This file provides structures, constants and functions useful for
 * representing and checking IP addresses.
 *
 * @see https://rfc-editor.org/rfc/rfc791.html
 * @see https://rfc-editor.org/rfc/rfc8200.html
 */
#include "defs.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/**
 * The smallest number of bytes required to represent @e any IPv4 address as a
 * human-readable string with a terminating @c NULL byte.
*/
#define AH_IPADDR_V4_STRLEN_MAX 16u

/**
 * The smallest number of bytes required to represent @e any IPv6 address as a
 * human readable string with a terminating @c NULL byte.
*/
#define AH_IPADDR_V6_STRLEN_MAX 46u

/** IPv4 address. */
struct ah_ipaddr_v4 {
    /** The octets, or bytes, constituting the address. */
    uint8_t octets[4];
};

/** IPv6 address. */
struct ah_ipaddr_v6 {
    /** The octets, or bytes, constituting the address. */
    uint8_t octets[16];
};

/**
 * The IPv4 loopback address.
 *
 * @see https://rfc-editor.org/rfc/rfc5735#section-3
 */
static const ah_ipaddr_v4_t ah_ipaddr_v4_loopback = {
    { 127u, 0u, 0u, 1u }
};

/**
 * The IPv4 wildcard (or @e "this") address.
 *
 * @see https://rfc-editor.org/rfc/rfc5735#section-3
 */
static const ah_ipaddr_v4_t ah_ipaddr_v4_wildcard = {
    { 0u, 0u, 0u, 0u },
};

/**
 * The IPv6 loopback address.
 *
 * @see https://rfc-editor.org/rfc/rfc4291#section-2.5.3
 */
static const ah_ipaddr_v6_t ah_ipaddr_v6_loopback = {
    { 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u },
};

/**
 * The IPv6 wildcard (or @e unspecified) address.
 *
 * @see https://rfc-editor.org/rfc/rfc4291#section-2.5.2
 */
static const ah_ipaddr_v6_t ah_ipaddr_v6_wildcard = {
    { 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u },
};

/**
 * Tests whether @a addr is the IPv4 loopback address.
 *
 * @param addr Pointer to tested address.
 * @return @c true only if @a addr is the IPv4 loopback address.
 *
 * @see https://rfc-editor.org/rfc/rfc5735#section-3
 */
ah_extern bool ah_ipaddr_v4_is_loopback(const ah_ipaddr_v4_t* addr);

/**
 * Tests whether @a addr is the IPv4 wildcard (or @e "this") address.
 *
 * @param addr Pointer to tested address.
 * @return @c true only if @a addr is the IPv4 wildcard address.
 *
 * @see https://rfc-editor.org/rfc/rfc5735#section-3
 */
ah_extern bool ah_ipaddr_v4_is_wildcard(const ah_ipaddr_v4_t* addr);

/**
 * Tests whether @a addr is the IPv6 loopback address.
 *
 * @param addr Pointer to tested address.
 * @return @c true only if @a addr is the IPv6 loopback address.
 *
 * @see https://rfc-editor.org/rfc/rfc4291#section-2.5.3
 */
ah_extern bool ah_ipaddr_v6_is_loopback(const ah_ipaddr_v6_t* addr);

/**
 * Tests whether @a addr is the IPv6 wildcard (or @e unspecified)
 *        address.
 *
 * @param addr Pointer to tested address.
 * @return @c true only if @a addr is the IPv6 wildcard address.
 *
 * @see https://rfc-editor.org/rfc/rfc4291#section-2.5.2
 */
ah_extern bool ah_ipaddr_v6_is_wildcard(const ah_ipaddr_v6_t* addr);

/**
 * Writes dot-decimal representation of @a addr and a @c NULL terminator to
 * @a dest.
 *
 * If the representation does not fit in @a dest, @a dest is left unmodified.
 *
 * @param addr Pointer to IPv4 address.
 * @param dest Pointer to buffer to receive stringification.
 * @param dest_size Size of @a dest, in bytes.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE     - If the complete representation could be written to @a dest.
 *   <li>@ref AH_EINVAL    - If any of @a addr, @a dest or @a dest_size is @c NULL.
 *   <li>@ref AH_EOVERFLOW - If the representation would not fit in @a dest.
 * </ul>
 *
 * @see https://datatracker.ietf.org/doc/html/rfc1123#section-2.1
 */
ah_extern ah_err_t ah_ipaddr_v4_stringify(const struct ah_ipaddr_v4* addr, char* dest, size_t* dest_size);

/**
 * Writes RFC 4291 representation of @a addr to @a dest.
 *
 * If the representation does not fit in @a dest, @a dest is left unmodified.
 *
 * @param addr Pointer to IPv6 address.
 * @param dest Pointer to buffer to receive stringification.
 * @param dest_size Size of @a dest, in bytes.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE     - If the complete representation could be written to @a dest.
 *   <li>@ref AH_EINVAL    - If any of @a addr, @a dest or @a dest_size is @c NULL.
 *   <li>@ref AH_EOVERFLOW - If the representation would not fit in @a dest.
 * </ul>
 *
 * @see https://rfc-editor.org/rfc/rfc4291#section-2.2
 */
ah_extern ah_err_t ah_ipaddr_v6_stringify(const struct ah_ipaddr_v6* addr, char* dest, size_t* dest_size);

#endif
