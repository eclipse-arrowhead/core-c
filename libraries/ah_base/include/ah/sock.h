// SPDX-License-Identifier: EPL-2.0

#ifndef AH_SOCK_H_
#define AH_SOCK_H_

/**
 * @file
 * BSD Socket utilities.
 *
 * The networking API for the BSD operating systems have become influential to
 * the degree that most operating systems today borrow the designs of their
 * networking APIs from it. To make it more straightforward to manage some of
 * the constructs of the BSD sockets API, some of its constructs are provided
 * here.
 *
 * This file most significantly contain representations for <em>socket
 * addresses</em>, which unions over a set of supported address formats. The
 * file additionally contains relevant constants and functions for dealing with
 * such addresses.
 */

#include "internal/_sock.h"
#include "ip.h"

#include <stdbool.h>

/**
 * The smallest number of bytes required to represent @e any socket address as a
 * human-readable string with a terminating @c NULL byte.
 */
#define AH_SOCKADDR_ANY_STRLEN_MAX AH_SOCKADDR_IPV6_STRLEN_MAX

/**
 * The smallest number of bytes required to represent an IPv4-based socket
 * address as a human-readable string with a terminating @c NULL byte.
 */
#define AH_SOCKADDR_IPV4_STRLEN_MAX (AH_IPADDR_V4_STRLEN_MAX + 1u + 5u)

/**
 * The smallest number of bytes required to represent an IPv6-based socket
 * address as a human-readable string with a terminating @c NULL byte.
 */
#define AH_SOCKADDR_IPV6_STRLEN_MAX (1u + AH_IPADDR_V6_STRLEN_MAX + 3u + 10u + 1u + 1u + 5u)

/** An integer identifying the IPv4 socket family. */
#define AH_SOCKFAMILY_IPV4 AH_I_SOCKFAMILY_IPV4

/** An integer identifying the IPv6 socket family. */
#define AH_SOCKFAMILY_IPV6 AH_I_SOCKFAMILY_IPV6

/**
 * Variant of ah_sockaddr that exposes struct fields present on all supported
 * socket address types.
 */
struct ah_sockaddr_any {
#ifdef AH_DOXYGEN
    uintX_t size;   /**< <b>[Darwin]</b> Byte size of this socket address. */
    uintX_t family; /**< The @e family of this socket address. */
#else
    AH_I_SOCKADDR_COMMON
#endif
};

/**
 * Variant of ah_sockaddr that exposes struct fields present on all IP-based
 * socket address types.
 */
struct ah_sockaddr_ip {
#ifdef AH_DOXYGEN
    uintX_t size;   /**< <b>[Darwin]</b> Byte size of this socket address. */
    uintX_t family; /**< The @e family of this socket address. */
#else
    AH_I_SOCKADDR_COMMON
#endif
    uint16_t port; /**< UDP or TCP port number. */
};

/** Variant of ah_sockaddr representing an IPv4-based address. */
struct ah_sockaddr_ipv4 {
#ifdef AH_DOXYGEN
    uintX_t size;   /**< <b>[Darwin]</b> Byte size of this socket address. */
    uintX_t family; /**< The @e family of this socket address. */
#else
    AH_I_SOCKADDR_COMMON
#endif
    uint16_t port;              /**< UDP or TCP port number. */
    struct ah_ipaddr_v4 ipaddr; /**< IPv4 address. */
#if AH_HAS_BSD_SOCKETS || defined(AH_DOXYGEN)
    uint8_t zero[8u]; /**< <b>[BSD Sockets]</b> Zero padding. */
#endif
};

/** Variant of ah_sockaddr representing an IPv6-based address. */
struct ah_sockaddr_ipv6 {
#ifdef AH_DOXYGEN
    uintX_t size;   /**< <b>[Darwin]</b> Byte size of this socket address. */
    uintX_t family; /**< The @e family of this socket address. */
#else
    AH_I_SOCKADDR_COMMON
#endif
    uint16_t port; /**< UDP or TCP port number. */
#if AH_HAS_BSD_SOCKETS || defined(AH_DOXYGEN)
    uint32_t flowinfo; /**< <b>[BSD Sockets]</b> Flow information (unused). */
#endif
    struct ah_ipaddr_v6 ipaddr; /**< IPv6 address. */
    uint32_t zone_id;           /**< IPv6 zone identifier. */
};

/** Union over all supported network address types. */
union ah_sockaddr {
    ah_sockaddr_any_t as_any;   /**< Holds fields valid for all variants. */
    ah_sockaddr_ip_t as_ip;     /**< Holds fields valid for all IP-based variants. */
    ah_sockaddr_ipv4_t as_ipv4; /**< IPv4-based address variant. */
    ah_sockaddr_ipv6_t as_ipv6; /**< IPv6-based address variant. */
};

/**
 * The IPv4 loopback socket address.
 *
 * @see https://www.rfc-editor.org/rfc/rfc5735#section-3
 */
static const ah_sockaddr_ipv4_t ah_sockaddr_ipv4_loopback = {
    AH_I_SOCKADDR_PREAMBLE_IPV4 AH_SOCKFAMILY_IPV4, 0u, { { 127u, 0u, 0u, 1u } }, { 0u }
};

/**
 * The IPv4 wildcard (or @e "this") socket address.
 *
 * @see https://www.rfc-editor.org/rfc/rfc5735#section-3
 */
static const ah_sockaddr_ipv4_t ah_sockaddr_ipv4_wildcard = {
    AH_I_SOCKADDR_PREAMBLE_IPV4 AH_SOCKFAMILY_IPV4, 0u, { { 0u, 0u, 0u, 0u } }, { 0u }
};

/**
 * The IPv6 loopback socket address.
 *
 * @see https://www.rfc-editor.org/rfc/rfc4291#section-2.5.3
 */
static const ah_sockaddr_ipv6_t ah_sockaddr_ipv6_loopback = {
    AH_I_SOCKADDR_PREAMBLE_IPV6 AH_SOCKFAMILY_IPV6, 0u, 0u,
    { { 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u } }, 0u
};

/**
 * The IPv6 wildcard (or @e unspecified) socket address.
 *
 * @see https://www.rfc-editor.org/rfc/rfc4291#section-2.5.2
 */
static const ah_sockaddr_ipv6_t ah_sockaddr_ipv6_wildcard = {
    AH_I_SOCKADDR_PREAMBLE_IPV6 AH_SOCKFAMILY_IPV6, 0u, 0u,
    { { 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u } }, 0u
};

/**
 * Initializes @a sockaddr with given @a port number and @a ipaddr.
 *
 * @param sockaddr Pointer to initialized socket address.
 * @param port     UDP or TCP port number.
 * @param ipaddr   IPv4 address.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE  - @a sockaddr was successfully initialized.
 *   <li>@ref AH_EINVAL - Either of @a sockaddr or @a ipaddr is @c NULL.
 * </ul>
 */
ah_extern ah_err_t ah_sockaddr_init_ipv4(ah_sockaddr_t* sockaddr, uint16_t port, const ah_ipaddr_v4_t* ipaddr);

/**
 * Initializes @a sockaddr with given @a port number and @a ipaddr.
 *
 * @param sockaddr Pointer to initialized socket address.
 * @param port     UDP or TCP port number.
 * @param ipaddr   IPv6 address.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE  - @a sockaddr was successfully initialized.
 *   <li>@ref AH_EINVAL - Either of @a sockaddr or @a ipaddr is @c NULL.
 * </ul>
 */
ah_extern ah_err_t ah_sockaddr_init_ipv6(ah_sockaddr_t* sockaddr, uint16_t port, const ah_ipaddr_v6_t* ipaddr);

/**
 * Checks if @a sockaddr is an IP-based socket address.
 *
 * @param sockaddr Pointer to socket address.
 * @return @c true only of @a sockaddr is not @c NULL and has an IP-based
 *         socket family, such as IPv4 or IPv6.
 */
ah_extern bool ah_sockaddr_is_ip(const ah_sockaddr_t* sockaddr);

/**
 * Checks if @a sockaddr is an IP-based socket address representing a wildcard
 * address.
 *
 * @param sockaddr Pointer to socket address.
 * @return @c true only of @a sockaddr is not @c NULL, has an IP-based socket
 *         family, such as IPv4 or IPv6, as well as holding an IP wildcard
 *         address.
 *
 * @see ah_ipaddr_v4_is_wildcard()
 * @see ah_ipaddr_v6_is_wildcard()
 */
ah_extern bool ah_sockaddr_is_ip_wildcard(const ah_sockaddr_t* sockaddr);

/**
 * Checks if @a sockaddr is an IP-based socket and has a port number of zero.
 *
 * @param sockaddr Pointer to socket address.
 * @return @c true only of @a sockaddr is not @c NULL, has an IP-based socket
 *         family, such as IPv4 or IPv6, as well as holding zero port.
 */
ah_extern bool ah_sockaddr_is_ip_with_port_zero(const ah_sockaddr_t* sockaddr);

/**
 * Writes human-readable representation of @a sockaddr to @a dest.
 *
 * If the representation does not fit in @a dest, @a dest is left unmodified.
 *
 * @param sockaddr  Pointer to socket address.
 * @param dest      Pointer to buffer to receive stringification.
 * @param dest_size Size of @a dest, in bytes.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE     - If the complete representation could be written to @a dest.
 *   <li>@ref AH_EINVAL    - If any of @a sockaddr, @a dest or @a dest_size is @c NULL.
 *   <li>@ref AH_EOVERFLOW - If the representation would not fit in @a dest.
 * </ul>
 *
 * @see ah_ipaddr_v4_stringify()
 * @see ah_ipaddr_v6_stringify()
 */
ah_extern ah_err_t ah_sockaddr_stringify(const ah_sockaddr_t* sockaddr, char* dest, size_t* dest_size);

#endif
