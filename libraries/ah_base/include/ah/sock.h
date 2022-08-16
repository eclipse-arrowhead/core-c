// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_SOCK_H_
#define AH_SOCK_H_

/// \brief BSD Socket utilities.
/// \file
///
/// The networking API for the BSD operating systems have become influential to
/// the degree that most operating systems today borrow the designs of their
/// networking APIs from it. To make it more straightforward to manage some of
/// the constructs of the BSD sockets API, some of its constructs are provided
/// here.
///
/// This file most significantly contain representations for <em>socket
/// addresses</em>, which unions over a set of supported address formats. The
/// file additionally contains relevant constants and functions for dealing with
/// such addresses.

#include "internal/_sock.h"
#include "ip.h"

#include <stdbool.h>

/// \brief The smallest number of bytes required to represent \e any socket
///        address as a human-readable string with a terminating \c NULL byte.
#define AH_SOCKADDR_ANY_STRLEN_MAX AH_SOCKADDR_IPV6_STRLEN_MAX

/// \brief The smallest number of bytes required to represent an IPv4-based
///        socket address as a human-readable string with a terminating \c NULL
///        byte.
#define AH_SOCKADDR_IPV4_STRLEN_MAX (AH_IPADDR_V4_STRLEN_MAX + 1u + 5u)

/// \brief The smallest number of bytes required to represent an IPv6-based
///        socket address as a human-readable string with a terminating \c NULL
///        byte.
#define AH_SOCKADDR_IPV6_STRLEN_MAX (1u + AH_IPADDR_V6_STRLEN_MAX + 3u + 10u + 1u + 1u + 5u)

/// \brief An integer identifying the IPv4 socket family.
#define AH_SOCKFAMILY_IPV4 AH_I_SOCKFAMILY_IPV4

/// \brief An integer identifying the IPv6 socket family.
#define AH_SOCKFAMILY_IPV6 AH_I_SOCKFAMILY_IPV6

#ifndef AH_SOCKFAMILY_DEFAULT
/// \brief An integer identifying the default socket family.
# define AH_SOCKFAMILY_DEFAULT AH_SOCKFAMILY_IPV4
#elif (AH_SOCKFAMILY_DEFAULT != AH_SOCKFAMILY_IPV4) && (AH_SOCKFAMILY_DEFAULT != AH_SOCKFAMILY_IPV6)
# error "AH_SOCKFAMILY_DEFAULT value is invalid; expected AH_SOCKFAMILY_IPV4 or AH_SOCKFAMILY_IPV6"
#endif

/// \brief Variant of ah_sockaddr that exposes struct members present on all
///        supported socket addresses.
struct ah_sockaddr_any {
#ifdef AH_DOXYGEN
    uintX_t size;   ///< \brief <b>[Darwin]</b> Byte size of this socket address.
    uintX_t family; ///< \brief The \e family of this socket address.
#else
    AH_I_SOCKADDR_COMMON
#endif
};

/// \brief Variant of ah_sockaddr that exposes struct members present on all
///        IP-based socket addresses.
struct ah_sockaddr_ip {
#ifdef AH_DOXYGEN
    uintX_t size;   ///< \brief <b>[Darwin]</b> Byte size of this socket address.
    uintX_t family; ///< \brief The \e family of this socket address.
#else
    AH_I_SOCKADDR_COMMON
#endif
    uint16_t port; ///< \brief UDP or TCP port number.
};

/// \brief Variant of ah_sockaddr representing an IPv4-based address.
struct ah_sockaddr_ipv4 {
#ifdef AH_DOXYGEN
    uintX_t size;   ///< \brief <b>[Darwin]</b> Byte size of this socket address.
    uintX_t family; ///< \brief The \e family of this socket address.
#else
    AH_I_SOCKADDR_COMMON
#endif
    uint16_t port;              ///< \brief UDP or TCP port number.
    struct ah_ipaddr_v4 ipaddr; ///< \brief IPv4 address.
#if AH_HAS_BSD_SOCKETS
    uint8_t zero[8u];
#endif
};

/// \brief Variant of ah_sockaddr representing an IPv6-based address.
struct ah_sockaddr_ipv6 {
#ifdef AH_DOXYGEN
    uintX_t size;   ///< \brief <b>[Darwin]</b> Byte size of this socket address.
    uintX_t family; ///< \brief The \e family of this socket address.
#else
    AH_I_SOCKADDR_COMMON
#endif
    uint16_t port; ///< \brief UDP or TCP port number.
#if AH_HAS_BSD_SOCKETS
    uint32_t flowinfo;
#endif
    struct ah_ipaddr_v6 ipaddr; ///< \brief IPv6 address.
    uint32_t zone_id;           ///< \brief IPv6 zone identifier.
};

/// \brief Union over all supported network address types.
union ah_sockaddr {
    ah_sockaddr_any_t as_any;   ///< \brief Holds fields valid for all variants.
    ah_sockaddr_ip_t as_ip;     ///< \brief Holds fields valid for all IP-based variants.
    ah_sockaddr_ipv4_t as_ipv4; ///< \brief IPv4-based address variant.
    ah_sockaddr_ipv6_t as_ipv6; ///< \brief IPv6-based address variant.
};

/// \brief The IPv4 loopback socket address.
///
/// \see https://www.rfc-editor.org/rfc/rfc5735#section-3
static const ah_sockaddr_ipv4_t ah_sockaddr_ipv4_loopback = {
    AH_I_SOCKADDR_PREAMBLE_IPV4 AH_SOCKFAMILY_IPV4, 0u, { { 127u, 0u, 0u, 1u } }, { 0u }
};

/// \brief The IPv4 wildcard (or \e "this") socket address.
///
/// \see https://www.rfc-editor.org/rfc/rfc5735#section-3
static const ah_sockaddr_ipv4_t ah_sockaddr_ipv4_wildcard = {
    AH_I_SOCKADDR_PREAMBLE_IPV4 AH_SOCKFAMILY_IPV4, 0u, { { 0u, 0u, 0u, 0u } }, { 0u }
};

/// \brief The IPv6 loopback socket address.
///
/// \see https://www.rfc-editor.org/rfc/rfc4291#section-2.5.3
static const ah_sockaddr_ipv6_t ah_sockaddr_ipv6_loopback = {
    AH_I_SOCKADDR_PREAMBLE_IPV6 AH_SOCKFAMILY_IPV6, 0u, 0u,
    { { 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u } }, 0u
};

/// \brief The IPv6 wildcard (or \e unspecified) socket address.
///
/// \see https://www.rfc-editor.org/rfc/rfc4291#section-2.5.2
static const ah_sockaddr_ipv6_t ah_sockaddr_ipv6_wildcard = {
    AH_I_SOCKADDR_PREAMBLE_IPV6 AH_SOCKFAMILY_IPV6, 0u, 0u,
    { { 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u } }, 0u
};

/// \brief Initializes \a sockaddr with given \a port number and \a ipaddr.
///
/// \param sockaddr Pointer to initialized socket address.
/// \param port     UDP or TCP port number.
/// \param ipaddr   IPv4 address.
/// \return <ul>
///   <li><b>AH_ENONE</b>  - \a sockaddr was successfully initialized.
///   <li><b>AH_EINVAL</b> - Either of \a sockaddr or \a ipaddr is \c NULL.
/// </ul>
ah_extern ah_err_t ah_sockaddr_init_ipv4(ah_sockaddr_t* sockaddr, uint16_t port, const ah_ipaddr_v4_t* ipaddr);

/// \brief Initializes \a sockaddr with given \a port number and \a ipaddr.
///
/// \param sockaddr Pointer to initialized socket address.
/// \param port     UDP or TCP port number.
/// \param ipaddr   IPv6 address.
/// \return <ul>
///   <li><b>AH_ENONE</b>  - \a sockaddr was successfully initialized.
///   <li><b>AH_EINVAL</b> - Either of \a sockaddr or \a ipaddr is \c NULL.
/// </ul>
ah_extern ah_err_t ah_sockaddr_init_ipv6(ah_sockaddr_t* sockaddr, uint16_t port, const ah_ipaddr_v6_t* ipaddr);

/// \brief Checks if \a sockaddr is an IP-based socket address.
///
/// \param sockaddr Pointer to socket address.
/// \return \c true only of \a sockaddr is not \c NULL and has an IP-based
///         socket family, such as IPv4 or IPv6.
ah_extern bool ah_sockaddr_is_ip(const ah_sockaddr_t* sockaddr);

/// \brief Checks if \a sockaddr is an IP-based socket address representing a
///        wildcard address.
///
/// \param sockaddr Pointer to socket address.
/// \return \c true only of \a sockaddr is not \c NULL, has an IP-based socket
///         family, such as IPv4 or IPv6, as well as holding an IP wildcard
///         address.
///
/// \see ah_ipaddr_v4_is_wildcard()
/// \see ah_ipaddr_v6_is_wildcard()
ah_extern bool ah_sockaddr_is_ip_wildcard(const ah_sockaddr_t* sockaddr);

/// \brief Checks if \a sockaddr is an IP-based socket and has a port number of
///        zero.
///
/// \param sockaddr Pointer to socket address.
/// \return \c true only of \a sockaddr is not \c NULL, has an IP-based socket
///         family, such as IPv4 or IPv6, as well as holding zero port.
ah_extern bool ah_sockaddr_is_ip_with_port_zero(const ah_sockaddr_t* sockaddr);

/// \brief Writes human-readable representation of \a sockaddr to \a dest.
///
/// If the representation does not fit in \a dest, \a dest is left unmodified.
///
/// \param sockaddr  Pointer to socket address.
/// \param dest      Pointer to buffer to receive stringification.
/// \param dest_size Size of \a dest, in bytes.
/// \return <ul>
///   <li><b>AH_ENONE</b>  - If the complete representation could be written to
///                          \a dest.
///   <li><b>AH_EINVAL</b> - If any of \a sockaddr, \a dest or \a dest_size is
///                          \c NULL.
///   <li><b>AH_ENOSPC</b> - If the representation would not fit in \a dest.
/// </ul>
///
/// \see ah_ipaddr_v4_stringify()
/// \see ah_ipaddr_v6_stringify()
ah_extern ah_err_t ah_sockaddr_stringify(const ah_sockaddr_t* sockaddr, char* dest, size_t* dest_size);

#endif
