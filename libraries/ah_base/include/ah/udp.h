// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_UDP_H_
#define AH_UDP_H_

/// \brief User Datagram Protocol (UDP) utilities.
/// \file
///
/// Here, the data structures and functions required to setup and send messages
/// using the UDP/IP protocol are made available. Such messages are both sent
/// and received using TCP sockets.
///
/// \note When we use the terms \e remote and \e local throughout this file, we
///       do so from the perspective of individual sockets rather than complete
///       devices. In other words, when we consider a certain socket, that
///       socket is local and whatever other socket it may communicate with is
///       remote.

#include "buf.h"
#include "internal/_udp.h"
#include "sock.h"

#include <stdbool.h>

/// \brief A UDP/IPv4 multicast group.
///
/// \see \see https://www.rfc-editor.org/rfc/rfc1112.html
struct ah_udp_group_ipv4 {
    /// \brief The address of the multicast group.
    ///
    /// \see https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml
    ah_ipaddr_v4_t group_addr;

    /// \brief The address of the local network interface through which the
    ///        multicast group is to be communicated with.
    ///
    /// If set to the wildcard address (all zeroes), all available local network
    /// interfaces may be used.
    ah_ipaddr_v4_t interface_addr;
};

/// \brief A UDP/IPv6 multicast group.
///
/// \see https://datatracker.ietf.org/doc/html/rfc3306
/// \see https://datatracker.ietf.org/doc/html/rfc7371
struct ah_udp_group_ipv6 {
    /// \brief The address of the multicast group.
    ///
    /// \see https://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xhtml
    ah_ipaddr_v6_t group_addr;

    /// \brief The index of the local network interface through which the
    ///        multicast group is to be communicated with.
    ///
    /// If set to zero, all available local network interfaces may be used.
    uint32_t zone_id;
};

/// \brief Union over all supported types of UDP multicast groups.
///
/// \warning There is no way of determining what kind of group is being used
///          from looking at an instance of this data structure in isolation.
union ah_udp_group {
    ah_udp_group_ipv4_t as_ipv4; ///< \brief Access as IPv4 group.
    ah_udp_group_ipv6_t as_ipv6; ///< \brief Access as IPv6 group.
};

/// \brief A UDP-based message transport.
///
/// A \e transport represents a medium through which UDP messages can be sent or
/// received. Such a medium could be a plain connection via an underlying
/// operating system, a DTLS layer on top of a plain socket, etc.
struct ah_udp_trans {
    /// \brief Virtual function table used to interact with transport medium.
    const ah_udp_vtab_t* vtab;

    /// \brief Pointer to whatever context is needed by the transport.
    void* ctx;
};

/// \brief Virtual function table for UDP-based transports.
///
/// A set of function pointers representing the UDP functions that must be
/// implemented by every valid transport (see ah_udp_trans). The functions must
/// behave as documented by the regular functions they are named after. Each of
/// them takes a void pointer \c ctx argument, which corresponds to the
/// ah_udp_trans::ctx member of the transport owning the function table in
/// question.
///
/// \note This structure is primarily useful to those wishing to implement their
///       own UDP transports.
struct ah_udp_vtab {
    ah_err_t (*sock_open)(void* ctx, ah_udp_sock_t* sock, const ah_sockaddr_t* laddr);
    ah_err_t (*sock_recv_start)(void* ctx, ah_udp_sock_t* sock);
    ah_err_t (*sock_recv_stop)(void* ctx, ah_udp_sock_t* sock);
    ah_err_t (*sock_send)(void* ctx, ah_udp_sock_t* sock, ah_udp_out_t* out);
    ah_err_t (*sock_close)(void* ctx, ah_udp_sock_t* sock);
};

/// \brief A TCP socket handle.
///
/// Such a handle can be used to both send and/or receive UDP datagrams
/// (messages).
///
/// \note All members of this data structure are \e private in the sense that
///       a user of this API should not access them directly.
struct ah_udp_sock {
    AH_I_UDP_SOCK_FIELDS
};

/// \brief An incoming UDP datagram (message).
///
/// \note Some members of this data structure are \e private in the sense that
///       a user of this API should not access them directly. All private
///       members have names beginning with an underscore.
struct ah_udp_in {
    /// \brief Pointer to the address from which the datagram was received.
    const ah_sockaddr_t* raddr;

    /// \brief Buffer containing datagram contents.
    ah_buf_t buf;

    /// \brief Size of the received datagram, in bytes.
    size_t nrecv;

    AH_I_UDP_IN_FIELDS
};

/// \brief An outgoing UDP datagram (message).
///
/// \note Some members of this data structure are \e private in the sense that
///       a user of this API should not access them directly. All private
///       members have names beginning with an underscore.
struct ah_udp_out {
    /// \brief Pointer to the address at which the datagram is to be sent.
    const ah_sockaddr_t* raddr;

    /// \brief Buffer containing datagram contents.
    ah_buf_t buf;

    /// \brief Size of the transmitted datagram, in bytes.
    size_t nsent;

    AH_I_UDP_OUT_FIELDS
};

/// \brief UDP socket callback set.
///
/// A set of function pointers used to handle events on UDP sockets.
struct ah_udp_sock_cbs {
    /// \brief \a sock has been opened, or the attempt failed.
    ///
    /// \param sock Pointer to socket.
    /// \param err  One of the following codes: <ul>
    ///   <li><b>AH_ENONE</b>                          - Socket opened successfully.
    ///   <li><b>AH_EACCESS [Darwin, Linux]</b>        - Not permitted to open socket.
    ///   <li><b>AH_EADDRINUSE</b>                     - Specified local address already in use.
    ///   <li><b>AH_EADDRNOTAVAIL</b>                  - No available local network interface is
    ///                                                  associated with the given local address.
    ///   <li><b>AH_EAFNOSUPPORT</b>                   - Specified IP version not supported.
    ///   <li><b>AH_ECANCELED</b>                      - Socket event loop is shutting down.
    ///   <li><b>AH_EMFILE [Darwin, Linux, Win32]</b>  - Process descriptor table is full.
    ///   <li><b>AH_ENETDOWN [Win32]</b>               - The network subsystem has failed.
    ///   <li><b>AH_ENFILE [Darwin, Linux]</b>         - System file table is full.
    ///   <li><b>AH_ENOBUFS [Darwin, Linux, Win32]</b> - Not enough buffer space available.
    ///   <li><b>AH_ENOMEM [Darwin, Linux]</b>         - Not enough heap memory available.
    ///   <li><b>AH_EPROVIDERFAILEDINIT [Win32]</b>    - Network service failed to initialize.
    /// </ul>
    ///
    /// \note Every successfully opened \a sock must eventually be provided to
    ///       ah_udp_sock_close().
    void (*on_open)(ah_udp_sock_t* sock, ah_err_t err);

    ///\brief Data has been received via \a sock.
    ///
    /// Successful calls to this function (meaning that \a err is equal to
    /// \c AH_ENONE) always carry a pointer to an ah_udp_in instance. That
    /// instance is reset and reused by \a sock every time this callback is
    /// invoked. If you wish to save the contents of \a in without having to
    /// copy it over to another buffer, you can detach it from \a sock using
    /// ah_udp_in_detach(), which allocates a new input buffer for \a sock.
    ///
    /// If this callback is invoked with an error code (\a err is not equal to
    /// \c AH_ENONE), \a sock should always be closed via a call to
    /// ah_udp_sock_close().
    ///
    /// \param sock Pointer to socket.
    /// \param in   Pointer to input data representation, or \c NULL if \a err
    ///             is not \c AH_ENONE.
    /// \param err  One of the following codes: <ul>
    ///   <li><b>AH_ENONE</b>                   - Data received successfully.
    ///   <li><b>AH_ECANCELED</b>               - Socket event loop is shutting down.
    ///   <li><b>AH_ECONNRESET [Win32]</b>      - A previous send operation resulted in an ICMP
    ///                                           "Port Unreachable" message.
    ///   <li><b>AH_EEOF</b>                    - Socket closed.
    ///   <li><b>AH_EMSGSIZE [Win32]</b>        - Received message too large to fit inside \a in.
    ///   <li><b>AH_ENETDOWN [Win32]</b>        - The network subsystem has failed.
    ///   <li><b>AH_ENETRESET [Win32]</b>       - Time to live is enabled for the socket and a
    ///                                           related failure was detected.
    ///   <li><b>AH_ENOBUFS [Darwin, Linux]</b> - Not enough buffer space available.
    ///   <li><b>AH_ENOMEM [Darwin, Linux]</b>  - Not enough heap memory available.
    /// </ul>
    void (*on_recv)(ah_udp_sock_t* sock, ah_udp_in_t* in, ah_err_t err);

    /// \brief Data has been sent via \a sock.
    ///
    /// This callback is always invoked after a successful call to
    /// ah_udp_sock_write(). If \a err is \c AH_ENONE, all outgoing data
    /// provided to the mentioned function was transmitted successfully. If \a
    /// err has any other value, an error occurred before the transmission could
    /// be completed. If an error has occurred, \a sock should be closed using
    /// ah_udp_sock_close().
    ///
    /// \param sock Pointer to socket.
    /// \param out  Pointer to output buffer provided to ah_udp_sock_write(),
    ///             or \c NULL if \a err is not \c AH_ENONE.
    /// \param err  One of the following codes: <ul>
    ///   <li><b>AH_ENONE</b>                   - Data sent successfully.
    ///   <li><b>AH_ECANCELED</b>               - Socket event loop is shutting down.
    ///   <li><b>AH_ECONNRESET [Win32]</b>      - A previous send operation resulted in an ICMP
    ///                                           "Port Unreachable" message.
    ///   <li><b>AH_EEOF</b>                    - Socket closed.
    ///   <li><b>AH_EMSGSIZE</b>                - Sent message size exceeds supported maximum.
    ///   <li><b>AH_ENETDOWN [Linux]</b>        - The local network interface required to send the
    ///                                           message is down.
    ///   <li><b>AH_ENETDOWN [Win32]</b>        - The network subsystem has failed.
    ///   <li><b>AH_ENETRESET [Win32]</b>       - Time to live is enabled for the socket and a
    ///                                           related failure was detected.
    ///   <li><b>AH_ENETUNREACH [Darwin]</b>    - Network of remote host not reachable.
    ///   <li><b>AH_ENOBUFS [Darwin, Linux]</b> - Not enough buffer space available.
    ///   <li><b>AH_ENOMEM [Darwin, Linux]</b>  - Not enough heap memory available.
    /// </ul>
    void (*on_send)(ah_udp_sock_t* sock, ah_udp_out_t* out, ah_err_t err);

    /// \brief The socket has been closed.
    ///
    /// \param sock Pointer to socket.
    /// \param err  Should always be \c AH_ENONE. Other codes may be provided if
    ///             an unexpected platform error occurs.
    ///
    /// \note This function is guaranteed to be called after every call to
    ///       ah_udp_sock_close(), which makes it an excellent place to release
    ///       any resources associated with \a sock.
    void (*on_close)(ah_udp_sock_t* sock, ah_err_t err);
};

ah_extern ah_udp_trans_t ah_udp_trans_get_default(void);

ah_extern bool ah_udp_vtab_is_valid(const ah_udp_vtab_t* vtab);

ah_extern ah_err_t ah_udp_sock_init(ah_udp_sock_t* sock, ah_loop_t* loop, ah_udp_trans_t trans, const ah_udp_sock_cbs_t* cbs);
ah_extern ah_err_t ah_udp_sock_open(ah_udp_sock_t* sock, const ah_sockaddr_t* laddr);
ah_extern ah_err_t ah_udp_sock_recv_start(ah_udp_sock_t* sock);
ah_extern ah_err_t ah_udp_sock_recv_stop(ah_udp_sock_t* sock);
ah_extern ah_err_t ah_udp_sock_send(ah_udp_sock_t* sock, ah_udp_out_t* out);
ah_extern ah_err_t ah_udp_sock_close(ah_udp_sock_t* sock);
ah_extern ah_err_t ah_udp_sock_get_laddr(const ah_udp_sock_t* sock, ah_sockaddr_t* laddr);
ah_extern ah_loop_t* ah_udp_sock_get_loop(const ah_udp_sock_t* sock);
ah_extern void* ah_udp_sock_get_user_data(const ah_udp_sock_t* sock);
ah_extern bool ah_udp_sock_is_closed(const ah_udp_sock_t* sock);
ah_extern bool ah_udp_sock_is_receiving(const ah_udp_sock_t* sock);
ah_extern ah_err_t ah_udp_sock_set_multicast_hop_limit(ah_udp_sock_t* sock, uint8_t hop_limit);
ah_extern ah_err_t ah_udp_sock_set_multicast_loopback(ah_udp_sock_t* sock, bool is_enabled);
ah_extern ah_err_t ah_udp_sock_set_reuseaddr(ah_udp_sock_t* sock, bool is_enabled);
ah_extern ah_err_t ah_udp_sock_set_unicast_hop_limit(ah_udp_sock_t* sock, uint8_t hop_limit);
ah_extern void ah_udp_sock_set_user_data(ah_udp_sock_t* sock, void* user_data);
ah_extern ah_err_t ah_udp_sock_join(ah_udp_sock_t* sock, const ah_udp_group_t* group);
ah_extern ah_err_t ah_udp_sock_leave(ah_udp_sock_t* sock, const ah_udp_group_t* group);

/// \brief Allocates new input buffer, storing a pointer to it in \a owner_ptr.
///
/// The allocated input buffer is stored to \a owner_ptr \e and contains its own
/// copy of \a owner_ptr. The buffer can later be detached from its owner by a
/// call to ah_udp_in_detach(), which sets the copy to \c NULL and replaces the
/// pointer pointed to by \a owner_ptr with that of a new input buffer.
///
/// Every input buffer allocated with this function must eventually be provided
/// to ah_udp_in_free(). It is the responsibility of the owner of each instance
/// to make sure this is the case.
///
/// \param owner_ptr Pointer to own pointer to allocated input buffer.
/// \return <ul>
///   <li><b>AH_ENONE</b>     - The operation was successful.
///   <li><b>AH_EINVAL</b>    - \a owner_ptr is \c NULL.
///   <li><b>AH_ENOMEM</b>    - No enough heap memory available (ah_palloc() returned \c NULL).
///   <li><b>AH_EOVERFLOW</b> - \c AH_CONF_PSIZE is too small for it to be possible to store both an
///                             ah_udp_in instance \e and have room for input data in a single page
///                             provided by the page allocator (see ah_palloc()).
/// </ul>
///
/// \note This function should primarily be of interest to those both wishing to
///       implement their own UDP transports and need to intercept buffers (for
///       the sake of decryption, for example).
ah_extern ah_err_t ah_udp_in_alloc_for(ah_udp_in_t** owner_ptr);

ah_extern ah_err_t ah_udp_in_detach(ah_udp_in_t* in);

// Must only be called after successful call to ah_udp_in_detach() with same `in`.
ah_extern ah_err_t ah_udp_in_free(ah_udp_in_t* in);

#endif
