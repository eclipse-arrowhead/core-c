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
/// and received using \e sockets.
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

/// \brief The maximum payload size of an ah_udp_in instance allocated via
///        ah_udp_in_alloc_for().
#define AH_UDP_IN_BUF_SIZE (AH_PSIZE - sizeof(ah_udp_in_t))

/// \brief The maximum payload size of an ah_udp_out instance allocated via
///        ah_udp_out_alloc().
#define AH_UDP_OUT_BUF_SIZE (AH_PSIZE - sizeof(ah_udp_out_t))

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
///          What kind of group is used depends on the family of the socket it
///          is used with.
union ah_udp_group {
    ah_udp_group_ipv4_t as_ipv4; ///< \brief Access as IPv4 group.
    ah_udp_group_ipv6_t as_ipv6; ///< \brief Access as IPv6 group.
};

/// \brief A UDP-based message transport.
///
/// A \e transport represents a medium through which UDP messages can be sent or
/// received. Such a medium could be a plain socket via an underlying operating
/// system, a DTLS layer on top of a plain socket, etc.
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

/// \brief A UDP socket handle.
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
    /// ah_udp_in_detach(), which automatically allocates a new input buffer
    /// for \a sock.
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
    ///   <li><b>AH_ENONE</b>                        - Data sent successfully.
    ///   <li><b>AH_ECANCELED</b>                    - Socket event loop is shutting down.
    ///   <li><b>AH_ECONNRESET [Win32]</b>           - A previous send operation resulted in an ICMP
    ///                                                "Port Unreachable" message.
    ///   <li><b>AH_EEOF</b>                         - Socket closed.
    ///   <li><b>AH_EHOSTUNREACH [Darwin, Linux]</b> - The targeted remote host could not be
    ///                                                reached.
    ///   <li><b>AH_EMSGSIZE</b>                     - Sent message size exceeds supported maximum.
    ///   <li><b>AH_ENETDOWN [Darwin, Linux]</b>     - The local network interface required to send
    ///                                                the message is down.
    ///   <li><b>AH_ENETDOWN [Win32]</b>             - The network subsystem has failed.
    ///   <li><b>AH_ENETRESET [Win32]</b>            - Time to live is enabled for the socket and a
    ///                                                related failure was detected.
    ///   <li><b>AH_ENETUNREACH [Darwin]</b>         - Network of remote host not reachable.
    ///   <li><b>AH_ENOBUFS [Darwin, Linux]</b>      - Not enough buffer space available.
    ///   <li><b>AH_ENOMEM [Darwin, Linux]</b>       - Not enough heap memory available.
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
/// \name UDP Transport
///
/// Operations on ah_udp_trans instances.
///
/// \{

/// \brief Gets a copy of the default UDP transport.
///
/// The default UCP transport directly utilizes the network subsystem of the
/// current platform. This transport may be used directly with
/// ah_udp_sock_init() to send plain UDP datagrams, which is to say that they
/// are not encrypted or analyzed in any way.
ah_extern ah_udp_trans_t ah_udp_trans_get_default(void);

/// \}

/// \name UDP Virtual Function Table
///
/// Operations on ah_udp_vtab instances.
///
/// \{

/// \brief Checks if all mandatory fields of \a vtab are set.
///
/// \param vtab Pointer to virtual function table.
/// \return \c true only if \a vtab is valid. \c false otherwise.
ah_extern bool ah_udp_vtab_is_valid(const ah_udp_vtab_t* vtab);

/// \}

/// \name UDP Socket
///
/// Operations on ah_udp_sock instances. All such instances must be initialized
/// using ah_udp_sock_init() before they are provided to any other functions
/// listed here. Any other requirements regarding the state of connections
/// are described in the documentation of each respective function, sometimes
/// only via the error codes it lists.
///
/// \{

/// \brief Initializes \a sock for subsequent use.
///
/// \param sock  Pointer to socket.
/// \param loop  Pointer to event loop.
/// \param trans Desired transport.
/// \param cbs   Pointer to event callback set.
/// \return <ul>
///   <li><b>AH_ENONE</b>  - \a sock successfully initialized.
///   <li><b>AH_EINVAL</b> - \a sock or \a loop or \a cbs is \c NULL.
///   <li><b>AH_EINVAL</b> - \a trans \c vtab is invalid, as reported by ah_udp_vtab_is_valid().
///   <li><b>AH_EINVAL</b> - \c on_open, \c on_recv, \c on_send or \c on_close of \a cbs is \c NULL.
/// </ul>
ah_extern ah_err_t ah_udp_sock_init(ah_udp_sock_t* sock, ah_loop_t* loop, ah_udp_trans_t trans, const ah_udp_sock_cbs_t* cbs);

/// \brief Schedules opening of \a sock, which must be initialized, and its
///        binding to the local network interface represented by \a laddr.
///
/// If the return value of this function is \c AH_ENONE, meaning that the open
/// attempt could indeed be scheduled, its result will eventually be presented
/// via the ah_udp_sock_cbs::on_open callback of \a sock.
///
/// \param sock  Pointer to socket.
/// \param laddr Pointer to socket address representing a local network
///              interface through which the socket must later send and/or
///              receive its datagrams. If opening is successful, the referenced
///              address must remain valid for the entire lifetime of the
///              created socket. To bind to all or any local network interface,
///              provide the wildcard address (see ah_sockaddr_ipv4_wildcard and
///              ah_sockaddr_ipv6_wildcard). If you want the platform to chose
///              port number automatically, specify port \c 0.

/// \return <ul>
///   <li><b>AH_ENONE</b>        - \a sock opening successfully scheduled.
///   <li><b>AH_EAFNOSUPPORT</b> - \a laddr is not \c NULL and is not an IP-based address.
///   <li><b>AH_ECANCELED</b>    - The event loop of \a sock is shutting down.
///   <li><b>AH_EINVAL</b>       - \a sock is \c NULL.
///   <li><b>AH_ENOBUFS</b>      - Not enough buffer space available.
///   <li><b>AH_ENOMEM</b>       - Not enough heap memory available.
///   <li><b>AH_ESTATE</b>       - \a sock is not closed.
/// </ul>
///
/// \note Every successfully opened \a sock must eventually be provided to
///       ah_udp_sock_close().
ah_extern ah_err_t ah_udp_sock_open(ah_udp_sock_t* sock, const ah_sockaddr_t* laddr);

/// \brief Enables receiving of incoming data via \a sock.
///
/// When the receiving of data is enabled, the ah_udp_sock_cbs::on_recv callback
/// of \a sock will be invoked whenever incoming data is received.
///
/// \param sock Pointer to socket.
/// \return <ul>
///   <li><b>AH_ENONE</b>            - Start of receiving data via \a sock successfully scheduled.
///   <li><b>AH_ECANCELED</b>        - The event loop of \a sock is shutting down.
///   <li><b>AH_EINVAL</b>           - \a sock is \c NULL.
///   <li><b>AH_ENETDOWN [Win32]</b> - The network subsystem has failed.
///   <li><b>AH_ENOBUFS</b>          - Not enough buffer space available.
///   <li><b>AH_ENOMEM</b>           - Not enough heap memory available.
///   <li><b>AH_EOVERFLOW</b>        - \c AH_PSIZE is too small for it to be possible to store both
///                                    required metadata \e and read data in a single page provided
///                                    by the page allocator (see ah_palloc()).
///   <li><b>AH_ESTATE</b>           - \a sock is not open.
/// </ul>
///
/// \warning This function must be called with a successfully opened socket. An
///          appropriate place to call this function is often going to be in an
///          ah_udp_sock_cbs::on_open callback after a check that the open
///          attempt was successful.
ah_extern ah_err_t ah_udp_sock_recv_start(ah_udp_sock_t* sock);

/// \brief Disables receiving of incoming data via \a sock.
///
/// \param sock Pointer to socket.
/// \return <ul>
///   <li><b>AH_ENONE</b>  - Receiving of data via \a sock successfully stopped.
///   <li><b>AH_EINVAL</b> - \a sock is \c NULL.
///   <li><b>AH_ESTATE</b> - \a sock reading not started.
/// </ul>
///
/// \note It is acceptable to call this function immediately after a successful
///       call to ah_udp_sock_recv_start() with the same \a sock, even if that
///       means that \a sock never had a practical chance to start receiving
///       data.
ah_extern ah_err_t ah_udp_sock_recv_stop(ah_udp_sock_t* sock);

/// \brief Schedules the sending of the data in \a out, which both specifies
///        where and what to send.
///
/// An output buffer can be allocated on the heap using ah_udp_out_alloc(). If
/// you want to store the buffer memory somewhere else, just zero an ah_udp_out
/// instance and then initialize its \c buf member.
///
/// If the return value of this function is \c AH_ENONE, meaning that the
/// sending could indeed be scheduled, the result of the sending will eventually
/// be presented via the ah_udp_sock_cbs::on_send callback of \a conn. More
/// specifically, the callback is invoked either if an error occurs or after all
/// data in \a out has been successfully transmitted.
///
/// \param sock Pointer to socket.
/// \param out  Pointer to outgoing data.
/// \return <ul>
///   <li><b>AH_ENONE</b>            - Data transmission scheduled successfully.
///   <li><b>AH_ECANCELED</b>        - The event loop of \a sock is shutting down.
///   <li><b>AH_EINVAL</b>           - \a sock or \a out is \c NULL.
///   <li><b>AH_ENETDOWN [Win32]</b> - The network subsystem has failed.
///   <li><b>AH_ENOBUFS</b>          - Not enough buffer space available.
///   <li><b>AH_ENOMEM</b>           - Not enough heap memory available.
///   <li><b>AH_ESTATE</b>           - \a sock is not open.
/// </ul>
ah_extern ah_err_t ah_udp_sock_send(ah_udp_sock_t* sock, ah_udp_out_t* out);

/// \brief Schedules closing of \a sock.
///
/// If the return value of this function is \c AH_ENONE, meaning that the
/// closing could indeed be scheduled, its result will eventually be presented
/// via the ah_udp_sock_cbs::on_close callback of \a sock.
///
/// \param sock Pointer to socket.
/// \return <ul>
///   <li><b>AH_ENONE</b>  - Close of \a sock successfully scheduled.
///   <li><b>AH_EINVAL</b> - \a sock is \c NULL.
///   <li><b>AH_ESTATE</b> - \a sock is already closed.
/// </ul>
ah_extern ah_err_t ah_udp_sock_close(ah_udp_sock_t* sock);

/// \brief Checks the socket family of \a sock.
///
/// \param sock Pointer to socket.
/// \return <ul>
///   <li><b>AH_SOCKFAMILY_IPV4</b> - IPv4 family identifier.
///   <li><b>AH_SOCKFAMILY_IPV6</b> - IPv6 family identifier.
///   <li><b>-1</b>                 - \a sock is \c NULL.
/// </ul>
ah_extern int ah_udp_sock_get_family(const ah_udp_sock_t* sock);

/// \brief Stores local address bound by \a sock into \a laddr.
///
/// If \a sock was opened with a zero port, this function will report what
/// concrete port was assigned to \a sock.
///
/// \param sock  Pointer to socket.
/// \param laddr Pointer to socket address to be set by this operation.
/// \return <ul>
///   <li><b>AH_ENONE</b>                   - The operation was successful.
///   <li><b>AH_EINVAL</b>                  - \a sock or \a laddr is \c NULL.
///   <li><b>AH_ENETDOWN [Win32]</b>        - The network subsystem has failed.
///   <li><b>AH_ENOBUFS [Darwin, Linux]</b> - Not enough buffer space available.
///   <li><b>AH_ESTATE</b>                  - \a sock is closed.
/// </ul>
ah_extern ah_err_t ah_udp_sock_get_laddr(const ah_udp_sock_t* sock, ah_sockaddr_t* laddr);

/// \brief Gets pointer to event loop of \a sock.
///
/// \param sock Pointer to socket.
/// \return Pointer to event loop, or \c NULL if \a sock is \c NULL.
ah_extern ah_loop_t* ah_udp_sock_get_loop(const ah_udp_sock_t* sock);

/// \brief Gets the user data pointer associated with \a sock.
///
/// \param sock Pointer to socket.
/// \return Any user data pointer previously set via
///         ah_tcp_conn_set_user_data(), or \c NULL if no such has been set or
///         if \a sock is \c NULL.
ah_extern void* ah_udp_sock_get_user_data(const ah_udp_sock_t* sock);

/// \brief Checks if \a sock is closed.
///
/// \param sock Pointer to socket.
/// \return \c true only if \a sock is not \c NULL and is currently closed.
///         \c false otherwise.
ah_extern bool ah_udp_sock_is_closed(const ah_udp_sock_t* sock);

/// \brief Checks if \a sock is currently receiving incoming data.
///
/// A socket is receiving if its currently open and ah_udp_sock_recv_start() has
/// been called with the same socket as argument. In addition,
/// ah_udp_sock_recv_stop() has not since been used to stop receiving on the
/// socket.
///
/// \param sock Pointer to socket.
/// \return \c true only if \a sock is not \c NULL and is currently receiving
///         data. \c false otherwise.
ah_extern bool ah_udp_sock_is_receiving(const ah_udp_sock_t* sock);

/// \brief Sets the <em>multicast hop limit</em> option of \a sock to
///        \a hop_limit.
///
/// The hop limit determines how many intermediary endpoints (i.e. routers)
/// datagrams sent via \a sock may pass on the way to their destinations before
/// they are to be dropped. This option only applies to multicast datagrams,
/// which are messages having an unbounded and indeterminate number of
/// recipients.
///
/// \param sock      Pointer to socket.
/// \param hop_limit Desired hop limit.
/// \return <ul>
///   <li><b>AH_ENONE</b>                   - The operation was successful.
///   <li><b>AH_EINVAL</b>                  - \a sock is \c NULL.
///   <li><b>AH_ENETDOWN [Win32]</b>        - The network subsystem has failed.
///   <li><b>AH_ENOBUFS [Darwin, Linux]</b> - Not enough buffer space available.
///   <li><b>AH_ENOMEM [Darwin, Linux]</b>  - Not enough heap memory available.
///   <li><b>AH_ESTATE</b>                  - \a sock is closed.
/// </ul>
///
/// \note This option can is an important way of preventing multicast messages
///       from leaving the local network of the current device. For example, on
///       Linux, the default multicast hop limit is \c 1. Generally, the value
///       should be small.
ah_extern ah_err_t ah_udp_sock_set_multicast_hop_limit(ah_udp_sock_t* sock, uint8_t hop_limit);

/// \brief Sets the <em>multicast loopback</em> option of \a sock to
///        \a is_enabled.
///
/// If multicast loopback is enabled, multicast messages are sent via \a sock
/// are also sent via the loopback interface of the local host, which means that
/// \a sock receives a copy of each multicast message it sends.
///
/// \param sock       Pointer to socket.
/// \param is_enabled Whether multicast loopback is to be enabled or not.
/// \return <ul>
///   <li><b>AH_ENONE</b>                   - The operation was successful.
///   <li><b>AH_EINVAL</b>                  - \a sock is \c NULL.
///   <li><b>AH_ENETDOWN [Win32]</b>        - The network subsystem has failed.
///   <li><b>AH_ENOBUFS [Darwin, Linux]</b> - Not enough buffer space available.
///   <li><b>AH_ENOMEM [Darwin, Linux]</b>  - Not enough heap memory available.
///   <li><b>AH_ESTATE</b>                  - \a sock is closed.
/// </ul>
ah_extern ah_err_t ah_udp_sock_set_multicast_loopback(ah_udp_sock_t* sock, bool is_enabled);

/// \brief Sets the <em>reuse address</em> option of \a sock to \a is_enabled.
///
/// Address reuse generally means that a the specific combination of local
/// interface address and port number bound by this socket can be reused right
/// after it closes. Address reuse can lead to security implications as it may
/// enable a malicious process on the same platform to hijack a closed socket.
///
/// \param sock       Pointer to socket.
/// \param is_enabled Whether keep-alive is to be enabled or not.
/// \return <ul>
///   <li><b>AH_ENONE</b>                   - The operation was successful.
///   <li><b>AH_EINVAL</b>                  - \a sock is \c NULL.
///   <li><b>AH_ENETDOWN [Win32]</b>        - The network subsystem has failed.
///   <li><b>AH_ENOBUFS [Darwin, Linux]</b> - Not enough buffer space available.
///   <li><b>AH_ENOMEM [Darwin, Linux]</b>  - Not enough heap memory available.
///   <li><b>AH_ESTATE</b>                  - \a sock is closed.
/// </ul>
ah_extern ah_err_t ah_udp_sock_set_reuseaddr(ah_udp_sock_t* sock, bool is_enabled);

/// \brief Sets the <em>unicast hop limit</em> option of \a sock to
///        \a hop_limit.
///
/// The hop limit determines how many intermediary endpoints (i.e. routers)
/// datagrams sent via \a sock may pass on the way to their destinations before
/// they are to be dropped. This option only applies to unicast datagrams, which
/// are messages having only a single recipient.
///
/// \param sock      Pointer to socket.
/// \param hop_limit Desired hop limit.
/// \return <ul>
///   <li><b>AH_ENONE</b>                   - The operation was successful.
///   <li><b>AH_EINVAL</b>                  - \a sock is \c NULL.
///   <li><b>AH_ENETDOWN [Win32]</b>        - The network subsystem has failed.
///   <li><b>AH_ENOBUFS [Darwin, Linux]</b> - Not enough buffer space available.
///   <li><b>AH_ENOMEM [Darwin, Linux]</b>  - Not enough heap memory available.
///   <li><b>AH_ESTATE</b>                  - \a sock is closed.
/// </ul>
ah_extern ah_err_t ah_udp_sock_set_unicast_hop_limit(ah_udp_sock_t* sock, uint8_t hop_limit);

/// \brief Sets the user data pointer associated with \a sock.
///
/// \param sock      Pointer to socket.
/// \param user_data User data pointer, referring to whatever context you want
///                  to associate with \a sock.
///
/// \note If \a sock is \c NULL, this function does nothing.
ah_extern void ah_udp_sock_set_user_data(ah_udp_sock_t* sock, void* user_data);

/// \brief Makes \a sock join the multicast group specified by \a group.
///
/// \param sock  Pointer to socket.
/// \param group Pointer to multicast group specification.
/// \return <ul>
///   <li><b>AH_ENONE</b>                   - The operation was successful.
///   <li><b>AH_EINVAL</b>                  - \a sock is \c NULL.
///   <li><b>AH_ENETDOWN [Win32]</b>        - The network subsystem has failed.
///   <li><b>AH_ENOBUFS [Darwin, Linux]</b> - Not enough buffer space available.
///   <li><b>AH_ENOMEM [Darwin, Linux]</b>  - Not enough heap memory available.
///   <li><b>AH_ESTATE</b>                  - \a sock is closed.
/// </ul>
///
/// \note This is a blocking operation on all supported platforms. It may entail
///       sending various messages via the local network interface of \a sock.
///
/// \warning The \a group parameter is a union type. What variant of that type
///          this function will access is determined by the IP version of the
///          local network interface to which \a sock is bound. It is up to you
///          to make sure that the correct variant of \a group is initialized.
///          If you do not know the family of a given socket, you can check it
///          using ah_udp_sock_get_family().
ah_extern ah_err_t ah_udp_sock_join(ah_udp_sock_t* sock, const ah_udp_group_t* group);

/// \brief Makes \a sock leave the multicast group specified by \a group.
///
/// \param sock  Pointer to socket.
/// \param group Pointer to multicast group specification.
/// \return <ul>
///   <li><b>AH_ENONE</b>                   - The operation was successful.
///   <li><b>AH_EINVAL</b>                  - \a sock is \c NULL.
///   <li><b>AH_ENETDOWN [Win32]</b>        - The network subsystem has failed.
///   <li><b>AH_ENOBUFS [Darwin, Linux]</b> - Not enough buffer space available.
///   <li><b>AH_ENOMEM [Darwin, Linux]</b>  - Not enough heap memory available.
///   <li><b>AH_ESTATE</b>                  - \a sock is closed.
/// </ul>
///
/// \note This is a blocking operation on all supported platforms. It may entail
///       sending various messages via the local network interface of \a sock.
///
/// \warning The \a group parameter is a union type. What variant of that type
///          this function will access is determined by the IP version of the
///          local network interface to which \a sock is bound. It is up to you
///          to make sure that the correct variant of \a group is initialized.
///          If you do not know the family of a given socket, you can check it
///          using ah_udp_sock_get_family().
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
///   <li><b>AH_EOVERFLOW</b> - \c AH_PSIZE is too small for it to be possible to store both an
///                             ah_udp_in instance \e and have room for input data in a single page
///                             provided by the page allocator (see ah_palloc()).
/// </ul>
///
/// \note This function should primarily be of interest to those both wishing to
///       implement their own UDP transports and need to intercept buffers (for
///       the sake of decryption, for example).
ah_extern ah_err_t ah_udp_in_alloc_for(ah_udp_in_t** owner_ptr);

/// \brief Detaches input buffer \a in from its owner.
///
/// This function first allocates a new input buffer, disassociates \a in from
/// its current owner (most typically an ah_udp_sock instance), and then
/// associates the newly allocated input buffer with that owner.
///
/// \param in Pointer to input buffer.
/// \return <ul>
///   <li><b>AH_ENONE</b>     - The operation was successful.
///   <li><b>AH_EINVAL</b>    - \a in is \c NULL.
///   <li><b>AH_ENOMEM</b>    - No enough heap memory available (ah_palloc() returned \c NULL).
///   <li><b>AH_EOVERFLOW</b> - \c AH_PSIZE is too small for it to be possible to store both an
///                             ah_udp_in instance \e and have room for input data in a single page
///                             provided by the page allocator (see ah_palloc()).
///   <li><b>AH_ESTATE</b>    - \a in is currently not owned and cannot be detached.
/// </ul>
///
/// \warning As the previous owner of \a in is no longer responsible for it or
///          its memory, you must manually free it using ah_udp_in_free() once
///          you have no more use of it.
ah_extern ah_err_t ah_udp_in_detach(ah_udp_in_t* in);

/// \brief Frees heap memory associated with \a in.
///
/// \param in Pointer to input buffer.
///
/// \warning Only free ah_tcp_in instances you own. Unless you explicitly call
///          ah_udp_in_alloc_for(), ah_udp_in_detach() or in some other way is
///          able to take ownership of your own instance, you are not going to
///          need to call this function.
///
/// \note This function does nothing if \a in is \c NULL.
ah_extern void ah_udp_in_free(ah_udp_in_t* in);

/// \brief Resets \a in, making all of its payload memory writable.
///
/// \param in Pointer to input buffer to reset.
///
/// \note This function does nothing if \a in is \c NULL.
ah_extern void ah_udp_in_reset(ah_udp_in_t* in);

/// \name UDP Output Buffer
///
/// Operations on ah_udp_out instances.
///
/// \{

/// \brief Dynamically allocates and partially initializes a UDP output buffer.
///
/// The size of the payload memory of the returned buffer
///
/// Every output buffer allocated with this function must eventually be provided
/// to ah_udp_out_free().
///
/// Concretely, the page allocator (see ah_palloc()) is used to allocate the
/// returned buffer. All parts of the returned buffer are initialized, except
/// for the actual payload memory.
///
/// \return Pointer to new output buffer, or \c NULL if the allocation failed.
///
/// \warning If \c AH_PSIZE is configured to a too small value (see conf.h),
///          this function always fails.
ah_extern ah_udp_out_t* ah_udp_out_alloc(void);

/// \brief Frees output buffer previously allocated using ah_udp_out_alloc().
///
/// \param out Pointer to output buffer.
///
/// \note If \a out is \c NULL, this function does nothing.
ah_extern void ah_udp_out_free(ah_udp_out_t* out);

/// \}

#endif
