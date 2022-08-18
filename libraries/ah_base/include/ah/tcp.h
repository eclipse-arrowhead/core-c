// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_TCP_H_
#define AH_TCP_H_

/// \brief Transmission Control Protocol (TCP) utilities.
/// \file
///
/// Here, the data structures and functions required to setup and send messages
/// through TCP connections are made available. Such connections are produced
/// either by \e connecting to a remote host or \e listening for incoming
/// connections.
///
/// \note When we use the terms \e remote and \e local to describe connections
///       and hosts, we do so from the perspective of individual connections
///       rather than complete devices. In other words, if a certain connection
///       is initialized and then established using calls to ah_tcp_conn_init()
///       and ah_tcp_conn_connect(), that connection is considered \e local. The
///       listener it connected to is considered \e remote, even if the listener
///       would happen to be located on the same device, or even in the same
///       process, as the original connection. The reverse is also true. If a
///       listener is established with calls to ah_tcp_listener_init() and
///       ah_tcp_listener_listen(), any accepted connection is considered
///       \e remote from the perspective of the listener, even if the connection
///       would have been initiated from the same device or process.

#include "buf.h"
#include "internal/_tcp.h"
#include "rw.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/// \brief Read shutdown flag that can be provided as argument to
///        ah_tcp_conn_shutdown().
#define AH_TCP_SHUTDOWN_RD 1u

/// \brief Write shutdown flag that can be provided as argument to
///        ah_tcp_conn_shutdown().
#define AH_TCP_SHUTDOWN_WR 2u

/// \brief Read and write shutdown flag that can be provided as argument to
///        ah_tcp_conn_shutdown().
#define AH_TCP_SHUTDOWN_RDWR 3u

/// \brief Type guaranteed to be able to hold all TCP shutdown flags.
typedef uint8_t ah_tcp_shutdown_t;

/// \brief A TCP-based transport.
///
/// A \e transport represents a medium through which TCP connections can be
/// established. Such a medium could be a plain connection via an underlying
/// operating system, a TLS/SSL layer on top of a plain connection, etc.
struct ah_tcp_trans {
    /// \brief Virtual function table used to interact with transport medium.
    const ah_tcp_vtab_t* vtab;

    /// \brief Pointer to whatever context is needed by the transport.
    void* ctx;
};

/// \brief Virtual function table for TCP-based transports.
///
/// A set of function pointers representing the TCP functions that must be
/// implemented via a transport (see ah_tcp_trans).
///
/// \note This structure is primarily useful to those wishing to implement their
///       own TCP transports.
struct ah_tcp_vtab {
    ah_err_t (*conn_open)(void* ctx, ah_tcp_conn_t* conn, const ah_sockaddr_t* laddr);
    ah_err_t (*conn_connect)(void* ctx, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr);
    ah_err_t (*conn_read_start)(void* ctx, ah_tcp_conn_t* conn);
    ah_err_t (*conn_read_stop)(void* ctx, ah_tcp_conn_t* conn);
    ah_err_t (*conn_write)(void* ctx, ah_tcp_conn_t* conn, ah_tcp_out_t* out);
    ah_err_t (*conn_shutdown)(void* ctx, ah_tcp_conn_t* conn, ah_tcp_shutdown_t flags);
    ah_err_t (*conn_close)(void* ctx, ah_tcp_conn_t* conn);

    ah_err_t (*listener_open)(void* ctx, ah_tcp_listener_t* ln, const ah_sockaddr_t* laddr);
    ah_err_t (*listener_listen)(void* ctx, ah_tcp_listener_t* ln, unsigned backlog, const ah_tcp_conn_cbs_t* conn_cbs);
    ah_err_t (*listener_close)(void* ctx, ah_tcp_listener_t* ln);
};

/// \brief A TCP connection handle.
///
/// Such a handle can be established either by connecting to a remote listener
/// via ah_tcp_conn_connect() or by accepting connections via
/// ah_tcp_listener_listen().
///
/// \note All members of this data structure are \e private in the sense that
///       a user of this API should not access them directly.
struct ah_tcp_conn {
    AH_I_TCP_CONN_FIELDS
};

/// \brief TCP connection callback set.
///
/// A set of function pointers used to handle events on TCP connections.
struct ah_tcp_conn_cbs {
    /// \brief \a conn has been opened, or the attempt failed.
    ///
    /// \param conn Pointer to connection.
    /// \param err One of the following codes: <ul>
    ///   <li><b>AH_ENONE</b>                          - Connection opened successfully.
    ///   <li><b>AH_EACCESS [Darwin, Linux]</b>        - Not permitted to open socket.
    ///   <li><b>AH_EADDRINUSE</b>                     - Specified local address already in use.
    ///   <li><b>AH_EADDRNOTAVAIL</b>                  - No available local network interface is
    ///                                                  associated with the given local address.
    ///   <li><b>AH_EAFNOSUPPORT</b>                   - Specified IP version not supported.
    ///   <li><b>AH_EMFILE [Darwin, Linux, Win32]</b>  - Process descriptor table is full.
    ///   <li><b>AH_ENETDOWN [Win32]</b>               - The network subsystem has failed.
    ///   <li><b>AH_ENFILE [Darwin, Linux]</b>         - System file table is full.
    ///   <li><b>AH_ENOBUFS [Darwin, Linux, Win32]</b> - Not enough buffer space available.
    ///   <li><b>AH_ENOMEM [Darwin, Linux]</b>         - Not enough heap memory available.
    /// </ul>
    ///
    /// \note This function is never called for accepted connections, which
    ///       means it may be set to \c NULL when this data structure is used
    ///       with ah_tcp_listener_listen().
    void (*on_open)(ah_tcp_conn_t* conn, ah_err_t err);

    /// \brief \a conn has been established to a specified remote host, or the
    ///        attempt to establish it has failed.
    ///
    /// \param conn Pointer to connection.
    /// \param err One of the following codes: <ul>
    ///   <li><b>AH_ENONE</b>                             - Connection established successfully.
    ///   <li><b>AH_EADDRINUSE [Darwin, Linux, Win32]</b> - Failed to bind a concrete local address.
    ///                                                     This error only occurs if the connection
    ///                                                     was opened with the wildcard address,
    ///                                                     which means that network interface
    ///                                                     binding is delayed until connection.
    ///   <li><b>AH_EADDRNOTAVAIL [Darwin, Win32]</b>     - The specified remote address is invalid.
    ///   <li><b>AH_EADDRNOTAVAIL [Linux]</b>             - No ephemeral TCP port is available.
    ///   <li><b>AH_EAFNOSUPPORT</b>                      - The IP version of the specified remote
    ///                                                     address does not match that of the bound
    ///                                                     local address.
    ///   <li><b>AH_ECANCELED</b>                         - The event loop of \a conn has shut down.
    ///   <li><b>AH_ECONNREFUSED</b>                      - Connection attempt ignored or rejected
    ///                                                     by targeted remote host.
    ///   <li><b>AH_ECONNRESET [Darwin]</b>               - Connection attempt reset by targeted
    ///                                                     remote host.
    ///   <li><b>AH_EHOSTUNREACH [Darwin, Win32]</b>      - The targeted remote host could not be
    ///                                                     reached.
    ///   <li><b>AH_ENETDOWN [Darwin]</b>                 - Local network not online.
    ///   <li><b>AH_ENETDOWN [Win32]</b>                  - The network subsystem has failed.
    ///   <li><b>AH_ENETUNREACH</b>                       - Network of targeted remote host not
    ///                                                     reachable.
    ///   <li><b>AH_ENOBUFS</b>                           - Not enough buffer space available.
    ///   <li><b>AH_ENOMEM</b>                            - Not enough heap memory available.
    ///   <li><b>AH_ETIMEDOUT</b>                         - The connection attempt did not complete
    ///                                                     before its deadline.
    /// </ul>
    ///
    /// \note This function is never called for accepted connections, which
    ///       means it may be set to \c NULL when this data structure is used
    ///       with ah_tcp_listener_listen().
    void (*on_connect)(ah_tcp_conn_t* conn, ah_err_t err);

    ///\brief Data has been received via \a conn.
    ///
    /// \param conn Pointer to connection.
    /// \param in   Pointer to input data representation, or \c NULL if \a err
    ///             is not \c AH_ENONE.
    /// \param err  One of the following codes: <ul>
    ///   <li><b>AH_ENONE</b>                      - Data received successfully.
    ///   <li><b>AH_ECONNABORTED [Win32]</b>       - Virtual circuit terminated due to time-out or
    ///                                              other failure.
    ///   <li><b>AH_ECONNRESET [Darwin, Win32]</b> - Connection reset by remote host.
    ///   <li><b>AH_EDISCON [Win32]</b>            - Connection gracefully closed by remote host.
    ///   <li><b>AH_EEOF</b>                       - Connection closed for reading.
    ///   <li><b>AH_ENETDOWN [Win32]</b>           - The network subsystem has failed.
    ///   <li><b>AH_ENETRESET [Win32]</b>          - Keep-alive is enabled for the connection and a
    ///                                              related failure was detected.
    ///   <li><b>AH_ENOBUFS [Darwin, Linux]</b>    - Not enough buffer space available.
    ///   <li><b>AH_ENOMEM [Linux]</b>             - Not enough heap memory available.
    ///   <li><b>AH_ETIMEDOUT</b>                  - Connection timed out.
    /// </ul>
    ///
    /// \note If set to \c NULL, reading is shutdown automatically.
    void (*on_read)(ah_tcp_conn_t* conn, ah_tcp_in_t* in, ah_err_t err);

    /// \brief Data has been sent via the connection.
    ///
    /// \param conn Pointer to connection.
    /// \param out  Pointer to output data representation, or \c NULL if \a err
    ///             is not \c AH_ENONE.
    /// \param err  One of the following codes: <ul>
    ///   <li><b>AH_ENONE</b>                - Data sent successfully.
    ///   <li><b>AH_ECONNRESET [Darwin]</b>  - Connection reset by remote host.
    ///   <li><b>AH_EEOF [Darwin]</b>        - Connection closed for writing.
    ///   <li><b>AH_ENETDOWN [Darwin]</b>    - Local network not online.
    ///   <li><b>AH_ENETUNREACH [Darwin]</b> - Network of remote host not reachable.
    ///   <li><b>AH_ENOBUFS [Darwin]</b>     - Not enough buffer space available.
    ///   <li><b>AH_ENOMEM [Darwin]</b>      - Not enough heap memory available.
    /// </ul>
    ///
    /// \note If set to \c NULL, writing is shutdown automatically.
    void (*on_write)(ah_tcp_conn_t* conn, ah_tcp_out_t* out, ah_err_t err);

    /// \brief The connection has been closed.
    ///
    /// \param conn Pointer to connection.
    /// \param err  Should always be \c AH_ENONE. Other codes may be provided if
    ///             an unexpected platform error occurs.
    void (*on_close)(ah_tcp_conn_t* conn, ah_err_t err);
};

/// \brief A TCP listener handle.
///
/// Such a handle may represent the attempt to accept incoming TCP connections.
///
/// \note All members of this data structure are \e private in the sense that
///       a user of this API should not access them directly.
struct ah_tcp_listener {
    AH_I_TCP_LISTENER_FIELDS
};

struct ah_tcp_listener_cbs {
    void (*on_open)(ah_tcp_listener_t* ln, ah_err_t err);
    void (*on_listen)(ah_tcp_listener_t* ln, ah_err_t err);
    void (*on_accept)(ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr, ah_err_t err);
    void (*on_close)(ah_tcp_listener_t* ln, ah_err_t err);
};

// A buffer part of a stream of incoming TCP bytes.
struct ah_tcp_in {
    ah_rw_t rw;

    AH_I_TCP_IN_FIELDS
};

// A buffer part of a stream of outgoing TCP bytes.
struct ah_tcp_out {
    ah_buf_t buf;

    AH_I_TCP_OUT_FIELDS
};

ah_extern ah_tcp_trans_t ah_tcp_trans_get_default(void);

ah_extern bool ah_tcp_vtab_is_valid(const ah_tcp_vtab_t* vtab);

ah_extern ah_err_t ah_tcp_conn_init(ah_tcp_conn_t* conn, ah_loop_t* loop, ah_tcp_trans_t trans, const ah_tcp_conn_cbs_t* cbs);
ah_extern ah_err_t ah_tcp_conn_open(ah_tcp_conn_t* conn, const ah_sockaddr_t* laddr);
ah_extern ah_err_t ah_tcp_conn_connect(ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr);
ah_extern ah_err_t ah_tcp_conn_read_start(ah_tcp_conn_t* conn);
ah_extern ah_err_t ah_tcp_conn_read_stop(ah_tcp_conn_t* conn);
ah_extern ah_err_t ah_tcp_conn_write(ah_tcp_conn_t* conn, ah_tcp_out_t* out);
ah_extern ah_err_t ah_tcp_conn_shutdown(ah_tcp_conn_t* conn, ah_tcp_shutdown_t flags);
ah_extern ah_err_t ah_tcp_conn_close(ah_tcp_conn_t* conn);
ah_extern ah_err_t ah_tcp_conn_get_laddr(const ah_tcp_conn_t* conn, ah_sockaddr_t* laddr);
ah_extern ah_err_t ah_tcp_conn_get_raddr(const ah_tcp_conn_t* conn, ah_sockaddr_t* raddr);
ah_extern ah_loop_t* ah_tcp_conn_get_loop(const ah_tcp_conn_t* conn);
ah_extern ah_tcp_shutdown_t ah_tcp_conn_get_shutdown_flags(const ah_tcp_conn_t* conn);
ah_extern void* ah_tcp_conn_get_user_data(const ah_tcp_conn_t* conn);
ah_extern bool ah_tcp_conn_is_closed(const ah_tcp_conn_t* conn);
ah_extern bool ah_tcp_conn_is_readable(const ah_tcp_conn_t* conn);
ah_extern bool ah_tcp_conn_is_readable_and_writable(const ah_tcp_conn_t* conn);
ah_extern bool ah_tcp_conn_is_reading(const ah_tcp_conn_t* conn);
ah_extern bool ah_tcp_conn_is_writable(const ah_tcp_conn_t* conn);
ah_extern ah_err_t ah_tcp_conn_set_keepalive(ah_tcp_conn_t* conn, bool is_enabled);
ah_extern ah_err_t ah_tcp_conn_set_nodelay(ah_tcp_conn_t* conn, bool is_enabled);
ah_extern ah_err_t ah_tcp_conn_set_reuseaddr(ah_tcp_conn_t* conn, bool is_enabled);
ah_extern void ah_tcp_conn_set_user_data(ah_tcp_conn_t* conn, void* user_data);

ah_extern ah_err_t ah_tcp_in_alloc_for(ah_tcp_in_t** owner_ptr);
ah_extern ah_err_t ah_tcp_in_detach(ah_tcp_in_t* in);

// Must only be called after successful call to ah_tcp_in_detach() with same `in`.
ah_extern void ah_tcp_in_free(ah_tcp_in_t* in);

ah_extern ah_err_t ah_tcp_in_repackage(ah_tcp_in_t* in);

ah_extern ah_tcp_out_t* ah_tcp_out_alloc(void);
ah_extern void ah_tcp_out_free(ah_tcp_out_t* out);

ah_extern ah_err_t ah_tcp_listener_init(ah_tcp_listener_t* ln, ah_loop_t* loop, ah_tcp_trans_t trans, const ah_tcp_listener_cbs_t* cbs);
ah_extern ah_err_t ah_tcp_listener_open(ah_tcp_listener_t* ln, const ah_sockaddr_t* laddr);
ah_extern ah_err_t ah_tcp_listener_listen(ah_tcp_listener_t* ln, unsigned backlog, const ah_tcp_conn_cbs_t* conn_cbs);
ah_extern ah_err_t ah_tcp_listener_close(ah_tcp_listener_t* ln);
ah_extern ah_err_t ah_tcp_listener_term(ah_tcp_listener_t* ln);
ah_extern ah_err_t ah_tcp_listener_get_laddr(const ah_tcp_listener_t* ln, ah_sockaddr_t* laddr);
ah_extern ah_loop_t* ah_tcp_listener_get_loop(const ah_tcp_listener_t* ln);
ah_extern void* ah_tcp_listener_get_user_data(const ah_tcp_listener_t* ln);
ah_extern bool ah_tcp_listener_is_closed(ah_tcp_listener_t* ln);
ah_extern ah_err_t ah_tcp_listener_set_keepalive(ah_tcp_listener_t* ln, bool is_enabled);
ah_extern ah_err_t ah_tcp_listener_set_nodelay(ah_tcp_listener_t* ln, bool is_enabled);
ah_extern ah_err_t ah_tcp_listener_set_reuseaddr(ah_tcp_listener_t* ln, bool is_enabled);
ah_extern void ah_tcp_listener_set_user_data(ah_tcp_listener_t* ln, void* user_data);

#endif
