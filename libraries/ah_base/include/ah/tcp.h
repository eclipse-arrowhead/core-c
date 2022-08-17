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
/// through TCP connections. Such connections are produced either by
/// \e connecting to a remote host or \e listening for incoming connections.
///
/// \note The terms \e remote and \e local are used here from the perspective
/// of individual setup connections, not from the host they are running on. A
/// connection being connected to a listener residing on the same host, or even
/// being setup in the same operating process, is considered \e remote from the
/// viewpoint of the connector, which considers itself to be local.

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
    /// \brief The connection has been opened or failed to open.
    ///
    /// \param conn Pointer to connection.
    /// \param err <ul>
    ///   <li><b>AH_ENONE</b>                  - Connection opened.
    ///   <li><b>AH_EACCESS [Darwin]</b>       - Not permitted to open socket.
    ///   <li><b>AH_EADDRINUSE [Darwin]</b>    - Specified address already in use.
    ///   <li><b>AH_EADDRNOTAVAIL [Darwin]</b> - No available network interface is associated with
    ///                                          the specified address.
    ///   <li><b>AH_EAFNOSUPPORT [Darwin]</b>  - Used IP version not supported.
    ///   <li><b>AH_EMFILE [Darwin]</b>        - Process descriptor table is full.
    ///   <li><b>AH_ENFILE [Darwin]</b>        - System file table is full.
    ///   <li><b>AH_ENOBUFS [Darwin]</b>       - Not enough buffer space available.
    ///   <li><b>AH_ENOMEM [Darwin]</b>        - Not enough heap memory available.
    /// </ul>
    ///
    /// \note Never called for accepted connections. May be \c NULL when used
    ///       with ah_tcp_listener_listen().
    void (*on_open)(ah_tcp_conn_t* conn, ah_err_t err);

    /// \brief The connection has been established to a remote host.
    ///
    /// \param conn Pointer to connection.
    /// \param err <ul>
    ///   <li><b>AH_ENONE</b>                  - Connection established.
    ///   <li><b>AH_EADDRINUSE [Darwin]</b>    - Specified address already in use.
    ///   <li><b>AH_EADDRNOTAVAIL [Darwin]</b> - No available network interface is associated with
    ///                                          the specified address.
    ///   <li><b>AH_EAFNOSUPPORT [Darwin]</b>  - Used IP version not supported.
    ///   <li><b>AH_ECANCELED</b>              - The event loop of \a conn was shut down.
    ///   <li><b>AH_ECONNREFUSED [Darwin]</b>  - Connection attempt ignored or rejected by targeted
    ///                                          remote host.
    ///   <li><b>AH_ECONNRESET [Darwin]</b>    - Connection attempt reset by targeted remote host.
    ///   <li><b>AH_EHOSTUNREACH [Darwin]</b>  - The targeted remote host could not be reached.
    ///   <li><b>AH_ENETDOWN [Darwin]</b>      - Local network not online.
    ///   <li><b>AH_ENETUNREACH [Darwin]</b>   - Network of targeted remote host not reachable.
    ///   <li><b>AH_ENOBUFS</b>                - Not enough buffer space available.
    ///   <li><b>AH_ENOMEM</b>                 - Not enough heap memory available.
    ///   <li><b>AH_ETIMEDOUT [Darwin]</b>     - Connection attempt timed out.
    /// </ul>
    ///
    /// \note Never called for accepted connections. May be \c NULL when used
    ///       with ah_tcp_listener_listen().
    void (*on_connect)(ah_tcp_conn_t* conn, ah_err_t err);

    ///\brief Data has been received via the connection.
    ///
    /// \param conn Pointer to connection.
    /// \param in   Pointer to input data representation, or \c NULL if \a err
    ///             is not \c AH_ENONE.
    /// \param err  <ul>
    ///   <li><b>AH_ENONE</b>               - Data received successfully.
    ///   <li><b>AH_ECONNRESET [Darwin]</b> - Connection reset by remote host.
    ///   <li><b>AH_EEOF [Darwin]</b>       - Connection closed for reading.
    ///   <li><b>AH_ENOBUFS [Darwin]</b>    - Not enough buffer space available.
    ///   <li><b>AH_ETIMEDOUT [Darwin]</b>  - Connection attempt timed out.
    /// </ul>
    ///
    /// \note If set to \c NULL, reading is shutdown automatically.
    void (*on_read)(ah_tcp_conn_t* conn, ah_tcp_in_t* in, ah_err_t err);

    /// \brief Data has been sent via the connection.
    ///
    /// \param conn Pointer to connection.
    /// \param out  Pointer to output data representation, or \c NULL if \a err
    ///             is not \c AH_ENONE.
    /// \param err  <ul>
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
