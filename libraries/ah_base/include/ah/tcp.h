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
/// \note When we use the terms \e remote and \e local throughout this file, we
///       do so from the perspective of individual connections rather than
///       complete devices. In other words, when we consider a certain
///       connection, that connection is local and whatever listener it connects
///       to is remote. When we, on the other hand, consider a certain
///       listener, that listener is local and whatever connection attempts it
///       receives are remote. Whether the connections and listeners are
///       physically located on different devices or processes is not of
///       concern.

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
    ah_err_t (*conn_shutdown)(void* ctx, ah_tcp_conn_t* conn, uint8_t flags);
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
    ///   <li><b>AH_ECANCELED</b>                      - Connection event loop is shutting down.
    ///   <li><b>AH_EMFILE [Darwin, Linux, Win32]</b>  - Process descriptor table is full.
    ///   <li><b>AH_ENETDOWN [Win32]</b>               - The network subsystem has failed.
    ///   <li><b>AH_ENFILE [Darwin, Linux]</b>         - System file table is full.
    ///   <li><b>AH_ENOBUFS [Darwin, Linux, Win32]</b> - Not enough buffer space available.
    ///   <li><b>AH_ENOMEM [Darwin, Linux]</b>         - Not enough heap memory available.
    ///   <li><b>AH_EPROVIDERFAILEDINIT [Win32]</b>    - Network service failed to initialize.
    /// </ul>
    ///
    /// \note This function is never called for accepted connections, which
    ///       means it may be set to \c NULL when this data structure is used
    ///       with ah_tcp_listener_listen().
    /// \note Every successfully opened \a conn must eventually be provided to
    ///       ah_tcp_conn_close().
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
    /// Successful calls to this function (meaning that \a err is equal to
    /// \c AH_ENONE) always carry a pointer to an ah_tcp_in instance. That
    /// instance is reused by \a conn every time this callback is invoked. If
    /// the ah_rw member of that instance is not read in its entirety, whatever
    /// unread contents remain when this callback returns will be presented
    /// again in another call to this callback. If not all of the contents of
    /// \a in are read or discarded every time this callback is invoked, or
    /// the buffer is repackaged via ah_tcp_in_repackage(), that buffer may
    /// eventually become full, triggering the \c AH_EOVERFLOW error. If you
    /// wish to save the contents of \a in without having to copy it over to
    /// another buffer, you can detach it from \a conn using ah_tcp_in_detach(),
    /// which allocates a new input buffer for \a conn.
    ///
    /// If this callback is invoked with an error code (\a err is not equal to
    /// \c AH_ENONE), \a conn should always be closed via a call to
    /// ah_tcp_conn_close().
    ///
    /// \param conn Pointer to connection.
    /// \param in   Pointer to input data representation, or \c NULL if \a err
    ///             is not \c AH_ENONE.
    /// \param err  One of the following codes: <ul>
    ///   <li><b>AH_ENONE</b>                      - Data received successfully.
    ///   <li><b>AH_ECANCELED</b>                  - Connection event loop is shutting down.
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
    ///   <li><b>AH_EOVERFLOW</b>                  - The input buffer of \a conn is full. Note that
    ///                                              the input buffer is not available via \a in if
    ///                                              this error code is provided. The only way to
    ///                                              recover from this error is by closing the
    ///                                              connection. To prevent this error from
    ///                                              occurring, you must ensure that the input
    ///                                              buffer never gets exhausted by reading,
    ///                                              discarding, repackaging or detaching
    ///                                              its contents, as described further above.
    ///   <li><b>AH_ETIMEDOUT</b>                  - Connection timed out.
    /// </ul>
    ///
    /// \note If set to \c NULL, reading is shutdown automatically.
    void (*on_read)(ah_tcp_conn_t* conn, ah_tcp_in_t* in, ah_err_t err);

    /// \brief Data has been sent via the connection.
    ///
    /// This callback is always invoked after a successful call to
    /// ah_tcp_conn_write(). If \a err is \c AH_ENONE, all outgoing data
    /// provided to the mentioned function was transmitted successfully. If \a
    /// err has any other value, an error occurred before the transmission could
    /// be completed. If an error has occurred, \a conn should be closed using
    /// ah_tcp_conn_close().
    ///
    /// \param conn Pointer to connection.
    /// \param out  Pointer to output data representation, or \c NULL if \a err
    ///             is not \c AH_ENONE.
    /// \param err  One of the following codes: <ul>
    ///   <li><b>AH_ENONE</b>                             - Data sent successfully.
    ///   <li><b>AH_ECANCELED</b>                         - Connection event loop is shutting down.
    ///   <li><b>AH_ECONNABORTED [Win32]</b>              - Virtual circuit terminated due to
    ///                                                     time-out or other failure.
    ///   <li><b>AH_ECONNRESET [Darwin, Linux, Win32]</b> - Connection reset by remote host.
    ///   <li><b>AH_EEOF</b>                              - Connection closed for writing.
    ///   <li><b>AH_ENETDOWN [Darwin]</b>                 - Local network not online.
    ///   <li><b>AH_ENETDOWN [Win32]</b>                  - The network subsystem has failed.
    ///   <li><b>AH_ENETRESET [Win32]</b>                 - Keep-alive is enabled for the connection
    ///                                                     and a related failure was detected.
    ///   <li><b>AH_ENETUNREACH [Darwin]</b>              - Network of remote host not reachable.
    ///   <li><b>AH_ENOBUFS [Darwin, Linux, Win32]</b>    - Not enough buffer space available.
    ///   <li><b>AH_ENOMEM [Darwin, Linux]</b>            - Not enough heap memory available.
    ///   <li><b>AH_ETIMEDOUT</b>                         - Connection timed out.
    /// </ul>
    ///
    /// \note If set to \c NULL, writing is shutdown automatically.
    void (*on_write)(ah_tcp_conn_t* conn, ah_tcp_out_t* out, ah_err_t err);

    /// \brief The connection has been closed.
    ///
    /// \param conn Pointer to connection.
    /// \param err  Should always be \c AH_ENONE. Other codes may be provided if
    ///             an unexpected platform error occurs.
    ///
    /// \note This function is guaranteed to be called after every call to
    ///       ah_tcp_conn_close(), which makes it an excellent place to release
    ///       any resources associated with \a conn.
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

/// \brief TCP listener callback set.
///
/// A set of function pointers used to handle events related to TCP listeners.
struct ah_tcp_listener_cbs {
    /// \brief Listener \a ln has been opened, or the attempt failed.
    ///
    /// \param conn Pointer to listener.
    /// \param err  One of the following codes: <ul>
    ///   <li><b>AH_ENONE</b>                          - Listener opened successfully.
    ///   <li><b>AH_EACCESS [Darwin, Linux]</b>        - Not permitted to open socket.
    ///   <li><b>AH_EADDRINUSE</b>                     - Specified local address already in use.
    ///   <li><b>AH_EADDRNOTAVAIL</b>                  - No available local network interface is
    ///                                                  associated with the given local address.
    ///   <li><b>AH_EAFNOSUPPORT</b>                   - Specified IP version not supported.
    ///   <li><b>AH_ECANCELED</b>                      - Connection event loop is shutting down.
    ///   <li><b>AH_EMFILE [Darwin, Linux, Win32]</b>  - Process descriptor table is full.
    ///   <li><b>AH_ENETDOWN [Win32]</b>               - The network subsystem has failed.
    ///   <li><b>AH_ENFILE [Darwin, Linux]</b>         - System file table is full.
    ///   <li><b>AH_ENOBUFS [Darwin, Linux, Win32]</b> - Not enough buffer space available.
    ///   <li><b>AH_ENOMEM [Darwin, Linux]</b>         - Not enough heap memory available.
    /// </ul>
    void (*on_open)(ah_tcp_listener_t* ln, ah_err_t err);

    /// \brief Listener \a ln has started to listen for incoming connections, or
    ///        the attempt failed.
    ///
    /// \param conn Pointer to listener.
    /// \param err  One of the following codes: <ul>
    ///   <li><b>AH_ENONE</b>                     - Listener started to listen successfully.
    ///   <li><b>AH_EACCESS [Darwin]</b>          - Not permitted to listen.
    ///   <li><b>AH_EADDRINUSE [Linux, Win32]</b> - No ephemeral TCP port is available. This error
    ///                                             can only occur if the listener was opened with
    ///                                             the wildcard address, which means that network
    ///                                             interface binding is delayed until listening.
    ///   <li><b>AH_ECANCELED</b>                 - Listener event loop is shutting down.
    ///   <li><b>AH_ENETDOWN [Win32]</b>          - The network subsystem has failed.
    ///   <li><b>AH_ENFILE [Win32]</b>            - System file table is full.
    ///   <li><b>AH_ENOBUFS [Win32]</b>           - Not enough buffer space available.
    /// </ul>
    void (*on_listen)(ah_tcp_listener_t* ln, ah_err_t err);

    /// \brief Listener \a ln has accepted the connection \a conn.
    ///
    /// If \a err is \c AH_ENONE, which indicates a successful acceptance, all
    /// further events related to \a conn will be dealt with via the connection
    /// callback set (see ah_tcp_conn_cbs) provided when listening was started
    /// via ah_tcp_listener_listen().
    ///
    /// \param ln    Pointer to listener.
    /// \param conn  Pointer to accepted connection, or \c NULL if \a err is not
    ///              \c AH_ENONE.
    /// \param raddr Pointer to address of \a conn, or \c NULL if \a err is not
    ///              \c AH_ENONE.
    /// \param err  One of the following codes: <ul>
    ///   <li><b>AH_ENONE</b>                         - Connection accepted successfully.
    ///   <li><b>AH_ECANCELED</b>                     - Listener event loop is shutting down.
    ///   <li><b>AH_ECONNABORTED [Darwin, Linux]</b>  - Connection aborted before finalization.
    ///   <li><b>AH_ECONNRESET [Win32]</b>            - Connection aborted before finalization.
    ///   <li><b>AH_EMFILE [Darwin, Linux, Win32]</b> - Process descriptor table is full.
    ///   <li><b>AH_ENETDOWN [Win32]</b>              - The network subsystem has failed.
    ///   <li><b>AH_ENFILE [Darwin, Linux]</b>        - System file table is full.
    ///   <li><b>AH_ENOBUFS [Linux, Win32]</b>        - Not enough buffer space available.
    ///   <li><b>AH_ENOMEM [Darwin, Linux]</b>        - Not enough heap memory available.
    ///   <li><b>AH_EPROVIDERFAILEDINIT [Win32]</b>   - Network service failed to initialize.
    /// </ul>
    ///
    /// \note Every successfully accepted \a conn must eventually be provided to
    ///       ah_tcp_conn_close().
    void (*on_accept)(ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr, ah_err_t err);

    /// \brief Listener \a ln has been closed.
    ///
    /// \param conn Pointer to listener.
    /// \param err  Should always be \c AH_ENONE. Other codes may be provided if
    ///             an unexpected platform error occurs.
    void (*on_close)(ah_tcp_listener_t* ln, ah_err_t err);
};

/// \brief An incoming stream of bytes.
///
/// \note Some members of this data structure are \e private in the sense that
///       a user of this API should not access them directly. All private
///       members have names beginning with an underscore.
struct ah_tcp_in {
    /// \brief Reader/writer referring to incoming data.
    ah_rw_t rw;

    AH_I_TCP_IN_FIELDS
};

/// \brief An outgoing buffer of bytes.
///
/// \note Some members of this data structure are \e private in the sense that
///       a user of this API should not access them directly. All private
///       members have names beginning with an underscore.
struct ah_tcp_out {
    /// \brief Buffer referring to outgoing data.
    ah_buf_t buf;

    AH_I_TCP_OUT_FIELDS
};

/// \name TCP Transport
///
/// Operations on ah_tcp_trans instances.
///
/// \{

/// \brief Gets a copy of the default TCP transport.
///
/// The default TCP transport represents a plain connection via the network
/// subsystem of the current platform. This transport may be used directly with
/// ah_tcp_conn_init() and ah_tcp_listener_init() to establish plain TCP
/// connections, which is to say that they are not encrypted or analyzed in any
/// way.
ah_extern ah_tcp_trans_t ah_tcp_trans_get_default(void);

/// \}

/// \name TCP Virtual Function Table
///
/// Operations on ah_tcp_vtab instances.
///
/// \{

/// \brief Checks if all mandatory fields of \a vtab are set.
///
/// \param vtab Pointer to virtual function table.
/// \return \c true only if \a vtab is valid. \c false otherwise.
ah_extern bool ah_tcp_vtab_is_valid(const ah_tcp_vtab_t* vtab);

/// \}

/// \name TCP Connection
///
/// Operations on ah_tcp_conn instances. All such instances must be initialized
/// using ah_tcp_conn_init() before they are provided to any other functions
/// listed here. Any other requirements regarding the state of connections
/// are described in the documentation of each respective function, sometimes
/// only via the error codes it lists.
///
/// \{

/// \brief Initializes \a conn for subsequent use.
///
/// \param conn  Pointer to connection.
/// \param loop  Pointer to event loop.
/// \param trans Desired transport.
/// \param cbs   Pointer to event callback set.
/// \return <ul>
///   <li><b>AH_ENONE</b>  - \a conn successfully initialized.
///   <li><b>AH_EINVAL</b> - \a conn or \a loop or \a cbs is \c NULL.
///   <li><b>AH_EINVAL</b> - \a trans \c vtab is invalid, as reported by ah_tcp_vtab_is_valid().
///   <li><b>AH_EINVAL</b> - \c on_open, \c on_connect or \c on_close of \a cbs is \c NULL.
/// </ul>
///
/// \note Every successfully initialized \a conn must eventually be provided to
///       ah_tcp_conn_close().
ah_extern ah_err_t ah_tcp_conn_init(ah_tcp_conn_t* conn, ah_loop_t* loop, ah_tcp_trans_t trans, const ah_tcp_conn_cbs_t* cbs);

/// \brief Schedules opening of \a conn, which must be initialized, via the
///        local network interface represented by \a laddr.
///
/// If the return value of this function is \c AH_ENONE, meaning that the open
/// attempt could indeed be scheduled, its result will eventually be presented
/// via the ah_tcp_conn_cbs::on_open callback of \a conn.
///
/// \param conn  Pointer to connection.
/// \param laddr Pointer to socket address representing a local network
///              interface through which the connection must later be
///              established. If opening is successful, the referenced address
///              must remain valid for the entire lifetime of the created
///              connection. If \c NULL, the connection is bound to the wildcard
///              address and the zero port, which means that it can be
///              established through any available local network interface and
///              that a concrete port number is chosen automatically.
/// \return <ul>
///   <li><b>AH_ENONE</b>        - \a conn opening successfully scheduled.
///   <li><b>AH_EAFNOSUPPORT</b> - \a laddr is not \c NULL and is not an IP-based address.
///   <li><b>AH_ECANCELED</b>    - The event loop of \a conn is shutting down.
///   <li><b>AH_EINVAL</b>       - \a conn is \c NULL.
///   <li><b>AH_ENOBUFS</b>      - Not enough buffer space available.
///   <li><b>AH_ENOMEM</b>       - Not enough heap memory available.
///   <li><b>AH_ESTATE</b>       - \a conn is not closed.
/// </ul>
ah_extern ah_err_t ah_tcp_conn_open(ah_tcp_conn_t* conn, const ah_sockaddr_t* laddr);

/// \brief Schedules connection of \a conn, which must be open, to \a raddr.
///
/// If the return value of this function is \c AH_ENONE, meaning that connection
/// could indeed be scheduled, its result will eventually be presented via the
/// ah_tcp_conn_cbs::on_connect callback of \a conn.
///
/// \param conn  Pointer to connection.
/// \param raddr Pointer to socket address representing the remote host to which
///              the connection is to be established. If connection is
///              successful, the referenced address must remain valid until
///              \a conn is closed.
/// \return <ul>
///   <li><b>AH_ENONE</b>        - \a conn opening successfully scheduled.
///   <li><b>AH_EAFNOSUPPORT</b> - \a raddr is not an IP-based address.
///   <li><b>AH_ECANCELED</b>    - The event loop of \a conn is shutting down.
///   <li><b>AH_EINVAL</b>       - \a conn or \a raddr is \c NULL.
///   <li><b>AH_ENOBUFS</b>      - Not enough buffer space available.
///   <li><b>AH_ENOMEM</b>       - Not enough heap memory available.
///   <li><b>AH_ESTATE</b>       - \a conn is not open.
/// </ul>
///
/// \note Data receiving is disabled for new connections by default. Is must be
///       explicitly enabled via a call to ah_tcp_conn_read_start().
///
/// \warning This function must be called with a successfully opened connection.
///          An appropriate place to call this function is often going to be in
///          an ah_tcp_conn_cbs::on_open callback after a check that opening was
///          successful.
ah_extern ah_err_t ah_tcp_conn_connect(ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr);

/// \brief Enables receiving of incoming data via \a conn.
///
/// When the receiving of data is enabled, the ah_tcp_conn_cbs::on_read callback
/// of \a conn will be invoked whenever incoming data is received.
///
/// \param conn Pointer to connection.
/// \return <ul>
///   <li><b>AH_ENONE</b>            - Start of receiving data via \a conn successfully scheduled.
///   <li><b>AH_ECANCELED</b>        - The event loop of \a conn is shutting down.
///   <li><b>AH_EINVAL</b>           - \a conn is \c NULL.
///   <li><b>AH_ENETDOWN [Win32]</b> - The network subsystem has failed.
///   <li><b>AH_ENOBUFS</b>          - Not enough buffer space available.
///   <li><b>AH_ENOMEM</b>           - Not enough heap memory available.
///   <li><b>AH_EOVERFLOW</b>        - The configured \c AH_PSIZE is too small for it to be possible
///                                    to store both required metadata \e and read data in a single
///                                    page provided by the page allocator (see ah_palloc()).
///   <li><b>AH_ESTATE</b>           - \a conn is not connected or its read direction has been shut
///                                    down.
/// </ul>
///
/// \warning This function must be called with a successfully connected
///          connection. An appropriate place to call this function is often
///          going to be in an ah_tcp_conn_cbs::on_connect callback after a
///          check that the connection attempt was successful.
ah_extern ah_err_t ah_tcp_conn_read_start(ah_tcp_conn_t* conn);

/// \brief Disables receiving of incoming data via \a conn.
///
/// \param conn Pointer to connection.
/// \return <ul>
///   <li><b>AH_ENONE</b>            - Receiving of data via \a conn successfully stopped.
///   <li><b>AH_EINVAL</b>           - \a conn is \c NULL.
///   <li><b>AH_ESTATE</b>           - \a conn reading not started.
/// </ul>
///
/// \note It is acceptable to call this function immediately after a successful
///       call to ah_tcp_conn_read_start() with the same \a conn, even if that
///       means that \a conn never had a practical chance to start reading.
ah_extern ah_err_t ah_tcp_conn_read_stop(ah_tcp_conn_t* conn);

/// \brief Schedules the sending of the data in \a out to the remote host of
///        \a conn.
///
/// An output buffer can be allocated on the heap using ah_tcp_out_alloc(). If
/// you want to store the buffer memory somewhere else, just zero an ah_tcp_out
/// instance and then initialize its \c buf member.
///
/// If the return value of this function is \c AH_ENONE, meaning that the
/// sending could indeed be scheduled, the result of the sending will eventually
/// be presented via the ah_tcp_conn_cbs::on_write callback of \a conn. More
/// specifically, the callback is invoked either if an error occurs or after all
/// data in \a out has been successfully transmitted.
///
/// \param conn Pointer to connection.
/// \param out  Pointer to outgoing data.
/// \return <ul>
///   <li><b>AH_ENONE</b>            - Data transmission scheduled successfully.
///   <li><b>AH_ECANCELED</b>        - The event loop of \a conn is shutting down.
///   <li><b>AH_EINVAL</b>           - \a conn or \a out is \c NULL.
///   <li><b>AH_ENETDOWN [Win32]</b> - The network subsystem has failed.
///   <li><b>AH_ENOBUFS</b>          - Not enough buffer space available.
///   <li><b>AH_ENOMEM</b>           - Not enough heap memory available.
///   <li><b>AH_ESTATE</b>           - \a conn is not open or its write direction has been shut
///                                    down.
/// </ul>
ah_extern ah_err_t ah_tcp_conn_write(ah_tcp_conn_t* conn, ah_tcp_out_t* out);

/// \brief Shuts down the read and/or write direction of \a conn, as specified
///        by \a flags.
///
/// \param conn  Pointer to connection.
/// \param flags Shutdown flags.
/// \return <ul>
///   <li><b>AH_ENONE</b>                - Receiving of data via \a conn successfully stopped.
///   <li><b>AH_ECONNABORTED [Win32]</b> - Connection has been aborted.
///   <li><b>AH_ECONNRESET [Win32]</b>   - Connection has been reset by its remote host.
///   <li><b>AH_EINVAL</b>               - \a conn is \c NULL.
///   <li><b>AH_ENETDOWN [Win32]</b>     - The network subsystem has failed.
///   <li><b>AH_ESTATE</b>               - \a conn is not connected.
/// </ul>
///
/// \warning A connection with both of its read and write directions shut down
///          is not considered as being closed. Every connection must eventually
///          be provided to ah_tcp_conn_close(), irrespective of any direction
///          being shutdown.
ah_extern ah_err_t ah_tcp_conn_shutdown(ah_tcp_conn_t* conn, uint8_t flags);

/// \brief Schedules closing of \a conn.
///
/// If the return value of this function is \c AH_ENONE, meaning that the
/// closing could indeed be scheduled, its result will eventually be presented
/// via the ah_tcp_conn_cbs::on_close callback of \a conn.
///
/// \param conn Pointer to connection.
/// \return <ul>
///   <li><b>AH_ENONE</b>  - Close of \a conn successfully scheduled.
///   <li><b>AH_EINVAL</b> - \a conn is \c NULL.
///   <li><b>AH_ESTATE</b> - \a conn is already closed.
/// </ul>
ah_extern ah_err_t ah_tcp_conn_close(ah_tcp_conn_t* conn);

/// \brief Stores local address bound by \a conn into \a laddr.
///
/// If \a conn was opened with a zero port, this function will report what
/// concrete port was assigned to \a conn.
///
/// \param conn  Pointer to connection.
/// \param laddr Pointer to socket address to be set by this operation.
/// \return <ul>
///   <li><b>AH_ENONE</b>                   - The operation was successful.
///   <li><b>AH_EINVAL</b>                  - \a conn or \a laddr is \c NULL.
///   <li><b>AH_ENETDOWN [Win32]</b>        - The network subsystem has failed.
///   <li><b>AH_ENOBUFS [Darwin, Linux]</b> - Not enough buffer space available.
///   <li><b>AH_ESTATE</b>                  - \a conn is closed.
/// </ul>
ah_extern ah_err_t ah_tcp_conn_get_laddr(const ah_tcp_conn_t* conn, ah_sockaddr_t* laddr);

/// \brief Stores remote address of \a conn into \a raddr.
///
/// \param conn  Pointer to connection.
/// \param raddr Pointer to socket address to be set by this operation.
/// \return <ul>
///   <li><b>AH_ENONE</b>                   - The operation was successful.
///   <li><b>AH_EINVAL</b>                  - \a conn or \a raddr is \c NULL.
///   <li><b>AH_ENETDOWN [Win32]</b>        - The network subsystem has failed.
///   <li><b>AH_ENOBUFS [Darwin, Linux]</b> - Not enough buffer space available.
///   <li><b>AH_ESTATE</b>                  - \a conn is not connected to a remote host.
/// </ul>
ah_extern ah_err_t ah_tcp_conn_get_raddr(const ah_tcp_conn_t* conn, ah_sockaddr_t* raddr);

/// \brief Gets pointer to event loop of \a conn.
///
/// \param conn Pointer to connection.
/// \return Pointer to event loop, or \c NULL if \a conn is \c NULL.
ah_extern ah_loop_t* ah_tcp_conn_get_loop(const ah_tcp_conn_t* conn);

/// \brief Gets currently set shutdown flags of \a conn.
///
/// \param conn Pointer to connection.
/// \return Shutdown flags associated with \a conn. If \a conn is \c NULL,
///         \c AH_TCP_SHUTDOWN_RDWR is returned.
ah_extern uint8_t ah_tcp_conn_get_shutdown_flags(const ah_tcp_conn_t* conn);

/// \brief Gets the user data pointer associated with \a conn.
///
/// \param conn Pointer to connection.
/// \return Any user data pointer previously set via
///         ah_tcp_conn_set_user_data(), or \c NULL if no such has been set or
///         if \a conn is \c NULL.
ah_extern void* ah_tcp_conn_get_user_data(const ah_tcp_conn_t* conn);

/// \brief Checks if \a conn is closed.
///
/// \param conn Pointer to connection.
/// \return \c true only if \a conn is not \c NULL and is currently closed.
///         \c false otherwise.
ah_extern bool ah_tcp_conn_is_closed(const ah_tcp_conn_t* conn);

/// \brief Checks if \a conn can be read from.
///
/// A readable connection is currently connected and has not had its read
/// direction shut down.
///
/// \param conn Pointer to connection.
/// \return \c true only if \a conn is not \c NULL and is currently readable.
///         \c false otherwise.
ah_extern bool ah_tcp_conn_is_readable(const ah_tcp_conn_t* conn);

/// \brief Checks if \a conn can be read from and written to.
///
/// A readable and writable connection is currently connected and has not had
/// either of its read or write directions shut down.
///
/// \param conn Pointer to connection.
/// \return \c true only if \a conn is not \c NULL and is currently readable and
///         writable. \c false otherwise.
ah_extern bool ah_tcp_conn_is_readable_and_writable(const ah_tcp_conn_t* conn);

/// \brief Checks if \a conn is currently reading incoming data.
///
/// A connection is reading if its currently connected and
/// ah_tcp_conn_read_start() has been called with the same connection as
/// argument. In addition, neither of ah_tcp_conn_read_stop() or
/// ah_tcp_conn_shutdown() has since been used to stop or shutdown the read
/// direction of the same connection.
///
/// \param conn Pointer to connection.
/// \return \c true only if \a conn is not \c NULL and is currently reading.
///         \c false otherwise.
ah_extern bool ah_tcp_conn_is_reading(const ah_tcp_conn_t* conn);

/// \brief Checks if \a conn can be written to.
///
/// A writable connection is currently connected and has not had its write
/// direction shut down.
///
/// \param conn Pointer to connection.
/// \return \c true only if \a conn is not \c NULL and is currently readable.
///         \c false otherwise.
ah_extern bool ah_tcp_conn_is_writable(const ah_tcp_conn_t* conn);

/// \brief Sets the \e keep-alive option of \a conn to \a is_enabled.
///
/// This option enables or disables keep-alive messaging. Generally, using such
/// messaging means that \a conn automatically sends messages sensible times to
/// check if the connection is in a usable condition. The exact implications
/// of this option depends on the platform.
///
/// \param conn       Pointer to connection.
/// \param is_enabled Whether keep-alive is to be enabled or not.
/// \return <ul>
///   <li><b>AH_ENONE</b>            - The operation was successful.
///   <li><b>AH_EINVAL</b>           - \a conn is \c NULL.
///   <li><b>AH_ENETDOWN [Win32]</b> - The network subsystem has failed.
///   <li><b>AH_ENOBUFS [Darwin]</b> - Not enough buffer space available.
///   <li><b>AH_ENOMEM [Darwin]</b>  - Not enough heap memory available.
///   <li><b>AH_ESTATE</b>           - \a conn is closed.
/// </ul>
ah_extern ah_err_t ah_tcp_conn_set_keepalive(ah_tcp_conn_t* conn, bool is_enabled);

/// \brief Sets the \e no-delay option of \a conn to \a is_enabled.
///
/// This option being enabled means that use of Nagle's algorithm is disabled.
/// The mentioned algorithm queues up messages for a short time before sending
/// them over the network. The purpose of this is to reduce the number of TCP
/// segments submitted over the used network.
///
/// \param conn       Pointer to connection.
/// \param is_enabled Whether keep-alive is to be enabled or not.
/// \return <ul>
///   <li><b>AH_ENONE</b>            - The operation was successful.
///   <li><b>AH_EINVAL</b>           - \a conn is \c NULL.
///   <li><b>AH_ENETDOWN [Win32]</b> - The network subsystem has failed.
///   <li><b>AH_ENOBUFS [Darwin]</b> - Not enough buffer space available.
///   <li><b>AH_ENOMEM [Darwin]</b>  - Not enough heap memory available.
///   <li><b>AH_ESTATE</b>           - \a conn is closed.
/// </ul>
ah_extern ah_err_t ah_tcp_conn_set_nodelay(ah_tcp_conn_t* conn, bool is_enabled);

/// \brief Sets the <em>reuse address</em> option of \a conn to \a is_enabled.
///
/// Address reuse generally means that a the specific combination of local
/// interface address and port number bound by this connection can be reused
/// right after it closes. Address reuse can lead to security implications as
/// it may enable a malicious process on the same platform to hijack a closed
/// connection.
///
/// \param conn       Pointer to connection.
/// \param is_enabled Whether keep-alive is to be enabled or not.
/// \return <ul>
///   <li><b>AH_ENONE</b>            - The operation was successful.
///   <li><b>AH_EINVAL</b>           - \a conn is \c NULL.
///   <li><b>AH_ENETDOWN [Win32]</b> - The network subsystem has failed.
///   <li><b>AH_ENOBUFS [Darwin]</b> - Not enough buffer space available.
///   <li><b>AH_ENOMEM [Darwin]</b>  - Not enough heap memory available.
///   <li><b>AH_ESTATE</b>           - \a conn is closed.
/// </ul>
ah_extern ah_err_t ah_tcp_conn_set_reuseaddr(ah_tcp_conn_t* conn, bool is_enabled);

/// \brief Sets the user data pointer associated with \a conn.
///
/// \param conn      Pointer to connection.
/// \param user_data User data pointer, referring to whatever context you want
///                  to associate with \a conn.
///
/// \note If \a conn is \c NULL, this function does nothing.
ah_extern void ah_tcp_conn_set_user_data(ah_tcp_conn_t* conn, void* user_data);

/// \}

/// \name TCP Input Buffer
///
/// Operations on ah_tcp_in instances.
///
/// \{

/// \brief Allocates new input buffer, storing a pointer to it in \a owner_ptr.
///
/// The allocated input buffer is stored to \a owner_ptr \e and contains its own
/// copy of \a owner_ptr. The buffer can later be detached from its owner by a
/// call to ah_tcp_in_detach(), which sets the copy to \c NULL and replaces the
/// pointer pointed to by \a owner_ptr with that of a new input buffer.
///
/// Every input buffer allocated with this function must eventually be provided
/// to ah_tcp_in_free(). It is the responsibility of the owner of each instance
/// to make sure this is the case.
///
/// \param owner_ptr Pointer to own pointer to allocated input buffer.
/// \return <ul>
///   <li><b>AH_ENONE</b>     - The operation was successful.
///   <li><b>AH_EINVAL</b>    - \a owner_ptr is \c NULL.
///   <li><b>AH_ENOMEM</b>    - No enough heap memory available (ah_palloc() returned \c NULL).
///   <li><b>AH_EOVERFLOW</b> - The configured \c AH_PSIZE is too small for it to be possible to
///                             store both an ah_tcp_in instance \e and have room for input data in
///                             a single page provided by the page allocator (see ah_palloc()).
/// </ul>
///
/// \note This function should primarily be of interest to those both wishing to
///       implement their own TCP transports and need to intercept buffers (for
///       the sake of decryption, for example).
ah_extern ah_err_t ah_tcp_in_alloc_for(ah_tcp_in_t** owner_ptr);

/// \brief Detaches input buffer \a in from its owner.
///
/// This function first allocates a new input buffer, disassociates \a in from
/// its current owner (most typically an ah_tcp_conn instance), and then
/// associates the newly allocated input buffer with that owner.
///
/// \param in Pointer to input buffer.
/// \return
///
/// \warning As the previous owner of \a in is no longer responsible for it or
///          its memory, you must manually free it using ah_tcp_in_free() once
///          you have no more use of it.
ah_extern ah_err_t ah_tcp_in_detach(ah_tcp_in_t* in);

/// \brief Frees heap memory associated with \a in.
///
/// \param in Pointer to input buffer.
///
/// \warning Only free ah_tcp_in instances you own. Unless you explicitly call
///          ah_tcp_in_alloc_for(), ah_tcp_in_detach() or in some other way is
///          able to take ownership of your own instance, you are not going to
///          need to call this function.
///
/// \note This function does nothing if \a in is \c NULL.
ah_extern void ah_tcp_in_free(ah_tcp_in_t* in);

/// \brief Moves the readable bytes of \a in to the beginning of its internal
///        buffer.
///
/// The internal buffer of \a in has a finite size. When data is written to that
/// internal buffer, a write pointer advances. If enough data is written to it,
/// the write pointer advances to the end of the buffer, making it impossible to
/// store further data to it. When data is read from the buffer, an internal
/// read pointer advances towards the write pointer. After a successful such
/// read operation, the memory between the beginning of the buffer and the read
/// pointer becomes inaccessible. This function moves the data between the read
/// and write pointers of the internal buffer to the beginning of that buffer.
/// This eliminates the inaccessible region and makes it possible to write more
/// data to the end of the buffer.
///
/// TCP is a streaming transmission protocol. Whatever data is sent may arrive
/// split up into multiple segments at its intended receiver. Multiple such
/// segments may have to be awaited before a certain data object can be
/// interpreted correctly, and the last segment may contain the beginning of
/// another data object. In such a scenario, this function makes it possible to
/// move the received part of second data object to the beginning of the
/// internal buffer, preventing it from overflowing for data objects that are
/// smaller than the full size of that buffer.
///
/// \param in Pointer to input buffer.
/// \return <ul>
///   <li><b>AH_ENONE</b>  - The operation was successful.
///   <li><b>AH_EINVAL</b> - \a in is \c NULL.
///   <li><b>AH_ENOSPC</b> - \a in is full. Nothing can be moved.
/// </ul>
ah_extern ah_err_t ah_tcp_in_repackage(ah_tcp_in_t* in);

/// \}

/// \name TCP Output Buffer
///
/// Operations on ah_tcp_out instances.
///
/// \{

/// \brief Dynamically allocates and partially initializes a TCP output buffer.
///
/// Every output buffer allocated with this function must eventually be provided
/// to ah_tcp_out_free().
///
/// Concretely, the page allocator (see ah_palloc()) is used to allocate the
/// returned buffer. All parts of the returned buffer are initialized, except
/// for the actual payload memory.
///
/// \return Pointer to new output buffer, or \c NULL if the allocation failed.
///
/// \warning If \c AH_CONF_PSIZE is configured to a too small value
///          (see conf.h), this function always fails.
ah_extern ah_tcp_out_t* ah_tcp_out_alloc(void);

/// \brief Frees output buffer previously allocated using ah_tcp_out_alloc().
///
/// \param out Pointer to output buffer.
///
/// \note If \a out is \c NULL, this function does nothing.
ah_extern void ah_tcp_out_free(ah_tcp_out_t* out);

/// \}

/// \name TCP Listener
///
/// Operations on ah_tcp_listener instances.
///
/// \{

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

/// \}

#endif
