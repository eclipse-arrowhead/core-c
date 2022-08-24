// SPDX-License-Identifier: EPL-2.0

#ifndef AH_HTTP_H_
#define AH_HTTP_H_

/**
 * @file
 * HTTP/1 client and server.
 *
 * Here, data structures and functions are provided for representing, setting up
 * and communicating via HTTP/1 clients and servers.
 *
 * <h3>Clients</h3>
 *
 * HTTP clients are set up using ah_http_client_init(), ah_http_client_open()
 * and ah_http_client_connect(). Successfully opened clients are closed with
 * ah_http_client_close(). Clients receive data and are notified of other events
 * via their callback sets (see ah_http_client_cbs), which they must be provided
 * with when they are initialized or when they are listened for. Clients
 * transmit data by first calling ah_http_client_send_head(), ensuring the call
 * was successful, and then adhering to one of the following patterns.
 *
 * <ol>
 *   <li>If <em>no message body</em> is relevant, ah_http_client_send_end() must
 *       be called to indicate that sending is complete.
 *   <li>If a <em>non-chunked body</em> is to be sent, which is recommended when
 *       the final size of the transmitted body @c is known in advance,
 *       ah_http_client_send_data() must be called repeatedly until all body
 *       data has been enqueued. Finally, ah_http_client_send_end() must be
 *       called to indicate that the complete body is in the send queue.
 *   <li>If a <em>chunked body</em> is to be sent, which is recommended when the
 *       final size of the transmitted body is @e not known in advance,
 *       ah_http_client_send_chunk() must be called repeatedly until all body
 *       chunks have been enqueued. Finally, ah_http_client_send_trailer() must
 *       be called to submit any trailing chunk extension and headers, and to
 *       indicate that the complete body is in the send queue.
 * </ol>
 *
 * When sending and receiving data, @e metadata, such as start lines, headers
 * and chunks, are gathered into dynamically allocated buffers maintained by
 * each client. Each client owns one such buffer it reuses for all data it
 * receives data by and one more is allocated for each sent message. If a
 * certain metadata item exceeds the size of its receive buffer, or a send
 * buffer is too small to contain all relevant metadata items, the message
 * transmission is failed with error code @c AH_EOVERFLOW. Limiting sizes in
 * this way helps reduce the complexity the client implementation and works as a
 * form of protection from exploits that use large metadata items. Generally,
 * the size of each of these buffers will be limited by the page allocator page
 * size, @c AH_PSIZE, more of which you can read in the documentation for
 * ah_palloc().
 *
 * <h3>Servers</h3>
 *
 * HTTP servers are set up using ah_http_server_init(), ah_http_server_open()
 * and ah_http_server_listen(). Successfully initialized servers are
 * terminated with ah_http_server_term() and successfully opened servers are
 * closed with ah_http_server_close(). Servers receive incoming client and are
 * notified of other events via their callback sets (see ah_http_server_cbs),
 * which must be provided when they are initialized.
 *
 * <h3>Automatic Headers</h3>
 *
 * As described in the directory-level documentation for this library, only a
 * small subset of all headers part of the HTTP standards are handled
 * automatically. Those headers are outlined in the below table.
 *
 * <table>
 *   <caption id="http-headers">Automatically Handled HTTP Headers</caption>
 *   <tr>
 *     <th>Header
 *     <th>Automatic Behavior
 *   <tr>
 *     <td>\c Connection
 *     <td>The options (1) \c close and (2) \c keep-alive automatically cause HTTP connections to
 *         either (1) be closed after the current request/response exchange or (2) remain open
 *         between exchanges. Which of the two behaviors represented by these options is the default
 *         varies between HTTP versions. In version 1.0 \c close is the default, while on all
 *         subsequent versions \c keep-alive is the default.
 *   <tr>
 *     <td>\c Content-Length
 *     <td>When receiving incoming requests and responses, the \c Content-Length is used
 *         automatically to determine when and if a message body is expected, and when all of it has
 *         been received. Incoming messages that neither specify a \c Content-Length nor
 *         <code>Transfer-Encoding: chunked</code> are assumed to not have bodies at all. Note that
 *         no \c Content-Length header is added automatically to sent requests or responses. You
 *         must make sure to add it when relevant.
 *   <tr>
 *     <td>\c Host
 *     <td>When sending requests, if this header is left unspecified and the used HTTP version is
 *         1.1 or higher, the header is automatically populated with the IP address and port number
 *         of the targeted server.
 *   <tr>
 *     <td>\c Transfer-Encoding
 *     <td>If <code>Transfer-Encoding: chunked</code> is specified in an incoming request or
 *         response, the individual chunks are decoded and presented automatically. Other transfer
 *         encoding options are ignored. This means that body compression and decompression is not
 *         handled automatically.
 * </table>
 *
 * @see https://www.rfc-editor.org/rfc/rfc9110.html
 * @see https://www.rfc-editor.org/rfc/rfc9112.html
 */

#include "internal/_http.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef struct ah_http_chunk ah_http_chunk_t;
typedef struct ah_http_client ah_http_client_t;
typedef struct ah_http_client_cbs ah_http_client_cbs_t;
typedef struct ah_http_header ah_http_header_t;
typedef struct ah_http_head ah_http_head_t;
typedef struct ah_http_server ah_http_server_t;
typedef struct ah_http_server_cbs ah_http_server_cbs_t;
typedef struct ah_http_trailer ah_http_trailer_t;
typedef struct ah_http_ver ah_http_ver_t;

/**
 * HTTP client.
 *
 * Clients are either (1) initiated, opened and connected explicitly, or (2)
 * listened for using an ah_http_server instance.
 *
 * Clients send HTTP requests and receive HTTP responses.
 *
 * @note All fields of this data structure are @e private in the sense that a
 *       user of this API should not access them directly.
 */
struct ah_http_client {
    AH_I_HTTP_CLIENT_FIELDS
};

/**
 * HTTP client callback set.
 *
 * A set of function pointers used to handle events on HTTP clients.
 */
struct ah_http_client_cbs {
    /**
     * @a cln has been opened, or the attempt failed.
     *
     * @param cln Pointer to client.
     * @param err One of the following codes: <ul>
     *   <li><b>AH_ENONE</b>                          - Client opened successfully.
     *   <li><b>AH_EACCESS [Darwin, Linux]</b>        - Not permitted to open TCP connection.
     *   <li><b>AH_EADDRINUSE</b>                     - Specified local address already in use.
     *   <li><b>AH_EADDRNOTAVAIL</b>                  - No available local network interface is
     *                                                  associated with the given local address.
     *   <li><b>AH_EAFNOSUPPORT</b>                   - Specified IP version not supported.
     *   <li><b>AH_ECANCELED</b>                      - Client event loop is shutting down.
     *   <li><b>AH_EMFILE [Darwin, Linux, Win32]</b>  - Process descriptor table is full.
     *   <li><b>AH_ENETDOWN [Win32]</b>               - The network subsystem has failed.
     *   <li><b>AH_ENFILE [Darwin, Linux]</b>         - System file table is full.
     *   <li><b>AH_ENOBUFS [Darwin, Linux, Win32]</b> - Not enough buffer space available.
     *   <li><b>AH_ENOMEM [Darwin, Linux]</b>         - Not enough heap memory available.
     *   <li><b>AH_EPROVIDERFAILEDINIT [Win32]</b>    - Network service failed to initialize.
     * </ul>
     *
     * @note This function is never called for accepted clients, which
     *       means it may be set to @c NULL when this data structure is used
     *       with ah_http_server_listen().
     *
     * @note Every successfully opened @a cln must eventually be provided to
     *       ah_http_client_close().
     */
    void (*on_open)(ah_http_client_t* cln, ah_err_t err);

    /**
     * @a cln has been connected to a specified remote host, or the attempt to
     * connect it has failed.
     *
     * @param cln Pointer to client.
     * @param err One of the following codes: <ul>
     *   <li><b>AH_ENONE</b>                             - Connection established successfully.
     *   <li><b>AH_EADDRINUSE [Darwin, Linux, Win32]</b> - Failed to bind a concrete local address.
     *                                                     This error only occurs if the client
     *                                                     was opened with the wildcard address,
     *                                                     which means that network interface
     *                                                     binding is delayed until connection.
     *   <li><b>AH_EADDRNOTAVAIL [Darwin, Win32]</b>     - The specified remote address is invalid.
     *   <li><b>AH_EADDRNOTAVAIL [Linux]</b>             - No ephemeral TCP port is available.
     *   <li><b>AH_EAFNOSUPPORT</b>                      - The IP version of the specified remote
     *                                                     address does not match that of the bound
     *                                                     local address.
     *   <li><b>AH_ECANCELED</b>                         - The event loop of @a cln has shut down.
     *   <li><b>AH_ECONNREFUSED</b>                      - Connection attempt ignored or rejected
     *                                                     by targeted remote host.
     *   <li><b>AH_ECONNRESET [Darwin]</b>               - Connection attempt reset by targeted
     *                                                     remote host.
     *   <li><b>AH_EHOSTUNREACH</b>                      - The targeted remote host could not be
     *                                                     reached.
     *   <li><b>AH_ENETDOWN [Darwin]</b>                 - Local network not online.
     *   <li><b>AH_ENETDOWN [Win32]</b>                  - The network subsystem has failed.
     *   <li><b>AH_ENETUNREACH</b>                       - Network of targeted remote host not
     *                                                     reachable.
     *   <li><b>AH_ENOBUFS</b>                           - Not enough buffer space available.
     *   <li><b>AH_ENOMEM</b>                            - Not enough heap memory available.
     *   <li><b>AH_ETIMEDOUT</b>                         - The connection attempt did not complete
     *                                                     before its deadline.
     * </ul>
     *
     * @note In contrast to plain TCP connections, data receiving is always
     *       enabled for new HTTP connections.
     *
     * @note This function is never called for accepted HTTP clients, which
     *       means it may be set to @c NULL when this data structure is used
     *       with ah_http_server_listen().
     */
    void (*on_connect)(ah_http_client_t* cln, ah_err_t err);

    /**
     * @a cln finished sending an HTTP message or the attempt failed.
     *
     * This callback is invoked if a complete HTTP message could be sent, in
     * which case @a err is @c AH_ENONE, or if sending it failed, which should
     * prompt you to close @a cln using ah_http_client_close().
     *
     * @param cln  Pointer to client.
     * @param head Pointer to ah_http_head instance provided earlier to
     *             ah_http_client_send_head().
     * @param err  One of the following codes: <ul>
     *   <li><b>AH_ENONE</b>                             - Message sent successfully.
     *   <li><b>AH_ECANCELED</b>                         - Client event loop is shutting down or it
     *                                                     was closed before the message represented
     *                                                     by @a head could be transmitted.
     *   <li><b>AH_ECONNABORTED [Win32]</b>              - Virtual circuit terminated due to
     *                                                     time-out or other failure.
     *   <li><b>AH_ECONNRESET [Darwin, Linux, Win32]</b> - Client connection reset by remote host.
     *   <li><b>AH_EEOF</b>                              - Client connection closed for writing.
     *   <li><b>AH_ENETDOWN [Darwin]</b>                 - Local network not online.
     *   <li><b>AH_ENETDOWN [Win32]</b>                  - The network subsystem has failed.
     *   <li><b>AH_ENETRESET [Win32]</b>                 - Keep-alive is enabled for the connection
     *                                                     and a related failure was detected.
     *   <li><b>AH_ENETUNREACH [Darwin]</b>              - Network of remote host not reachable.
     *   <li><b>AH_ENOBUFS [Darwin, Linux, Win32]</b>    - Not enough buffer space available.
     *   <li><b>AH_ENOMEM</b>                            - Not enough heap memory available.
     *   <li><b>AH_EOVERFLOW</b>                         - The used output buffer, which is always
     *                                                     allocated via the page allocator (see
     *                                                     ah_palloc()) is too small for it to be
     *                                                     possible to store the start line, headers
     *                                                     and/or chunk extension of some
     *                                                     ah_http_head, ah_http_chunk or
     *                                                     ah_http_trailer part of the message
     *                                                     transmission.
     *   <li><b>AH_ETIMEDOUT</b>                         - Client connection timed out.
     * </ul>
     */
    void (*on_send)(ah_http_client_t* cln, ah_http_head_t* head, ah_err_t err);

    /**
     * @a cln has received a start line.
     *
     * A start line begins an HTTP message. Whether the start line is a request
     * line or a status line depends on whether the entity receiving the message
     * is a client or a server. Clients you connect using
     * ah_http_client_connect() receive status lines while clients accepted via
     * servers via ah_http_server_listen() receive request lines.
     *
     * If an error occurred before or while parsing the start line,
     * ah_http_client_cbs::on_recv_end is called before this callback is ever
     * invoked.
     *
     * @param cln     Pointer to client receiving start line.
     * @param line    Message start line.
     * @param version HTTP version indicator. The major version is always @c 1.
     *
     * @note If you need to maintain state about the received message, you may
     *       do so by referring to that state using the user data pointer of
     *       @a cln (see ah_http_client_get_user_data() and
     *       ah_http_client_set_user_data()). Messages are always received in
     *       sequence over the same connection, which means that this callback
     *       will not be called again for the current @a cln until
     *       ah_http_client_cbs::on_recv_end has been called to end the
     *       receiving of this message.
     *
     * @warning @a line is not guaranteed to be valid, as per RFC9112. It is up
     *          to you to determine that it both is valid and specifies
     *          something of relevance.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9112.html
     */
    void (*on_recv_line)(ah_http_client_t* cln, const char* line, ah_http_ver_t version);

    /**
     * @a cln has received a header field.
     *
     * This callback is invoked both for regular headers and for those in the
     * trailer of a chunked message. If you need to know which of the two
     * sources a particular header is from, make sure to set
     * ah_http_client_cbs::on_recv_headers, which is called after all regular
     * headers have been received.
     *
     * @param cln    Pointer to client receiving header.
     * @param header HTTP header, consisting of a name and a value.
     */
    void (*on_recv_header)(ah_http_client_t* cln, ah_http_header_t header);

    /**
     * @a cln has seen all headers in the currently received message.
     *
     * @param cln Pointer to client.
     *
     * @note This callback is optional. Set if to @c NULL if not relevant.
     */
    void (*on_recv_headers)(ah_http_client_t* cln);

    /**
     * @a cln has received a chunk size and a chunk extension.
     *
     * @param cln  Pointer to client.
     * @param size Size, in bytes, of the incoming chunk.
     * @param ext  Chunk extension, provided as a NULL-terminated string if
     *             present in received chunk. Otherwise @c NULL.
     *
     * @note The chunk size is handled automatically by the HTTP implementation.
     *       Setting this callback is primarily useful for inspecting chunk
     *       extensions, which are ignored if this callback is unset.
     *
     * @note This callback is optional. Set if to @c NULL if not relevant.
     *
     * @warning @a ext is not guaranteed to be valid, as per RFC9112. It is up
     *          to you to determine that it both is valid and specifies
     *          something of relevance.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9112.html
     */
    void (*on_recv_chunk_line)(ah_http_client_t* cln, size_t size, const char* ext);

    /**
     * @a cln has received data part of a message body.
     *
     * The ah_tcp_in instance referenced by @a in is reused by @a cln every time
     * this callback is invoked. If the ah_rw field of that instance is not read
     * in its entirety, whatever unread contents remain when this callback
     * returns will be presented again in another call to this callback. If not
     * all of the contents of @a in are read or discarded every time this
     * callback is invoked, or the buffer is repackaged via
     * ah_tcp_in_repackage(), that buffer may eventually become full, triggering
     * the @c AH_EOVERFLOW error. If you wish to save the contents of @a in
     * without having to copy it over to another buffer, you can detach it from
     * @a cln using ah_tcp_in_detach(), which allocates a new input buffer for
     * @a cln.
     *
     * @param cln Pointer to client.
     * @param in  Input buffer containing message body data.
     *
     * @note If you feel surprised by TCP data structures and functions
     *       appearing here, remember that HTTP/1 is specified as an extension
     *       of the TCP protocol.
     */
    void (*on_recv_data)(ah_http_client_t* cln, ah_tcp_in_t* in);

    /**
     * @a cln has finished receiving a message.
     *
     * If this callback is invoked with an error code (@a err is not equal to
     * @c AH_ENONE), or if connection keep-alive is disabled, the client will be
     * closed automatically at some point after this function returns.
     *
     * @param cln Pointer to client.
     * @param err One of the following codes: <ul>
     *   <li><b>AH_ENONE</b>                      - Message received successfully.
     *   <li><b>AH_EBADMSG</b>                    - Message metadata violates HTTP specification.
     *   <li><b>AH_ECANCELED</b>                  - Client event loop is shutting down.
     *   <li><b>AH_ECONNABORTED [Win32]</b>       - Virtual circuit terminated due to time-out or
     *                                              other failure.
     *   <li><b>AH_ECONNRESET [Darwin, Win32]</b> - Connection reset by remote host.
     *   <li><b>AH_EDISCON [Win32]</b>            - Connection gracefully closed by remote host.
     *   <li><b>AH_EDUP</b>                       - Supported header or header value that may only
     *                                              occur once has been seen multiple times.
     *   <li><b>AH_EEOF</b>                       - Connection closed for reading.
     *   <li><b>AH_EILSEQ</b>                     - Message syntax not valid according to RFC9112.
     *   <li><b>AH_ENETDOWN [Win32]</b>           - The network subsystem has failed.
     *   <li><b>AH_ENETRESET [Win32]</b>          - Keep-alive is enabled for the connection and a
     *                                              related failure was detected.
     *   <li><b>AH_ENOBUFS</b>                    - Not enough buffer space available.
     *   <li><b>AH_ENOMEM</b>                     - Not enough heap memory available.
     *   <li><b>AH_EOVERFLOW</b>                  - The input buffer of @a cln is full. To prevent
     *                                              this error from occurring when receiving body
     *                                              data, you must ensure that the input buffer
     *                                              never gets exhausted by reading, discarding,
     *                                              repackaging or detaching its contents. The same
     *                                              error also occurs when a received metadata item
     *                                              is too large, which can only be avoided by the
     *                                              sender ensuring that no individual start line,
     *                                              header or chunk line exceeds the size
     *                                              @c AH_TCP_IN_BUF_SIZE.
     *   <li><b>AH_EPROTONOSUPPORT</b>            - Received message uses an unsupported version of
     *                                              HTTP.
     *   <li><b>AH_ETIMEDOUT</b>                  - Connection timed out.
     * </ul>
     */
    void (*on_recv_end)(ah_http_client_t* cln, ah_err_t err);

    /**
     * @a cln has been closed.
     *
     * @param cln Pointer to connection.
     * @param err Should always be @c AH_ENONE. Other codes may be provided if
     *            an unexpected platform error occurs.
     *
     * @note This function is guaranteed to be called after every call to
     *       ah_http_client_close(), which makes it an excellent place to
     *       release any resources associated with @a cln.
     */
    void (*on_close)(ah_http_client_t* cln, ah_err_t err);
};

/**
 * HTTP server.
 *
 * Servers are used to accept incoming HTTP clients, represented by
 * ah_http_client instances.
 *
 * Servers receive HTTP requests and send HTTP responses.
 *
 * @note All fields of this data structure are @e private in the sense that a
 *       user of this API should not access them directly.
 */
struct ah_http_server {
    AH_I_HTTP_SERVER_FIELDS
};

/**
 * HTTP server callback set.
 *
 * A set of function pointers used to handle events on HTTP servers.
 */
struct ah_http_server_cbs {
    /**
     * @a srv has been opened, or the attempt failed.
     *
     * @param srv Pointer to server.
     * @param err One of the following codes: <ul>
     *   <li><b>AH_ENONE</b>                          - Server opened successfully.
     *   <li><b>AH_EACCESS [Darwin, Linux]</b>        - Not permitted to open TCP listener.
     *   <li><b>AH_EADDRINUSE</b>                     - Specified local address already in use.
     *   <li><b>AH_EADDRNOTAVAIL</b>                  - No available local network interface is
     *                                                  associated with the given local address.
     *   <li><b>AH_EAFNOSUPPORT</b>                   - Specified IP version not supported.
     *   <li><b>AH_ECANCELED</b>                      - Server event loop is shutting down.
     *   <li><b>AH_EMFILE [Darwin, Linux, Win32]</b>  - Process descriptor table is full.
     *   <li><b>AH_ENETDOWN [Win32]</b>               - The network subsystem has failed.
     *   <li><b>AH_ENFILE [Darwin, Linux]</b>         - System file table is full.
     *   <li><b>AH_ENOBUFS [Darwin, Linux, Win32]</b> - Not enough buffer space available.
     *   <li><b>AH_ENOMEM [Darwin, Linux]</b>         - Not enough heap memory available.
     * </ul>
     */
    void (*on_open)(ah_http_server_t* srv, ah_err_t err);

    /**
     * @a srv has started to listen for connecting clients, or the attempt
     * failed.
     *
     * @param srv Pointer to server.
     * @param err One of the following codes: <ul>
     *   <li><b>AH_ENONE</b>                     - Server started to listen successfully.
     *   <li><b>AH_EACCESS [Darwin]</b>          - Not permitted to listen for TCP connections.
     *   <li><b>AH_EADDRINUSE [Linux, Win32]</b> - No ephemeral TCP port is available. This error
     *                                             can only occur if the server was opened with the
     *                                             wildcard address, which means that network
     *                                             interface binding is delayed until listening.
     *   <li><b>AH_ECANCELED</b>                 - Server event loop is shutting down.
     *   <li><b>AH_ENETDOWN [Win32]</b>          - The network subsystem has failed.
     *   <li><b>AH_ENFILE [Win32]</b>            - System file table is full.
     *   <li><b>AH_ENOBUFS [Win32]</b>           - Not enough buffer space available.
     * </ul>
     */
    void (*on_listen)(ah_http_server_t* srv, ah_err_t err);

    /**
     * @a srv has accepted the client @a cln.
     *
     * If @a err is @c AH_ENONE, which indicates a successful acceptance, all
     * further events related to @a cln will be dealt with via the client
     * callback set (see ah_http_client_cbs) provided when listening was started
     * via ah_http_server_listen().
     *
     * @param srv   Pointer to listener.
     * @param cln   Pointer to accepted client, or @c NULL if @a err is not
     *              @c AH_ENONE.
     * @param raddr Pointer to address of @a cln, or @c NULL if @a err is not
     *              @c AH_ENONE.
     * @param err  One of the following codes: <ul>
     *   <li><b>AH_ENONE</b>                         - Client accepted successfully.
     *   <li><b>AH_ECANCELED</b>                     - Server event loop is shutting down.
     *   <li><b>AH_ECONNABORTED [Darwin, Linux]</b>  - Connection aborted before finalization.
     *   <li><b>AH_ECONNRESET [Win32]</b>            - Connection aborted before finalization.
     *   <li><b>AH_EMFILE [Darwin, Linux, Win32]</b> - Process descriptor table is full.
     *   <li><b>AH_ENETDOWN [Win32]</b>              - The network subsystem has failed.
     *   <li><b>AH_ENFILE [Darwin, Linux]</b>        - System file table is full.
     *   <li><b>AH_ENOBUFS [Linux, Win32]</b>        - Not enough buffer space available.
     *   <li><b>AH_ENOMEM [Darwin, Linux]</b>        - Not enough heap memory available.
     *   <li><b>AH_EPROVIDERFAILEDINIT [Win32]</b>   - Network service failed to initialize.
     * </ul>
     *
     * @note Every successfully accepted @a cln must eventually be provided to
     *       ah_http_client_close().
     *
     * @note In contrast to plain TCP connections, data receiving is always
     *       enabled for new HTTP connections.
     */
    void (*on_accept)(ah_http_server_t* srv, ah_http_client_t* client, ah_err_t err);

    /**
     * @a srv has been closed.
     *
     * @param srv Pointer to server.
     * @param err Should always be @c AH_ENONE. Other codes may be provided if
     *            an unexpected platform error occurs.
     */
    void (*on_close)(ah_http_server_t* srv, ah_err_t err);
};

/**
 * HTTP version indicator.
 *
 * Its major and minor versions are only valid if they are in the range [0,9].
 *
 * @see https://www.rfc-editor.org/rfc/rfc9112#section-2.3
 */
struct ah_http_ver {
    uint8_t major; /**< Major version indicator. Must be between 0 and 9. */
    uint8_t minor; /**< Minor version indicator. Must be between 0 and 9. */
};

/**
 * HTTP header field, which is a name/value pair.
 *
 * Concretely consists of two NULL-terminated C strings. The data structure is
 * used to represent headers in both sent and received HTTP messages.
 */
struct ah_http_header {
    const char* name;  /**< Header name. Case insensitive. */
    const char* value; /**< Header values. Case sensitive. */
};

/**
 * HTTP start line and field lines.
 *
 * Gathers meta-information that must be including in sent HTTP requests and
 * responses.
 *
 * @note Some fields of this data structure are @e private in the sense that a
 *       user of this API should not access them directly. All private fields
 *       have names beginning with an underscore.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9112#section-2
 */
struct ah_http_head {
    /**
     * Start line, excluding HTTP version.
     *
     * As the field is provided as a plain NULL-terminated C string, it is up to
     * you to make sure its contents are correct. If this ah_http_head is used
     * in a sent \e request, it must contain a \e method and \e target separated
     * by a single space (e.g. <code>"GET /objects/143"</code>). If it is used
     * in a sent \e response, it must contain a three digit <em>status
     * code</em>, a space, and a <em>reason phrase</em> consisting of zero or
     * more characters (e.g. <code>"400 Not Found"</code>, or
     * <code>"200 "</code>. The position of the HTTP version relative to this
     * field is handled automatically.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9112#section-3
     * @see https://www.rfc-editor.org/rfc/rfc9112#section-4
     */
    const char* line;

    /**
     * HTTP version of request.
     *
     * @note Only HTTP versions 1.* are currently supported by this library.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9112#section-2.3
     */
    ah_http_ver_t version;

    /**
     * Pointer to array of headers, terminated by a <code>{ NULL, NULL }</code>
     * header, or @c NULL.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9112#section-5
     */
    ah_http_header_t* headers;

    AH_I_HTTP_HEAD_FIELDS
};

/**
 * HTTP chunk, including data and an arbitrary extension.
 *
 * Used with ah_http_client_send_chunk() to send chunked HTTP messages.
 *
 * @note Some fields of this data structure are @e private in the sense that a
 *       user of this API should not access them directly. All private fields
 *       have names beginning with an underscore.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9112#section-7.1
 */
struct ah_http_chunk {
    /**
     * Arbitrary chunk extension.
     *
     * This field must be @c NULL, contain an empty NULL-terminated string, or
     * adhere to the @c chunk-ext syntax outlined in RFC9112.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9112#section-7.1.1
     */
    const char* ext;

    /**
     * Data to include in chunk.
     *
     * The size of the @c buf of this field will be used as @c chunk-size when
     * this chunk is sent.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9112#section-7.1
     */
    ah_tcp_out_t data;

    AH_I_HTTP_CHUNK_FIELDS
};

/**
 * Last chunk extension and trailer section of a chunked HTTP message.
 *
 * An instance of this message is used to end a chunked HTTP transmission in a
 * call to ah_http_client_send_trailer(). It allows for you to specify an
 * extension for the @c last-chunk and any headers for the @c trailer-section.
 *
 * @note Some fields of this data structure are @e private in the sense that a
 *       user of this API should not access them directly. All private fields
 *       have names beginning with an underscore.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9112#section-7.1
 * @see https://www.rfc-editor.org/rfc/rfc9112#section-7.1.2
 */
struct ah_http_trailer {
    /**
     * Arbitrary chunk extension.
     *
     * This field must be @c NULL, contain an empty NULL-terminated string, or
     * adhere to the @c chunk-ext syntax outlined in RFC9112.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9112#section-7.1.1
     */
    const char* ext;

    /**
     * Pointer to array of headers, terminated by a <code>{ NULL, NULL }</code>
     * header, or @c NULL.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9112#section-5
     */
    ah_http_header_t* headers;

    AH_I_HTTP_TRAILER_FIELDS
};

/**
 * Initializes @a cln for subsequent use.
 *
 * @param cln   Pointer to client.
 * @param loop  Pointer to event loop.
 * @param trans Desired transport.
 * @param cbs   Pointer to event callback set.
 * @return One of the following error codes: <ul>
 *   <li><b>AH_ENONE</b>  - @a cln successfully initialized.
 *   <li><b>AH_EINVAL</b> - @a cln or @a loop or @a cbs is @c NULL.
 *   <li><b>AH_EINVAL</b> - @a trans @c vtab is invalid, as reported by ah_tcp_vtab_is_valid().
 *   <li><b>AH_EINVAL</b> - @c on_open, @c on_connect, @c on_send, @c on_recv_line,
 *                          @c on_recv_header, @c on_recv_data, @c on_recv_end, or @c on_close of
 *                          @a cbs is @c NULL.
 * </ul>
 */
ah_extern ah_err_t ah_http_client_init(ah_http_client_t* cln, ah_loop_t* loop, ah_tcp_trans_t trans, const ah_http_client_cbs_t* cbs);

/**
 * Schedules opening of @a cln, which must be initialized, and its binding to
 * the local network interface represented by @a laddr.
 *
 * If the return value of this function is @c AH_ENONE, meaning that the open
 * attempt could indeed be scheduled, its result will eventually be presented
 * via the ah_http_client_cbs::on_open callback of @a cln.
 *
 * @param cln   Pointer to client.
 * @param laddr Pointer to socket address representing a local network interface
 *              through which the client connection must later be established.
 *              If opening is successful, the referenced address must remain
 *              valid for the entire lifetime of the created client. To bind to
 *              all or any local network interface, provide the wildcard address
 *              (see ah_sockaddr_ipv4_wildcard and ah_sockaddr_ipv6_wildcard).
 *              If you want the platform to chose port number automatically,
 *              specify port @c 0.
 * @return One of the following error codes: <ul>
 *   <li><b>AH_ENONE</b>        - @a cln opening successfully scheduled.
 *   <li><b>AH_EAFNOSUPPORT</b> - @a laddr is not @c NULL and is not an IP-based address.
 *   <li><b>AH_ECANCELED</b>    - The event loop of @a cln is shutting down.
 *   <li><b>AH_EINVAL</b>       - @a cln is @c NULL.
 *   <li><b>AH_ENOBUFS</b>      - Not enough buffer space available.
 *   <li><b>AH_ENOMEM</b>       - Not enough heap memory available.
 *   <li><b>AH_ESTATE</b>       - @a cln is not closed.
 * </ul>
 *
 * @note Every successfully opened @a cln must eventually be provided to
 *       ah_http_client_close().
 */
ah_extern ah_err_t ah_http_client_open(ah_http_client_t* cln, const ah_sockaddr_t* laddr);

/**
 * Schedules connection of @a cln, which must be open, to @a raddr.
 *
 * If the return value of this function is @c AH_ENONE, meaning that connection
 * could indeed be scheduled, its result will eventually be presented via the
 * ah_http_client_cbs::on_connect callback of @a cln.
 *
 * @param cln   Pointer to client.
 * @param raddr Pointer to socket address representing the remote host to which
 *              the client connection is to be established. If connection is
 *              successful, the referenced address must remain valid until
 *              @a cln is closed.
 * @return One of the following error codes: <ul>
 *   <li><b>AH_ENONE</b>        - @a cln opening successfully scheduled.
 *   <li><b>AH_EAFNOSUPPORT</b> - @a raddr is not an IP-based address.
 *   <li><b>AH_ECANCELED</b>    - The event loop of @a cln is shutting down.
 *   <li><b>AH_EINVAL</b>       - @a cln or @a raddr is @c NULL.
 *   <li><b>AH_ENOBUFS</b>      - Not enough buffer space available.
 *   <li><b>AH_ENOMEM</b>       - Not enough heap memory available.
 *   <li><b>AH_ESTATE</b>       - @a cln is not open.
 * </ul>
 *
 * @warning This function must be called with a successfully opened connection.
 *          An appropriate place to call this function is often going to be in
 *          an ah_http_client_cbs::on_open callback after a check that opening
 *          was successful.
 */
ah_extern ah_err_t ah_http_client_connect(ah_http_client_t* cln, const ah_sockaddr_t* raddr);

/**
 * Schedules sending of HTTP message head.
 *
 * Calling this function initiates the send procedure by enqueuing the
 * transmission of the message start line and headers. You must finalize that
 * procedure in one out of three ways, depending on if an HTTP body is to be
 * included in the message and, if so, that body has a size known when starting
 * to send it it or not. The following table specifies what functions to call
 * to finalize the procedure in one of these ways:
 *
 * <table>
 *   <caption id="http-send-procedures">Possible Continuations of the Send Procedure</caption>
 *   <tr>
 *     <th>Prerequisite
 *     <th>Description
 *   <tr>
 *     <td>No body
 *     <td>Call ah_http_client_send_end().
 *   <tr>
 *     <td>Body with initially known size
 *     <td>Call ah_http_client_send_data() until there is no more
 *         data to send. Finally, call ah_http_client_send_end().
 *   <tr>
 *     <td>Body with initially unknown size
 *     <td>Call ah_http_client_send_chunk() until there is no more
 *         data to send. Finally, call ah_http_client_send_trailer().
 * </table>
 *
 * The invocation of this function must be successful in order for it to be
 * possible to follow any of the above procedures. Please refer to the
 * documentation for the functions in the above table for further details.
 *
 * @param cln  Pointer to client.
 * @param head Pointer to head, specifying a start line and set of headers.
 * @return One of the following error codes: <ul>
 *   <li><b>AH_ENONE</b>           - Transmission of @a head enqueued successfully.
 *   <li><b>AH_EINVAL</b>          - @a cln or @a head is @c NULL.
 *   <li><b>AH_EPROTONOSUPPORT</b> - The HTTP version specified in
 *                                   <code>head->version</code> is not
 *                                   supported.
 * </ul>
 */
ah_extern ah_err_t ah_http_client_send_head(ah_http_client_t* cln, ah_http_head_t* head);

/**
 * Schedules sending of HTTP message body data.
 *
 * This function is used to continue the send procedure, which must have been
 * initiated for @a cln via a call to ah_http_client_send_head(). It is meant to
 * be used when a @c Content-Length header is specified in the head with a value
 * larger than zero. The function schedules the transmission of some or all of
 * the data indicated by that @c Content-Length. You must ensure that exactly
 * @c Content-Length bytes of body data is sent, via one or more calls to this
 * function, before ah_http_client_send_end() is called with @a cln to end the
 * message.
 *
 * @param cln Pointer to client.
 * @param out Pointer to TCP output buffer.
 * @return One of the following error codes: <ul>
 *   <li><b>AH_ENONE</b>            - Transmission of @a out enqueued successfully.
 *   <li><b>AH_ECANCELED</b>        - The event loop of @a cln is shutting down.
 *   <li><b>AH_EINVAL</b>           - @a cln or @a out is @c NULL.
 *   <li><b>AH_ENETDOWN [Win32]</b> - The network subsystem has failed.
 *   <li><b>AH_ENOBUFS</b>          - Not enough buffer space available.
 *   <li><b>AH_ENOMEM</b>           - Not enough heap memory available.
 *   <li><b>AH_ERANGE</b>           - The variable keeping track of the number
 *                                    of currently enqueued data transmissions
 *                                    would overflow if @a out was accepted.
 *   <li><b>AH_ESTATE</b>           - @a cln is not currently sending any HTTP
 *                                    message, @a cln is not open, or the write
 *                                    direction of the connection of @a cln has
 *                                    been shut down.
 * </ul>
 */
ah_extern ah_err_t ah_http_client_send_data(ah_http_client_t* cln, ah_tcp_out_t* out);

/**
 * Ends current HTTP message of @a cln.
 *
 * Call this function after a successful call to either
 * ah_http_client_send_head() or ah_http_client_send_data() to indicate that the
 * current message is complete.
 *
 * @param cln Pointer to client.
 * @return One of the following error codes: <ul>
 *   <li><b>AH_ENONE</b>  - Transmission of @a out ended successfully.
 *   <li><b>AH_EINVAL</b> - @a cln is @c NULL.
 *   <li><b>AH_ESTATE</b> - @a cln is not currently sending any HTTP message.
 * </ul>
 *
 * @note This function returning with the error code @c AH_ENONE, which
 *       indicates success, only means that all parts of the message have been
 *       enqueued. Whether or not their actual transmission is successful is
 *       reported later via ah_http_client_cbs::on_send.
 */
ah_extern ah_err_t ah_http_client_send_end(ah_http_client_t* cln);

/**
 * Schedules sending of HTTP message body data in the form of a @e chunk.
 *
 * This function is used to continue a send procedure initiated for @a cln via a
 * call to ah_http_client_send_head(). It is meant to be used when no
 * @c Content-Length header is specified in the head. Concretely, it schedules
 * the sending of @a chunk, which is sent asynchronously as soon as the
 * underlying TCP transport is able to. You may call this function with the same
 * @a cln as many times as you want before ending the sending procedure by
 * providing @a cln to ah_http_client_send_trailer().
 *
 * @param cln   Pointer to client.
 * @param chunk Pointer to chunk.
 * @return One of the following error codes: <ul>
 *   <li><b>AH_ENONE</b>            - Transmission of @a out enqueued successfully.
 *   <li><b>AH_ECANCELED</b>        - The event loop of @a cln is shutting down.
 *   <li><b>AH_EILSEQ</b>           - The @c ext field of @a chunk is not @c NULL, an empty
 *                                    NULL-terminated C string and it does not begin with a
 *                                    semicolon @c ;, which means that inserting @c ext into the
 *                                    chunk will make it syntactically invalid. <em>This error code
 *                                    is only returned when running in @c DEBUG mode.</em>
 *   <li><b>AH_EINVAL</b>           - @a cln or @a chunk is @c NULL.
 *   <li><b>AH_ENETDOWN [Win32]</b> - The network subsystem has failed.
 *   <li><b>AH_ENOBUFS</b>          - Not enough buffer space available.
 *   <li><b>AH_ENOMEM</b>           - Not enough heap memory available.
 *   <li><b>AH_EOVERFLOW</b>        - The used output buffer, which is always allocated via the page
 *                                    allocator (see ah_palloc()) is too small for it to be possible
 *                                    to store the @c size and @c ext specified in @a chunk.
 *   <li><b>AH_ERANGE</b>           - The variable keeping track of the number of currently enqueued
 *                                    data transmissions would overflow if @a chunk was accepted.
 *   <li><b>AH_ESTATE</b>           - @a cln is not currently sending any HTTP message, @a cln is
 *                                    not open, or the write direction of the connection of @a cln
 *                                    has been shut down.
 * </ul>
 */
ah_extern ah_err_t ah_http_client_send_chunk(ah_http_client_t* cln, ah_http_chunk_t* chunk);

/**
 * Schedules sending of last chunk and trailer of and ends the current message
 * of @a cln.
 *
 * Call this function after a successful call to either
 * ah_http_client_send_head() or ah_http_client_send_chunk() to send the last
 * chunk and trailer, as well as to indicate that the current message is
 * complete.
 *
 * @param cln     Pointer to client.
 * @param trailer Pointer to trailer.
 * @return One of the following error codes: <ul>
 *   <li><b>AH_ENONE</b>            - Transmission of @a trailer enqueued and current message ended
 *                                    successfully.
 *   <li><b>AH_ECANCELED</b>        - The event loop of @a cln is shutting down.
 *   <li><b>AH_EILSEQ</b>           - The @c ext field of @a trailer is not @c NULL, an empty
 *                                    NULL-terminated C string and it does not begin with a
 *                                    semicolon @c ;, which means that inserting @c ext into the
 *                                    last chunk will make it syntactically invalid. <em>This error
 *                                    code is only returned when running in @c DEBUG mode.</em>
 *   <li><b>AH_EINVAL</b>           - @a cln or @a trailer is @c NULL.
 *   <li><b>AH_ENETDOWN [Win32]</b> - The network subsystem has failed.
 *   <li><b>AH_ENOBUFS</b>          - Not enough buffer space available.
 *   <li><b>AH_ENOMEM</b>           - Not enough heap memory available.
 *   <li><b>AH_EOVERFLOW</b>        - The used output buffer, which is always allocated via the page
 *                                    allocator (see ah_palloc()) is too small for it to be possible
 *                                    to store the @c size and @c ext specified in @a trailer.
 *   <li><b>AH_ERANGE</b>           - The variable keeping track of the number of currently enqueued
 *                                    data transmissions would overflow if @a trailer was accepted.
 *   <li><b>AH_ESTATE</b>           - @a cln is not currently sending any HTTP message, @a cln is
 *                                    not open, or the write direction of the connection of @a cln
 *                                    has been shut down.
 * </ul>
 */
ah_extern ah_err_t ah_http_client_send_trailer(ah_http_client_t* cln, ah_http_trailer_t* trailer);

/**
 * Schedules closing of @a cln.
 *
 * If the return value of this function is @c AH_ENONE, meaning that the
 * closing could indeed be scheduled, its result will eventually be presented
 * via the ah_http_client_cbs::on_close callback of @a cln.
 *
 * @param cln Pointer to client.
 * @return One of the following error codes: <ul>
 *   <li><b>AH_ENONE</b>  - Close of @a cln successfully scheduled.
 *   <li><b>AH_EINVAL</b> - @a cln is @c NULL.
 *   <li><b>AH_ESTATE</b> - @a cln is already closed.
 * </ul>
 */
ah_extern ah_err_t ah_http_client_close(ah_http_client_t* cln);

/**
 * Gets the TCP connection of @a cln.
 *
 * @param cln Pointer to client.
 * @return Pointer to TCP connection of @a cln, or @c NULL if @a cln is @c NULL.
 */
ah_extern ah_tcp_conn_t* ah_http_client_get_conn(ah_http_client_t* cln);

/**
 * Stores local address bound by @a cln into @a laddr.
 *
 * If @a cln was opened with a zero port, this function will report what
 * concrete port was assigned to @a cln.
 *
 * @param cln   Pointer to client.
 * @param laddr Pointer to socket address to be set by this operation.
 * @return One of the following error codes: <ul>
 *   <li><b>AH_ENONE</b>                   - The operation was successful.
 *   <li><b>AH_EINVAL</b>                  - @a cln or @a laddr is @c NULL.
 *   <li><b>AH_ENETDOWN [Win32]</b>        - The network subsystem has failed.
 *   <li><b>AH_ENOBUFS [Darwin, Linux]</b> - Not enough buffer space available.
 *   <li><b>AH_ESTATE</b>                  - @a cln is closed.
 * </ul>
 */
ah_extern ah_err_t ah_http_client_get_laddr(const ah_http_client_t* cln, ah_sockaddr_t* laddr);

/**
 * Stores remote address of @a cln into @a raddr.
 *
 * @param cln   Pointer to client.
 * @param raddr Pointer to socket address to be set by this operation.
 * @return One of the following error codes: <ul>
 *   <li><b>AH_ENONE</b>                   - The operation was successful.
 *   <li><b>AH_EINVAL</b>                  - @a cln or @a raddr is @c NULL.
 *   <li><b>AH_ENETDOWN [Win32]</b>        - The network subsystem has failed.
 *   <li><b>AH_ENOBUFS [Darwin, Linux]</b> - Not enough buffer space available.
 *   <li><b>AH_ESTATE</b>                  - @a cln is not connected to a remote host.
 * </ul>
 */
ah_extern ah_err_t ah_http_client_get_raddr(const ah_http_client_t* cln, ah_sockaddr_t* raddr);

/**
 * Gets pointer to event loop of @a cln.
 *
 * @param cln Pointer to client.
 * @return Pointer to event loop, or @c NULL if @a cln is @c NULL.
 */
ah_extern ah_loop_t* ah_http_client_get_loop(const ah_http_client_t* cln);

/**
 * Gets the user data pointer associated with @a cln.
 *
 * @param cln Pointer to client.
 * @return Any user data pointer previously set via
 *         ah_http_client_set_user_data(), or @c NULL if no such has been set or
 *         if @a cln is @c NULL.
 *
 * @note This function gets the user data pointer of the ah_tcp_conn owned by
 *       @a cln, which you can get a pointer to by calling
 *       ah_http_client_get_conn() with @a cln as argument.
 */
ah_extern void* ah_http_client_get_user_data(const ah_http_client_t* cln);

/**
 * Sets the user data pointer associated with @a cln.
 *
 * @param cln       Pointer to client.
 * @param user_data User data pointer, referring to whatever context you want
 *                  to associate with @a cln.
 *
 * @note If @a cln is @c NULL, this function does nothing.
 *
 * @note This function sets the user data pointer of the ah_tcp_conn owned by
 *       @a cln, which you can get a pointer to by calling
 *       ah_http_client_get_conn() with @a cln as argument.
 */
ah_extern void ah_http_client_set_user_data(ah_http_client_t* cln, void* user_data);

ah_extern ah_err_t ah_http_server_init(ah_http_server_t* srv, ah_loop_t* loop, ah_tcp_trans_t trans, const ah_http_server_cbs_t* cbs);
ah_extern ah_err_t ah_http_server_open(ah_http_server_t* srv, const ah_sockaddr_t* laddr);
ah_extern ah_err_t ah_http_server_listen(ah_http_server_t* srv, unsigned backlog, const ah_http_client_cbs_t* cbs);
ah_extern ah_err_t ah_http_server_close(ah_http_server_t* srv);
ah_extern ah_err_t ah_http_server_term(ah_http_server_t* srv);
ah_extern ah_tcp_listener_t* ah_http_server_get_listener(ah_http_server_t* srv);
ah_extern ah_err_t ah_http_server_get_laddr(const ah_http_server_t* srv, ah_sockaddr_t* laddr);
ah_extern ah_loop_t* ah_http_server_get_loop(const ah_http_server_t* srv);
ah_extern void* ah_http_server_get_user_data(const ah_http_server_t* srv);
ah_extern void ah_http_server_set_user_data(ah_http_server_t* srv, void* user_data);

#endif
