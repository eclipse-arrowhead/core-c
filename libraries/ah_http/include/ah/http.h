// SPDX-License-Identifier: EPL-2.0

#ifndef AH_HTTP_H_
#define AH_HTTP_H_

/**
 * @file
 * HTTP/1 client and server.
 *
 * Here, data structures and functions are provided for representing, setting up
 * and communicating via HTTP/1 clients and servers. To learn more about the
 * HTTP/1 protocol itself, please refer to
 * <a href="https://rfc-editor.org/rfc/rfc9110.html">RFC9110</a>. Below, we
 * briefly describe how to use this C API.
 *
 * <h3>Clients</h3>
 *
 * HTTP clients are set up using ah_http_client_init(), ah_http_client_open()
 * and ah_http_client_connect(), in that order. Successfully opened clients are
 * closed with ah_http_client_close(). Every client receives data, and is
 * notified of other events, via a callback set of type ah_http_client_cbs. To
 * send a message, you must provide a certain client with a @e head, a number of
 * <em>body parts</em> and indicate the end of the message. The head and body
 * parts are added to the <em>send queue</em> of the client, which is processed
 * and emptied asynchronously when possible. The message head, which consists of
 * a <em>start line</em> and zero or more headers, is added by a call to
 * ah_http_client_send_head(). After a head has been successfully submitted, you
 * must continue in one of the following ways:
 *
 * <ol>
 *   <li>If <em>no message body</em> is to be sent, call ah_http_client_send_end() directly.
 *   <li>If a <em>non-chunked body</em> is to be sent, which is recommended when the final size of
 *       the send body is @e known in advance, call ah_http_client_send_data() repeatedly until all
 *       body parts have been added. Finally, call ah_http_client_send_end() to end the message.
 *   <li>If a <em>chunked body</em> is to be sent, which is recommended when the final size of the
 *       send body is <em>not known</em> in advance, call ah_http_client_send_chunk() repeatedly
 *       until all body chunks have been added. Finally, call ah_http_client_send_trailer() to
 *       submit any last chunk extension and trailer headers, as well as to indicate the end of the
 *       current message.
 * </ol>
 *
 * When sending and receiving @e metadata, such as start lines, headers and
 * chunks, that metadata is gathered automatically into dynamically allocated
 * buffers. Each client owns one such buffer it reuses for all data it receives.
 * Another is allocated for the duration of each on-going message send
 * procedure. If a certain metadata item, such as a header or chunk extension,
 * exceeds the size of its receive buffer, or a send buffer is too small to
 * contain @e all relevant metadata items, the message transmission is failed
 * with error code @ref AH_EOVERFLOW. Limiting sizes in this way helps reduce
 * the complexity the client implementation and works as a form of protection
 * from exploits that use large metadata items. Generally, the size of each of
 * these buffers will be limited by the page allocator page size, @c AH_PSIZE,
 * more of which you can read in the documentation for ah_palloc().
 *
 * <h3>Servers</h3>
 *
 * HTTP servers are set up using ah_http_server_init(), ah_http_server_open()
 * and ah_http_server_listen(). Successfully initialized servers are
 * terminated with ah_http_server_term() and successfully opened servers are
 * closed with ah_http_server_close(). Servers receive incoming clients and are
 * notified of other events via their callback sets, which are of type
 * ah_http_server_cbs.
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
 *     <td>@c Connection
 *     <td>The options (1) @c close and (2) @c keep-alive automatically cause HTTP connections to
 *         either (1) be closed after the current request/response exchange or (2) remain open
 *         between exchanges. Which of the two behaviors represented by these options is the default
 *         varies between HTTP versions. In version 1.0 @c close is the default, while on all
 *         subsequent versions @c keep-alive is the default.
 *   <tr>
 *     <td>@c Content-Length
 *     <td>When receiving incoming requests and responses, the @c Content-Length is used
 *         automatically to determine when and if a message body is expected, and when all of it has
 *         been received. Incoming messages that neither specify a @c Content-Length nor
 *         <code>Transfer-Encoding: chunked</code> are assumed to not have bodies at all. Note that
 *         no @c Content-Length header is added automatically to sent requests or responses. You
 *         must make sure to add it when relevant.
 *   <tr>
 *     <td>@c Host
 *     <td>When sending requests, if this header is left unspecified and the used HTTP version is
 *         1.1 or higher, the header is automatically populated with the IP address and port number
 *         of the targeted server.
 *   <tr>
 *     <td>@c Transfer-Encoding
 *     <td>If <code>Transfer-Encoding: chunked</code> is specified in an incoming request or
 *         response, the individual chunks are decoded and presented automatically. Other transfer
 *         encoding options are ignored. This means that body compression and decompression is not
 *         handled automatically.
 * </table>
 *
 * @see https://rfc-editor.org/rfc/rfc9110.html
 * @see https://rfc-editor.org/rfc/rfc9112.html
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
     *   <li>@ref AH_ENONE                          - Client opened successfully.
     *   <li>@ref AH_EACCES [Darwin, Linux]         - Not permitted to open TCP connection.
     *   <li>@ref AH_EADDRINUSE                     - Specified local address already in use.
     *   <li>@ref AH_EADDRNOTAVAIL                  - No available local network interface is
     *                                                associated with the given local address.
     *   <li>@ref AH_EAFNOSUPPORT                   - Specified IP version not supported.
     *   <li>@ref AH_ECANCELED                      - Client event loop is shutting down.
     *   <li>@ref AH_EMFILE [Darwin, Linux, Win32]  - Process descriptor table is full.
     *   <li>@ref AH_ENETDOWN [Win32]               - The network subsystem has failed.
     *   <li>@ref AH_ENFILE [Darwin, Linux]         - System file table is full.
     *   <li>@ref AH_ENOBUFS [Darwin, Linux, Win32] - Not enough buffer space available.
     *   <li>@ref AH_ENOMEM [Darwin, Linux]         - Not enough heap memory available.
     *   <li>@ref AH_EPROVIDERFAILEDINIT [Win32]    - Network service failed to initialize.
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
     *   <li>@ref AH_ENONE                             - Connection established successfully.
     *   <li>@ref AH_EADDRINUSE [Darwin, Linux, Win32] - Failed to bind a concrete local address.
     *                                                   This error only occurs if the client was
     *                                                   opened with the wildcard address, which
     *                                                   means that network interface binding is
     *                                                   delayed until connection.
     *   <li>@ref AH_EADDRNOTAVAIL [Darwin, Win32]     - The specified remote address is invalid.
     *   <li>@ref AH_EADDRNOTAVAIL [Linux]             - No ephemeral TCP port is available.
     *   <li>@ref AH_EAFNOSUPPORT                      - The IP version of the specified remote
     *                                                   address does not match that of the bound
     *                                                   local address.
     *   <li>@ref AH_ECANCELED                         - The event loop of @a cln has shut down.
     *   <li>@ref AH_ECONNREFUSED                      - Connection attempt ignored or rejected by
     *                                                   targeted remote host.
     *   <li>@ref AH_ECONNRESET [Darwin]               - Connection attempt reset by targeted
     *                                                   remote host.
     *   <li>@ref AH_EHOSTUNREACH                      - The targeted remote host could not be
     *                                                   reached.
     *   <li>@ref AH_ENETDOWN [Darwin]                 - Local network not online.
     *   <li>@ref AH_ENETDOWN [Win32]                  - The network subsystem has failed.
     *   <li>@ref AH_ENETUNREACH                       - Network of targeted remote host not
     *                                                   reachable.
     *   <li>@ref AH_ENOBUFS                           - Not enough buffer space available.
     *   <li>@ref AH_ENOMEM                            - Not enough heap memory available.
     *   <li>@ref AH_ETIMEDOUT                         - The connection attempt did not complete
     *                                                   before its deadline.
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
     * which case @a err is @ref AH_ENONE, or if sending it failed, which should
     * prompt you to close @a cln using ah_http_client_close().
     *
     * @param cln  Pointer to client.
     * @param head Pointer to ah_http_head instance provided earlier to
     *             ah_http_client_send_head().
     * @param err  One of the following codes: <ul>
     *   <li>@ref AH_ENONE                             - Message sent successfully.
     *   <li>@ref AH_ECANCELED                         - Client event loop is shutting down or it
     *                                                   was closed before the message represented
     *                                                   by @a head could be transmitted.
     *   <li>@ref AH_ECONNABORTED [Win32]              - Virtual circuit terminated due to time-out
     *                                                   or other failure.
     *   <li>@ref AH_ECONNRESET [Darwin, Linux, Win32] - Client connection reset by remote host.
     *   <li>@ref AH_EEOF                              - Client connection closed for writing.
     *   <li>@ref AH_ENETDOWN [Darwin]                 - Local network not online.
     *   <li>@ref AH_ENETDOWN [Win32]                  - The network subsystem has failed.
     *   <li>@ref AH_ENETRESET [Win32]                 - Keep-alive is enabled for the connection
     *                                                   and a related failure was detected.
     *   <li>@ref AH_ENETUNREACH [Darwin]              - Network of remote host not reachable.
     *   <li>@ref AH_ENOBUFS [Darwin, Linux, Win32]    - Not enough buffer space available.
     *   <li>@ref AH_ENOMEM                            - Not enough heap memory available.
     *   <li>@ref AH_EOVERFLOW                         - The used output buffer, which is always
     *                                                   allocated via the page allocator (see
     *                                                   ah_palloc()) is too small for it to be
     *                                                   possible to store the start line, headers
     *                                                   and/or chunk extension of some
     *                                                   ah_http_head, ah_http_chunk or
     *                                                   ah_http_trailer part of the message
     *                                                   transmission.
     *   <li>@ref AH_ETIMEDOUT                         - Client connection timed out.
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
     * @see https://rfc-editor.org/rfc/rfc9112.html
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
     * @see https://rfc-editor.org/rfc/rfc9112.html
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
     * the @ref AH_EOVERFLOW error. If you wish to save the contents of @a in
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
     * @ref AH_ENONE), or if connection keep-alive is disabled, the client will be
     * closed automatically at some point after this function returns.
     *
     * @param cln Pointer to client.
     * @param err One of the following codes: <ul>
     *   <li>@ref AH_ENONE                      - Message received successfully.
     *   <li>@ref AH_EBADMSG                    - Message metadata violates HTTP specification.
     *   <li>@ref AH_ECANCELED                  - Client event loop is shutting down.
     *   <li>@ref AH_ECONNABORTED [Win32]       - Virtual circuit terminated due to time-out or
     *                                            other failure.
     *   <li>@ref AH_ECONNRESET [Darwin, Win32] - Connection reset by remote host.
     *   <li>@ref AH_EDISCON [Win32]            - Connection gracefully closed by remote host.
     *   <li>@ref AH_EDUP                       - Supported header or header value that may only
     *                                            occur once has been seen multiple times.
     *   <li>@ref AH_EEOF                       - Connection closed for reading.
     *   <li>@ref AH_ESYNTAX                    - Message syntax not valid according to RFC9112.
     *   <li>@ref AH_ENETDOWN [Win32]           - The network subsystem has failed.
     *   <li>@ref AH_ENETRESET [Win32]          - Keep-alive is enabled for the connection and a
     *                                            related failure was detected.
     *   <li>@ref AH_ENOBUFS                    - Not enough buffer space available.
     *   <li>@ref AH_ENOMEM                     - Not enough heap memory available.
     *   <li>@ref AH_EOVERFLOW                  - The input buffer of @a cln is full. To prevent
     *                                            this error from occurring when receiving body
     *                                            data, you must ensure that the input buffer
     *                                            never gets exhausted by reading, discarding,
     *                                            repackaging or detaching its contents. The same
     *                                            error also occurs when a received metadata item
     *                                            is too large, which can only be avoided by the
     *                                            sender ensuring that no individual start line,
     *                                            header or chunk line exceeds the size
     *                                            @c AH_TCP_IN_BUF_SIZE.
     *   <li>@ref AH_EPROTONOSUPPORT            - Received message uses an unsupported version of
     *                                            HTTP.
     *   <li>@ref AH_ETIMEDOUT                  - Connection timed out.
     * </ul>
     */
    void (*on_recv_end)(ah_http_client_t* cln, ah_err_t err);

    /**
     * @a cln has been closed.
     *
     * @param cln Pointer to connection.
     * @param err Should always be @ref AH_ENONE. Other codes may be provided if
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
     *   <li>@ref AH_ENONE                          - Server opened successfully.
     *   <li>@ref AH_EACCES [Darwin, Linux]         - Not permitted to open TCP listener.
     *   <li>@ref AH_EADDRINUSE                     - Specified local address already in use.
     *   <li>@ref AH_EADDRNOTAVAIL                  - No available local network interface is
     *                                                associated with the given local address.
     *   <li>@ref AH_EAFNOSUPPORT                   - Specified IP version not supported.
     *   <li>@ref AH_ECANCELED                      - Server event loop is shutting down.
     *   <li>@ref AH_EMFILE [Darwin, Linux, Win32]  - Process descriptor table is full.
     *   <li>@ref AH_ENETDOWN [Win32]               - The network subsystem has failed.
     *   <li>@ref AH_ENFILE [Darwin, Linux]         - System file table is full.
     *   <li>@ref AH_ENOBUFS [Darwin, Linux, Win32] - Not enough buffer space available.
     *   <li>@ref AH_ENOMEM [Darwin, Linux]         - Not enough heap memory available.
     * </ul>
     */
    void (*on_open)(ah_http_server_t* srv, ah_err_t err);

    /**
     * @a srv has started to listen for connecting clients, or the attempt
     * failed.
     *
     * @param srv Pointer to server.
     * @param err One of the following codes: <ul>
     *   <li>@ref AH_ENONE                     - Server started to listen successfully.
     *   <li>@ref AH_EACCES [Darwin]           - Not permitted to listen for TCP connections.
     *   <li>@ref AH_EADDRINUSE [Linux, Win32] - No ephemeral TCP port is available. This error
     *                                           can only occur if the server was opened with the
     *                                           wildcard address, which means that network
     *                                           interface binding is delayed until listening.
     *   <li>@ref AH_ECANCELED                 - Server event loop is shutting down.
     *   <li>@ref AH_ENETDOWN [Win32]          - The network subsystem has failed.
     *   <li>@ref AH_ENFILE [Win32]            - System file table is full.
     *   <li>@ref AH_ENOBUFS [Win32]           - Not enough buffer space available.
     * </ul>
     */
    void (*on_listen)(ah_http_server_t* srv, ah_err_t err);

    /**
     * @a srv has accepted the client @a cln.
     *
     * If @a err is @ref AH_ENONE, which indicates a successful acceptance, all
     * further events related to @a cln will be dealt with via the client
     * callback set (see ah_http_client_cbs) provided when listening was started
     * via ah_http_server_listen().
     *
     * @param srv   Pointer to listener.
     * @param cln   Pointer to accepted client, or @c NULL if @a err is not
     *              @ref AH_ENONE.
     * @param raddr Pointer to address of @a cln, or @c NULL if @a err is not
     *              @ref AH_ENONE.
     * @param err  One of the following codes: <ul>
     *   <li>@ref AH_ENONE                         - Client accepted successfully.
     *   <li>@ref AH_ECANCELED                     - Server event loop is shutting down.
     *   <li>@ref AH_ECONNABORTED [Darwin, Linux]  - Connection aborted before finalization.
     *   <li>@ref AH_ECONNRESET [Win32]            - Connection aborted before finalization.
     *   <li>@ref AH_EMFILE [Darwin, Linux, Win32] - Process descriptor table is full.
     *   <li>@ref AH_ENETDOWN [Win32]              - The network subsystem has failed.
     *   <li>@ref AH_ENFILE [Darwin, Linux]        - System file table is full.
     *   <li>@ref AH_ENOBUFS [Linux, Win32]        - Not enough buffer space available.
     *   <li>@ref AH_ENOMEM [Darwin, Linux]        - Not enough heap memory available.
     *   <li>@ref AH_EPROVIDERFAILEDINIT [Win32]   - Network service failed to initialize.
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
     * @param err Should always be @ref AH_ENONE. Other codes may be provided if
     *            an unexpected platform error occurs.
     *
     * @note This function is guaranteed to be called after every call to
     *       ah_http_server_close(), which makes it an excellent place to
     *       release any resources associated with @a srv. You may, for example,
     *       elect to call ah_http_server_term() in this callback.
     */
    void (*on_close)(ah_http_server_t* srv, ah_err_t err);
};

/**
 * HTTP version indicator.
 *
 * Its major and minor versions are only valid if they are in the range [0,9].
 *
 * @see https://rfc-editor.org/rfc/rfc9112#section-2.3
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
 * @see https://rfc-editor.org/rfc/rfc9112#section-2
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
     * @see https://rfc-editor.org/rfc/rfc9112#section-3
     * @see https://rfc-editor.org/rfc/rfc9112#section-4
     */
    const char* line;

    /**
     * HTTP version of request.
     *
     * @note Only HTTP versions 1.* are currently supported by this library.
     *
     * @see https://rfc-editor.org/rfc/rfc9112#section-2.3
     */
    ah_http_ver_t version;

    /**
     * Pointer to array of headers, terminated by a <code>{ NULL, NULL }</code>
     * header, or @c NULL.
     *
     * @see https://rfc-editor.org/rfc/rfc9112#section-5
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
 * @see https://rfc-editor.org/rfc/rfc9112#section-7.1
 */
struct ah_http_chunk {
    /**
     * Arbitrary chunk extension.
     *
     * This field must be @c NULL, contain an empty NULL-terminated string, or
     * adhere to the @c chunk-ext syntax outlined in RFC9112.
     *
     * @see https://rfc-editor.org/rfc/rfc9112#section-7.1.1
     */
    const char* ext;

    /**
     * Data to include in chunk.
     *
     * The size of the @c buf of this field will be used as @c chunk-size when
     * this chunk is sent.
     *
     * @see https://rfc-editor.org/rfc/rfc9112#section-7.1
     */
    ah_tcp_out_t data;

    AH_I_HTTP_CHUNK_FIELDS
};

/**
 * HTTP chunked message end, consisting of a last chunk extension and a trailer.
 *
 * An instance of this message is used to end a chunked HTTP transmission in a
 * call to ah_http_client_send_trailer(). It allows for you to specify an
 * extension for the @c last-chunk and any headers for the @c trailer-section.
 *
 * @note Some fields of this data structure are @e private in the sense that a
 *       user of this API should not access them directly. All private fields
 *       have names beginning with an underscore.
 *
 * @see https://rfc-editor.org/rfc/rfc9112#section-7.1
 * @see https://rfc-editor.org/rfc/rfc9112#section-7.1.2
 */
struct ah_http_trailer {
    /**
     * Arbitrary chunk extension.
     *
     * This field must be @c NULL, contain an empty NULL-terminated string, or
     * adhere to the @c chunk-ext syntax outlined in RFC9112.
     *
     * @see https://rfc-editor.org/rfc/rfc9112#section-7.1.1
     */
    const char* ext;

    /**
     * Pointer to array of headers, terminated by a <code>{ NULL, NULL }</code>
     * header, or @c NULL.
     *
     * @see https://rfc-editor.org/rfc/rfc9112#section-5
     */
    ah_http_header_t* headers;

    AH_I_HTTP_TRAILER_FIELDS
};

/**
 * @name HTTP Client
 *
 * Operations on ah_http_client instances. All such instances must be
 * initialized using ah_http_client_init() before they are provided to any other
 * functions listed here. Any other requirements regarding the state of clients
 * are described in the documentation of each respective function, sometimes
 * only via the error codes it lists.
 *
 * @{
 */

/**
 * Initializes @a cln for subsequent use.
 *
 * @param cln   Pointer to client.
 * @param loop  Pointer to event loop.
 * @param trans Desired transport.
 * @param cbs   Pointer to event callback set.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE  - @a cln successfully initialized.
 *   <li>@ref AH_EINVAL - @a cln or @a loop or @a cbs is @c NULL.
 *   <li>@ref AH_EINVAL - @a trans @c vtab is invalid, as reported by ah_tcp_trans_vtab_is_valid().
 *   <li>@ref AH_EINVAL - @c on_open, @c on_connect, @c on_send, @c on_recv_line, @c on_recv_header,
 *                        @c on_recv_data, @c on_recv_end, or @c on_close of @a cbs is @c NULL.
 * </ul>
 */
ah_extern ah_err_t ah_http_client_init(ah_http_client_t* cln, ah_loop_t* loop, ah_tcp_trans_t trans, const ah_http_client_cbs_t* cbs);

/**
 * Schedules opening of @a cln, which must be initialized, and its binding to
 * the local network interface represented by @a laddr.
 *
 * If the return value of this function is @ref AH_ENONE, meaning that the open
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
 *   <li>@ref AH_ENONE        - @a cln opening successfully scheduled.
 *   <li>@ref AH_EAFNOSUPPORT - @a laddr is not @c NULL and is not an IP-based address.
 *   <li>@ref AH_ECANCELED    - The event loop of @a cln is shutting down.
 *   <li>@ref AH_EINVAL       - @a cln is @c NULL.
 *   <li>@ref AH_ENOBUFS      - Not enough buffer space available.
 *   <li>@ref AH_ENOMEM       - Not enough heap memory available.
 *   <li>@ref AH_ESTATE       - @a cln is not closed.
 * </ul>
 *
 * @note Every successfully opened @a cln must eventually be provided to
 *       ah_http_client_close().
 */
ah_extern ah_err_t ah_http_client_open(ah_http_client_t* cln, const ah_sockaddr_t* laddr);

/**
 * Schedules connection of @a cln, which must be open, to @a raddr.
 *
 * If the return value of this function is @ref AH_ENONE, meaning that connection
 * could indeed be scheduled, its result will eventually be presented via the
 * ah_http_client_cbs::on_connect callback of @a cln.
 *
 * @param cln   Pointer to client.
 * @param raddr Pointer to socket address representing the remote host to which
 *              the client connection is to be established. If connection is
 *              successful, the referenced address must remain valid until
 *              @a cln is closed.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE        - @a cln opening successfully scheduled.
 *   <li>@ref AH_EAFNOSUPPORT - @a raddr is not an IP-based address.
 *   <li>@ref AH_ECANCELED    - The event loop of @a cln is shutting down.
 *   <li>@ref AH_EINVAL       - @a cln or @a raddr is @c NULL.
 *   <li>@ref AH_ENOBUFS      - Not enough buffer space available.
 *   <li>@ref AH_ENOMEM       - Not enough heap memory available.
 *   <li>@ref AH_ESTATE       - @a cln is not open.
 * </ul>
 *
 * @warning This function must be called with a successfully opened client. An
 *          appropriate place to call this function is often going to be in an
 *          ah_http_client_cbs::on_open callback after a check that opening was
 *          successful.
 */
ah_extern ah_err_t ah_http_client_connect(ah_http_client_t* cln, const ah_sockaddr_t* raddr);

/**
 * Schedules sending of HTTP message head.
 *
 * Calling this function initiates a send procedure by adding @a head to the
 * send queue of @a cln. You must finalize that procedure in one out of three
 * ways, outlined in the below table. How depends on if an HTTP body is to be
 * included in the message and, if so, the final size of that body known in
 * advance.
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
 *     <td>Body size known
 *     <td>Call ah_http_client_send_data() until there are no more body parts to send. Finally, call
 *         ah_http_client_send_end().
 *   <tr>
 *     <td>Body size unknown
 *     <td>Call ah_http_client_send_chunk() until there are no more body parts to send. Finally,
 *         call ah_http_client_send_trailer().
 * </table>
 *
 * The invocation of this function must be successful in order for it to be
 * possible to follow any of the above procedures. Please refer to the
 * documentation for the functions in the above table for further details.
 *
 * @param cln  Pointer to client.
 * @param head Pointer to head, specifying a start line and set of headers.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE           - Transmission of @a head enqueued successfully.
 *   <li>@ref AH_EINVAL          - @a cln or @a head is @c NULL.
 *   <li>@ref AH_EPROTONOSUPPORT - The HTTP version specified in <code>head->version</code> is not
 *                                 supported.
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
 *   <li>@ref AH_ENONE            - Transmission of @a out enqueued successfully.
 *   <li>@ref AH_ECANCELED        - The event loop of @a cln is shutting down.
 *   <li>@ref AH_EINVAL           - @a cln or @a out is @c NULL.
 *   <li>@ref AH_ENETDOWN [Win32] - The network subsystem has failed.
 *   <li>@ref AH_ENOBUFS          - Not enough buffer space available.
 *   <li>@ref AH_ENOMEM           - Not enough heap memory available.
 *   <li>@ref AH_ERANGE           - The variable keeping track of the number of currently enqueued
 *                                  data transmissions would overflow if @a out was accepted.
 *   <li>@ref AH_ESTATE           - @a cln is not currently sending any HTTP message, @a cln is not
 *                                  open, or the write direction of the connection of @a cln has
 *                                  been shut down.
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
 *   <li>@ref AH_ENONE  - Transmission of @a out ended successfully.
 *   <li>@ref AH_EINVAL - @a cln is @c NULL.
 *   <li>@ref AH_ESTATE - @a cln is not currently sending any HTTP message.
 * </ul>
 *
 * @note This function returning with the error code @ref AH_ENONE, which
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
 *   <li>@ref AH_ENONE            - Transmission of @a out enqueued successfully.
 *   <li>@ref AH_ECANCELED        - The event loop of @a cln is shutting down.
 *   <li>@ref AH_ESYNTAX          - The @c ext field of @a chunk is not @c NULL, an empty
 *                                  NULL-terminated C string and it does not begin with a
 *                                  semicolon @c ;, which means that inserting @c ext into the
 *                                  chunk will make it syntactically invalid. <em>This error code
 *                                  is only returned when running in @c DEBUG mode.</em>
 *   <li>@ref AH_EINVAL           - @a cln or @a chunk is @c NULL.
 *   <li>@ref AH_ENETDOWN [Win32] - The network subsystem has failed.
 *   <li>@ref AH_ENOBUFS          - Not enough buffer space available.
 *   <li>@ref AH_ENOMEM           - Not enough heap memory available.
 *   <li>@ref AH_EOVERFLOW        - The used output buffer, which is always allocated via the page
 *                                  allocator (see ah_palloc()) is too small for it to be possible
 *                                  to store the @c size and @c ext specified in @a chunk.
 *   <li>@ref AH_ERANGE           - The variable keeping track of the number of currently enqueued
 *                                  data transmissions would overflow if @a chunk was accepted.
 *   <li>@ref AH_ESTATE           - @a cln is not currently sending any HTTP message, @a cln is
 *                                  not open, or the write direction of the connection of @a cln
 *                                  has been shut down.
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
 *   <li>@ref AH_ENONE            - Transmission of @a trailer enqueued and current message ended
 *                                  successfully.
 *   <li>@ref AH_ECANCELED        - The event loop of @a cln is shutting down.
 *   <li>@ref AH_ESYNTAX          - The @c ext field of @a trailer is not @c NULL, an empty
 *                                  NULL-terminated C string and it does not begin with a
 *                                  semicolon @c ;, which means that inserting @c ext into the
 *                                  last chunk will make it syntactically invalid. <em>This error
 *                                  code is only returned when running in @c DEBUG mode.</em>
 *   <li>@ref AH_EINVAL           - @a cln or @a trailer is @c NULL.
 *   <li>@ref AH_ENETDOWN [Win32] - The network subsystem has failed.
 *   <li>@ref AH_ENOBUFS          - Not enough buffer space available.
 *   <li>@ref AH_ENOMEM           - Not enough heap memory available.
 *   <li>@ref AH_EOVERFLOW        - The used output buffer, which is always allocated via the page
 *                                  allocator (see ah_palloc()) is too small for it to be possible
 *                                  to store the @c size and @c ext specified in @a trailer.
 *   <li>@ref AH_ERANGE           - The variable keeping track of the number of currently enqueued
 *                                  data transmissions would overflow if @a trailer was accepted.
 *   <li>@ref AH_ESTATE           - @a cln is not currently sending any HTTP message, @a cln is
 *                                  not open, or the write direction of the connection of @a cln
 *                                  has been shut down.
 * </ul>
 */
ah_extern ah_err_t ah_http_client_send_trailer(ah_http_client_t* cln, ah_http_trailer_t* trailer);

/**
 * Schedules closing of @a cln.
 *
 * If the return value of this function is @ref AH_ENONE, meaning that the
 * closing could indeed be scheduled, its result will eventually be presented
 * via the ah_http_client_cbs::on_close callback of @a cln.
 *
 * @param cln Pointer to client.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE  - Close of @a cln successfully scheduled.
 *   <li>@ref AH_EINVAL - @a cln is @c NULL.
 *   <li>@ref AH_ESTATE - @a cln is already closed.
 * </ul>
 */
ah_extern ah_err_t ah_http_client_close(ah_http_client_t* cln);

/**
 * Gets the TCP connection of @a cln.
 *
 * @param cln Pointer to client.
 * @return Pointer to TCP connection of @a cln, or @c NULL if @a cln is @c NULL.
 *
 * @note @a cln notably shares <em>user data pointer</em> and <em>receive
 *       buffer</em> with the TCP connection returned by this function. If you
 *       change or update the user data or detach the receive buffer via either
 *       @a cln or the connection, both are affected.
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
 *   <li>@ref AH_ENONE                   - The operation was successful.
 *   <li>@ref AH_EINVAL                  - @a cln or @a laddr is @c NULL.
 *   <li>@ref AH_ENETDOWN [Win32]        - The network subsystem has failed.
 *   <li>@ref AH_ENOBUFS [Darwin, Linux] - Not enough buffer space available.
 *   <li>@ref AH_ESTATE                  - @a cln is closed.
 * </ul>
 *
 * @note This function will always report the same local address as the TCP
 *       connection of @a cln would have reported if ah_tcp_conn_get_laddr() was
 *       called. You can get a pointer to that TCP connection by calling
 *       ah_http_client_get_conn() with @a cln as argument.
 */
ah_extern ah_err_t ah_http_client_get_laddr(const ah_http_client_t* cln, ah_sockaddr_t* laddr);

/**
 * Stores remote address of @a cln into @a raddr.
 *
 * @param cln   Pointer to client.
 * @param raddr Pointer to socket address to be set by this operation.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE                   - The operation was successful.
 *   <li>@ref AH_EINVAL                  - @a cln or @a raddr is @c NULL.
 *   <li>@ref AH_ENETDOWN [Win32]        - The network subsystem has failed.
 *   <li>@ref AH_ENOBUFS [Darwin, Linux] - Not enough buffer space available.
 *   <li>@ref AH_ESTATE                  - @a cln is not connected to a remote host.
 * </ul>
 *
 * @note This function will always report the same local address as the TCP
 *       connection of @a cln would have reported if ah_tcp_conn_get_raddr() was
 *       called. You can get a pointer to that TCP connection by calling
 *       ah_http_client_get_conn() with @a cln as argument.
 */
ah_extern ah_err_t ah_http_client_get_raddr(const ah_http_client_t* cln, ah_sockaddr_t* raddr);

/**
 * Gets pointer to event loop of @a cln.
 *
 * @param cln Pointer to client.
 * @return Pointer to event loop, or @c NULL if @a cln is @c NULL.
 *
 * @note This function gets the event loop pointer of the ah_tcp_conn owned by
 *       @a cln. You can get a pointer to that TCP connection by calling
 *       ah_http_client_get_conn() with @a cln as argument.
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
 *       @a cln. You can get a pointer to that TCP connection by calling
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
 *       @a cln. You can get a pointer to that TCP connection by calling
 *       ah_http_client_get_conn() with @a cln as argument.
 */
ah_extern void ah_http_client_set_user_data(ah_http_client_t* cln, void* user_data);

/** @} */

/**
 * @name HTTP Server
 *
 * Operations on ah_http_server instances. All such instances must be
 * initialized using ah_http_server_init() before they are provided to any other
 * functions listed here. Any other requirements regarding the state of servers
 * are described in the documentation of each respective function, sometimes
 * only via the error codes it lists.
 *
 * @{
 */

/**
 * Initializes @a srv for subsequent use.
 *
 * @param srv   Pointer to server.
 * @param loop  Pointer to event loop.
 * @param trans Desired transport.
 * @param cbs   Pointer to event callback set.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE     - @a srv successfully initialized.
 *   <li>@ref AH_EINVAL    - @a srv or @a loop or @a cbs is @c NULL.
 *   <li>@ref AH_EINVAL    - @a trans @c vtab is invalid, as reported by ah_tcp_trans_vtab_is_valid().
 *   <li>@ref AH_EINVAL    - @c on_open, @c on_listen, @c on_accept or @c on_close of @a cbs is
 *                           @c NULL.
 *   <li>@ref AH_ENOMEM    - Heap memory could not be allocated for storing incoming connections.
 *   <li>@ref AH_EOVERFLOW - @c AH_PSIZE is too small for it to be possible to store both
/ *                          metadata @e and have room for at least one incoming connection in a
 *                           single page provided by the page allocator (see ah_palloc()).
 * </ul>
 *
 * @note Every successfully initialized @a srv must eventually be provided to
 *       ah_http_server_term().
 */
ah_extern ah_err_t ah_http_server_init(ah_http_server_t* srv, ah_loop_t* loop, ah_tcp_trans_t trans, const ah_http_server_cbs_t* cbs);

/**
 * Schedules opening of @a srv, which must be initialized, and its binding to
 * the local network interface represented by @a laddr.
 *
 * If the return value of this function is @ref AH_ENONE, meaning that the open
 * attempt could indeed be scheduled, its result will eventually be presented
 * via the ah_http_server_cbs::on_open callback of @a srv.
 *
 * @param srv   Pointer to server.
 * @param laddr Pointer to socket address representing a local network interface
 *              through which the listener must later receive incoming
 *              connections. If opening is successful, the referenced address
 *              must remain valid for the remaining lifetime of @a srv. To bind
 *              to all or any local network interface, provide the wildcard
 *              address (see ah_sockaddr_ipv4_wildcard and
 *              ah_sockaddr_ipv6_wildcard). If you want the platform to chose
 *              port number automatically, specify port @c 0.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE        - @a srv opening successfully scheduled.
 *   <li>@ref AH_EAFNOSUPPORT - @a laddr is not an IP-based address.
 *   <li>@ref AH_ECANCELED    - The event loop of @a srv is shutting down.
 *   <li>@ref AH_EINVAL       - @a srv or @a laddr is @c NULL.
 *   <li>@ref AH_ENOBUFS      - Not enough buffer space available.
 *   <li>@ref AH_ENOMEM       - Not enough heap memory available.
 *   <li>@ref AH_ESTATE       - @a srv is not closed.
 * </ul>
 *
 * @note Every successfully opened @a srv must eventually be provided to
 *       ah_http_server_close() before it is provided to ah_http_server_term().
 */
ah_extern ah_err_t ah_http_server_open(ah_http_server_t* srv, const ah_sockaddr_t* laddr);

/**
 * Schedules for @a srv, which must be open, to start listening for connecting
 * clients.
 *
 * If the return value of this function is @ref AH_ENONE, meaning that listening
 * could indeed be scheduled, its result will eventually be presented via the
 * ah_http_server_cbs::on_listen callback of @a srv.
 *
 * @param srv      Pointer to server.
 * @param backlog  Capacity, in connections, of the queue in which incoming
 *                 clients wait to get accepted. If @c 0, a platform default
 *                 will be chosen. If larger than some arbitrary platform
 *                 maximum, it will be set to that maximum.
 * @param cbs      Pointer to event callback set to provide to all accepted
 *                 clients.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE     - @a srv listening successfully scheduled.
 *   <li>@ref AH_ECANCELED - The event loop of @a srv is shutting down.
 *   <li>@ref AH_EINVAL    - @a srv or @a conn_cbs is @c NULL.
 *   <li>@ref AH_EINVAL    - @c on_send, @c on_recv_line, @c on_recv_header, @c on_recv_data,
 *                           @c on_recv_end, or @c on_close of @a cbs is @c NULL.
 *   <li>@ref AH_ENOBUFS   - Not enough buffer space available.
 *   <li>@ref AH_ENOMEM    - Not enough heap memory available.
 *   <li>@ref AH_ESTATE    - @a srv is not open.
 * </ul>
 *
 * @warning This function must be called with a successfully opened server. An
 *          appropriate place to call this function is often going to be in an
 *          ah_http_server_cbs::on_open callback after a check that opening
 *          was successful.
 */
ah_extern ah_err_t ah_http_server_listen(ah_http_server_t* srv, unsigned backlog, const ah_http_client_cbs_t* cbs);

/**
 * Schedules closing of @a srv.
 *
 * If the return value of this function is @ref AH_ENONE, meaning that the closing
 * could indeed be scheduled, its result will eventually be presented via the
 * ah_http_server_cbs::on_close callback of @a srv.
 *
 * @param srv Pointer to server.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE  - Close of @a srv successfully scheduled.
 *   <li>@ref AH_EINVAL - @a srv is @c NULL.
 *   <li>@ref AH_ESTATE - @a srv is already closed.
 * </ul>
 *
 * @note Any already accepted clients that are still open are unaffected by the
 *       server being closed.
 */
ah_extern ah_err_t ah_http_server_close(ah_http_server_t* srv);

/**
 * Terminates @a srv, freeing any resources it holds.
 *
 * @param srv Pointer to server.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE  - @a srv successfully terminated.
 *   <li>@ref AH_EINVAL - @a srv is @c NULL.
 *   <li>@ref AH_ESTATE - @a srv is not currently closed.
 * </ul>
 *
 * @note Any already accepted clients that are still open are unaffected by the
 *       server being terminated. It may, however, be the case at some resources
 *       @a srv shares with those clients are not freed until they are all
 *       closed.
 */
ah_extern ah_err_t ah_http_server_term(ah_http_server_t* srv);

/**
 * Gets the TCP listener of @a srv.
 *
 * @param srv Pointer to server.
 * @return Pointer to TCP listener of @a srv, or @c NULL if @a srv is @c NULL.
 *
 * @note @a srv notably shares <em>user data pointer</em> with the TCP listener
 *       returned by this function. If you change or update the user data via
 *       either @a srv or the listener, both are affected.
 */
ah_extern ah_tcp_listener_t* ah_http_server_get_listener(ah_http_server_t* srv);

/**
 * Stores local address bound by @a srv into @a laddr.
 *
 * If @a srv was opened with a zero port, this function will report what
 * concrete port was assigned to @a srv.
 *
 * @param srv   Pointer to server.
 * @param laddr Pointer to socket address to be set by this operation.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE                   - The operation was successful.
 *   <li>@ref AH_EINVAL                  - @a srv or @a laddr is @c NULL.
 *   <li>@ref AH_ENETDOWN [Win32]        - The network subsystem has failed.
 *   <li>@ref AH_ENOBUFS [Darwin, Linux] - Not enough buffer space available.
 *   <li>@ref AH_ESTATE                  - @a srv is closed.
 * </ul>
 *
 * @note This function will always report the same local address as the TCP
 *       listener of @a srv would have reported if ah_tcp_listener_get_laddr()
 *       was called. You can get a pointer to that TCP listener by calling
 *       ah_http_server_get_listener() with @a srv as argument.
 */
ah_extern ah_err_t ah_http_server_get_laddr(const ah_http_server_t* srv, ah_sockaddr_t* laddr);

/**
 * Gets pointer to event loop of @a srv.
 *
 * @param srv Pointer to server.
 * @return Pointer to event loop, or @c NULL if @a srv is @c NULL.
 *
 * @note This function gets the event loop pointer of the ah_tcp_listener owned
 *       by @a srv. You can get a pointer to that TCP listener by calling
 *       ah_http_server_get_listener() with @a srv as argument.
 */
ah_extern ah_loop_t* ah_http_server_get_loop(const ah_http_server_t* srv);

/**
 * Gets the user data pointer associated with @a srv.
 *
 * @param srv Pointer to server.
 * @return Any user data pointer previously set via
 *         ah_http_server_set_user_data(), or @c NULL if no such has been set or
 *         if @a srv is @c NULL.
 *
 * @note This function gets the user data pointer of the ah_tcp_listener owned
 *       by @a srv. You can get a pointer to that TCP listener by calling
 *       ah_http_server_get_listener() with @a srv as argument.
 */
ah_extern void* ah_http_server_get_user_data(const ah_http_server_t* srv);

/**
 * Sets the user data pointer associated with @a srv.
 *
 * @param srv       Pointer to server.
 * @param user_data User data pointer, referring to whatever context you want
 *                  to associate with @a srv.
 *
 * @note If @a srv is @c NULL, this function does nothing.
 *
 * @note This function sets the user data pointer of the ah_tcp_listener owned
 *       by @a srv. You can get a pointer to that TCP listener by calling
 *       ah_http_server_get_listener() with @a srv as argument.
 */
ah_extern void ah_http_server_set_user_data(ah_http_server_t* srv, void* user_data);

/** @} */

#endif
