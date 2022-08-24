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
 *       called to indicate that the complete body has been enqueued.
 *   <li>If a <em>chunked body</em> is to be sent, which is recommended when the
 *       final size of the transmitted body is @e not known in advance,
 *       ah_http_client_send_chunk() must be called repeatedly until all body
 *       chunks have been enqueued. Finally, ah_http_client_send_trailer() must
 *       be called to submit any trailing chunk extension and headers, and to
 *       indicate that the complete body has been enqueued.
 * </ol>
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
 *     <td>When sending requests, if this header is left unspecified, it is automatically populated
 *         with the IP address of the targeted server.
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
    void (*on_open)(ah_http_client_t* cln, ah_err_t err);    // Never called for accepted clients.
    void (*on_connect)(ah_http_client_t* cln, ah_err_t err); // Never called for accepted clients.

    void (*on_send)(ah_http_client_t* cln, ah_http_head_t* head, ah_err_t err);

    void (*on_recv_line)(ah_http_client_t* cln, const char* line, ah_http_ver_t version);
    void (*on_recv_header)(ah_http_client_t* cln, ah_http_header_t header);
    void (*on_recv_headers)(ah_http_client_t* cln);                                  // Optional.
    void (*on_recv_chunk_line)(ah_http_client_t* cln, size_t size, const char* ext); // Optional.
    void (*on_recv_data)(ah_http_client_t* cln, ah_tcp_in_t* in);

    // If `err` is not AH_ENONE or if connection keep-alive is disabled, the
    // client will be closed right after this function returns.
    void (*on_recv_end)(ah_http_client_t* cln, ah_err_t err);

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
    void (*on_open)(ah_http_server_t* srv, ah_err_t err);
    void (*on_listen)(ah_http_server_t* srv, ah_err_t err);
    void (*on_accept)(ah_http_server_t* srv, ah_http_client_t* client, ah_err_t err);
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

ah_extern ah_err_t ah_http_client_init(ah_http_client_t* cln, ah_loop_t* loop, ah_tcp_trans_t trans, const ah_http_client_cbs_t* cbs);
ah_extern ah_err_t ah_http_client_open(ah_http_client_t* cln, const ah_sockaddr_t* laddr);
ah_extern ah_err_t ah_http_client_connect(ah_http_client_t* cln, const ah_sockaddr_t* raddr);
ah_extern ah_err_t ah_http_client_send_head(ah_http_client_t* cln, ah_http_head_t* head);
ah_extern ah_err_t ah_http_client_send_data(ah_http_client_t* cln, ah_tcp_out_t* data);
ah_extern ah_err_t ah_http_client_send_end(ah_http_client_t* cln);
ah_extern ah_err_t ah_http_client_send_chunk(ah_http_client_t* cln, ah_http_chunk_t* chunk);
ah_extern ah_err_t ah_http_client_send_trailer(ah_http_client_t* cln, ah_http_trailer_t* trailer); // Implies *_end().
ah_extern ah_err_t ah_http_client_close(ah_http_client_t* cln);
ah_extern ah_tcp_conn_t* ah_http_client_get_conn(ah_http_client_t* cln);
ah_extern ah_err_t ah_http_client_get_laddr(const ah_http_client_t* cln, ah_sockaddr_t* laddr);
ah_extern ah_err_t ah_http_client_get_raddr(const ah_http_client_t* cln, ah_sockaddr_t* raddr);
ah_extern ah_loop_t* ah_http_client_get_loop(const ah_http_client_t* cln);
ah_extern void* ah_http_client_get_user_data(const ah_http_client_t* cln);
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
