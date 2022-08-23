// SPDX-License-Identifier: EPL-2.0

#ifndef AH_HTTP_H_
#define AH_HTTP_H_

/**
 * @file
 * HTTP/1 client and server.
 *
 * Here, data structures and functions are provided for representing, setting up
 * and communicating via HTTP/1 clients and servers. As described in the
 * directory-level documentation for this library, only a small subset of all
 * headers part of the HTTP standards are handled automatically. Those headers
 * are outlined in the below table.
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
 *         varies between HTTP versions. In version 1.0 \c close is default, while on all subsequent
 *         versions \c keep-alive is the default.
 *   <tr>
 *     <td>\c Content-Length
 *     <td>When receiving incoming requests and responses, the \c Content-Length is used
 *         automatically to determine when and if a message body is expected, and when all of it has
 *         been received. Incoming messages that neither specify a \c Content-Length nor
 *         <code>Transfer-Encoding: chunked</code> are assumed to not have bodies at all. Note that
 *         no \c Content-Length header is added automatically to outgoing requests or responses. You
 *         must make sure to add it when relevant.
 *   <tr>
 *     <td>\c Host
 *     <td>When sending outgoing requests, if this header is left unspecified, it is automatically
 *         populated with the IP address of the targeted server.
 *   <tr>
 *     <td>\c Transfer-Encoding
 *     <td>If <code>Transfer-Encoding: chunked</code> is specified in an incoming request or
 *         response, the individual chunks are decoded and presented automatically. Other transfer
 *         encoding options are ignored. This means that body compression and decompression is not
 *         handled automatically.
 * </table>
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
 * An HTTP client.
 *
 * Clients are either (1) initiated, opened and connected explicitly, or (2)
 * listened for using an ah_http_server instance.
 *
 * Clients send HTTP requests and receive HTTP responses.
 *
* @note All members of this data structure are @e private in the sense that
*       a user of this API should not access them directly.
 */
struct ah_http_client {
    AH_I_HTTP_CLIENT_FIELDS
};

/**
 * An HTTP client callback set.
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
 * An HTTP server.
 *
 * Servers are used to accept incoming HTTP clients, represented by
 * ah_http_client instances.
 *
 * Servers receive HTTP requests and send HTTP responses.
 *
* @note All members of this data structure are @e private in the sense that
*       a user of this API should not access them directly.
 */
struct ah_http_server {
    AH_I_HTTP_SERVER_FIELDS
};

/**
 * An HTTP server callback set.
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
 * An HTTP version indicator.
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
 * An HTTP header, or name/value pair.
 *
 * Concretely consists of two NULL-terminated C strings. The data structure is
 * used to represent headers in both sent and received HTTP messages.
 */
struct ah_http_header {
    const char* name;  /**< Header name. Case insensitive. */
    const char* value; /**< Header values. Case sensitive. */
};

// The meta-information of an outgoing HTTP request or response.
struct ah_http_head {
    const char* line; // "<method> <target>" or "<code> <reason phrase>".
    ah_http_ver_t version;
    ah_http_header_t* headers; // Array terminated by { NULL, * } pair.

    AH_I_HTTP_HEAD_FIELDS
};

// An outgoing HTTP chunk.
struct ah_http_chunk {
    // Must be NULL, an empty string, or adhere to the chunk-ext syntax, as
    // described in https://www.rfc-editor.org/rfc/rfc7230#section-4.1.1.
    const char* ext;

    ah_tcp_out_t data;

    AH_I_HTTP_CHUNK_FIELDS
};

// The ending part of an outgoing chunked message transmission.
struct ah_http_trailer {
    // Must be NULL, an empty string, or adhere to the chunk-ext syntax, as
    // described in https://www.rfc-editor.org/rfc/rfc7230#section-4.1.1.
    const char* ext;

    ah_http_header_t* headers; // Array terminated by { NULL, * } pair.

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
