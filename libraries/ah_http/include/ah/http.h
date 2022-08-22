// SPDX-License-Identifier: EPL-2.0

#ifndef AH_HTTP_H_
#define AH_HTTP_H_

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

// An HTTP client.
struct ah_http_client {
    AH_I_HTTP_CLIENT_FIELDS
};

// Virtual function table of an HTTP client.
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

// An HTTP server.
struct ah_http_server {
    AH_I_HTTP_SERVER_FIELDS
};

// Virtual function table of local HTTP server.
struct ah_http_server_cbs {
    void (*on_open)(ah_http_server_t* srv, ah_err_t err);
    void (*on_listen)(ah_http_server_t* srv, ah_err_t err);
    void (*on_accept)(ah_http_server_t* srv, ah_http_client_t* client, ah_err_t err);
    void (*on_close)(ah_http_server_t* srv, ah_err_t err);
};

// An HTTP version indicator.
struct ah_http_ver {
    uint8_t major;
    uint8_t minor;
};

// An HTTP header.
struct ah_http_header {
    const char* name;
    const char* value;
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
