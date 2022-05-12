// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_HTTP_H_
#define AH_HTTP_H_

#include "internal/_http.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define AH_HTTP_VER_1_0 ((ah_http_ver_t) { 1u, 0u })
#define AH_HTTP_VER_1_1 ((ah_http_ver_t) { 1u, 1u })

typedef struct ah_http_chunk_line ah_http_chunk_line_t;
typedef struct ah_http_client ah_http_client_t;
typedef struct ah_http_client_vtab ah_http_client_vtab_t;
typedef struct ah_http_header ah_http_header_t;
typedef struct ah_http_req ah_http_req_t;
typedef struct ah_http_req_line ah_http_req_line_t;
typedef struct ah_http_res ah_http_res_t;
typedef struct ah_http_server ah_http_server_t;
typedef struct ah_http_server_vtab ah_http_server_vtab_t;
typedef struct ah_http_stat_line ah_http_stat_line_t;
typedef struct ah_http_ver ah_http_ver_t;

typedef union ah_http_body ah_http_body_t;

struct ah_http_client {
    AH_I_HTTP_CLIENT_FIELDS
};

struct ah_http_client_vtab {
    void (*on_open)(ah_http_client_t* cln, ah_err_t err);
    void (*on_connect)(ah_http_client_t* cln, ah_err_t err);
    void (*on_close)(ah_http_client_t* cln, ah_err_t err);

    // It is safe to provide `buf` with the same memory block every time this
    // function is called with the same `cln`.
    void (*on_alloc)(ah_http_client_t* cln, ah_http_req_t* req, ah_buf_t* buf);

    void (*on_req_sent)(ah_http_client_t* cln, ah_http_req_t* req, ah_err_t err);

    void (*on_res_stat_line)(ah_http_client_t* cln, ah_http_req_t* req, const ah_http_stat_line_t* stat_line);
    void (*on_res_header)(ah_http_client_t* cln, ah_http_req_t* req, ah_http_header_t header);
    void (*on_res_headers)(ah_http_client_t* cln, ah_http_req_t* req);                                     // Optional.
    void (*on_res_chunk_line)(ah_http_client_t* cln, ah_http_req_t* req, ah_http_chunk_line_t chunk_line); // Optional.
    void (*on_res_data)(ah_http_client_t* cln, ah_http_req_t* req, const ah_buf_t* rbuf);
    void (*on_res_end)(ah_http_client_t* cln, ah_http_req_t* req, ah_err_t err);
};

struct ah_http_server {
    AH_I_HTTP_SERVER_FIELDS
};

struct ah_http_server_vtab {
    void (*on_open)(ah_http_server_t* srv, ah_err_t err);
    void (*on_listen)(ah_http_server_t* srv, ah_err_t err);
    void (*on_close)(ah_http_server_t* srv, ah_err_t err);

    // It is safe to provide `buf` with the same memory block every time this
    // function is called with the same `srv`.
    void (*on_alloc)(ah_http_server_t* srv, ah_buf_t* buf, ah_http_res_t* res);

    void (*on_req_line)(ah_http_server_t* srv, const ah_http_req_line_t* req_line, ah_http_res_t* res);
    void (*on_req_header)(ah_http_server_t* srv, ah_http_header_t header, ah_http_res_t* res);
    void (*on_req_headers)(ah_http_server_t* srv, ah_http_res_t* res);                                     // Optional.
    void (*on_req_chunk_line)(ah_http_server_t* srv, ah_http_chunk_line_t chunk_line, ah_http_res_t* res); // Optional.
    void (*on_req_data)(ah_http_server_t* srv, const ah_buf_t* rbuf, ah_http_res_t* res);
    void (*on_req_end)(ah_http_server_t* srv, ah_err_t err, uint16_t stat_code, ah_http_res_t* res);

    void (*on_res_sent)(ah_http_server_t* srv, ah_http_res_t* res, ah_err_t err);
};

struct ah_http_ver {
    uint8_t major;
    uint8_t minor;
};

struct ah_http_req_line {
    const char* method;
    const char* target;
    ah_http_ver_t version;
};

struct ah_http_stat_line {
    ah_http_ver_t version;
    uint16_t code;
    const char* reason;
};

struct ah_http_chunk_line {
    size_t size;
    const char* ext;
};

struct ah_http_header {
    const char* name;
    const char* value;
};

// An outgoing HTTP request or response body.
union ah_http_body {
    AH_I_HTTP_BODY_FIELDS
};

// An outgoing HTTP request.
struct ah_http_req {
    ah_http_req_line_t req_line;
    ah_http_header_t* headers; // Array terminated by { NULL, * } pair.
    ah_http_body_t body;
    void* user_data;

    AH_I_HTTP_REQ_FIELDS
};

// An outgoing HTTP response.
struct ah_http_res {
    ah_http_stat_line_t stat_line;
    ah_http_header_t* headers; // Array terminated by { NULL, * } pair.
    ah_http_body_t body;
    void* user_data;

    AH_I_HTTP_RES_FIELDS
};

ah_extern ah_err_t ah_http_client_init(ah_http_client_t* cln, ah_tcp_trans_t trans, const ah_http_client_vtab_t* vtab);
ah_extern ah_err_t ah_http_client_open(ah_http_client_t* cln, const ah_sockaddr_t* laddr);
ah_extern ah_err_t ah_http_client_connect(ah_http_client_t* cln, const ah_sockaddr_t* raddr);
ah_extern ah_err_t ah_http_client_request(ah_http_client_t* cln, ah_http_req_t* req);
ah_extern ah_err_t ah_http_client_send_chunk(ah_http_client_t* cln, ah_http_chunk_line_t chunk, ah_bufs_t bufs);
ah_extern ah_err_t ah_http_client_send_data(ah_http_client_t* cln, ah_bufs_t bufs);
ah_extern ah_err_t ah_http_client_send_trailer(ah_http_client_t* cln, ah_http_header_t* headers);
ah_extern ah_err_t ah_http_client_close(ah_http_client_t* cln);
ah_extern ah_tcp_conn_t* ah_http_client_get_conn(ah_http_client_t* cln);
ah_extern void* ah_http_client_get_user_data(ah_http_client_t* cln);
ah_extern void ah_http_client_set_user_data(ah_http_client_t* cln, void* user_data);

ah_extern ah_err_t ah_http_server_init(ah_http_server_t* srv, ah_tcp_trans_t trans, const ah_http_server_vtab_t* vtab);
ah_extern ah_err_t ah_http_server_open(ah_http_server_t* srv, const ah_sockaddr_t* laddr);
ah_extern ah_err_t ah_http_server_listen(ah_http_server_t* srv, unsigned backlog);
ah_extern ah_err_t ah_http_server_respond(ah_http_server_t* srv, const ah_http_res_t* res);
ah_extern ah_err_t ah_http_server_send_chunk(ah_http_server_t* srv, ah_http_chunk_line_t chunk, ah_bufs_t bufs);
ah_extern ah_err_t ah_http_server_send_data(ah_http_server_t* srv, ah_bufs_t bufs);
ah_extern ah_err_t ah_http_server_send_trailer(ah_http_server_t* srv, ah_http_header_t* headers);
ah_extern ah_err_t ah_http_server_close(ah_http_server_t* srv);
ah_extern ah_tcp_listener_t* ah_http_server_get_listener(ah_http_server_t* srv);
ah_extern void* ah_http_server_get_user_data(ah_http_server_t* srv);
ah_extern void ah_http_server_set_user_data(ah_http_server_t* srv, void* user_data);

ah_extern ah_http_body_t ah_http_body_empty();
ah_extern ah_http_body_t ah_http_body_from_buf(ah_buf_t buf);
ah_extern ah_http_body_t ah_http_body_from_bufs(ah_bufs_t bufs);
ah_extern ah_http_body_t ah_http_body_from_cstr(char* cstr);
ah_extern ah_http_body_t ah_http_body_override(void); // Enables use of *_send_{chunk,data,trailer} functions.

#endif
