// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_HTTP_H_
#define AH_HTTP_H_

#include "internal/_http.h"

#include <ah/buf.h>
#include <stdbool.h>
#include <stdint.h>

#define AH_HTTP_IREQ_ERR_CONTENT_LENGTH_RESPECIFIED 8701u
#define AH_HTTP_IREQ_ERR_HEADERS_TOO_LARGE          8702u
#define AH_HTTP_IREQ_ERR_HEADERS_TOO_MANY           8703u
#define AH_HTTP_IREQ_ERR_HOST_RESPECIFIED           8704u
#define AH_HTTP_IREQ_ERR_HOST_UNSPECIFIED           8705u
#define AH_HTTP_IREQ_ERR_INTERNAL                   8706u
#define AH_HTTP_IREQ_ERR_REQ_LINE_TOO_LONG          8707u
#define AH_HTTP_IREQ_ERR_VER_UNSUPPORTED            8708u

#define AH_HTTP_IRES_ERR_ALLOC_FAILED    8901u
#define AH_HTTP_IRES_ERR_BUFFER_OVERFLOW 8902u
#define AH_HTTP_IRES_ERR_FORMAT_INVALID  8903u
#define AH_HTTP_IRES_ERR_HEAD_TOO_LARGE  8904u
#define AH_HTTP_IRES_ERR_TRANSPORT_ERROR 8907u
#define AH_HTTP_IRES_ERR_VER_UNSUPPORTED 8908u

typedef struct ah_http_chunk ah_http_chunk_t;
typedef struct ah_http_client ah_http_client_t;
typedef struct ah_http_client_vtab ah_http_client_vtab_t;
typedef struct ah_http_data ah_http_data_t;
typedef struct ah_http_header ah_http_header_t;
typedef struct ah_http_hlist ah_http_hlist_t;
typedef struct ah_http_hmap ah_http_hmap_t;
typedef struct ah_http_hmap_value_iter ah_http_hmap_value_iter_t;
typedef struct ah_http_ireq ah_http_ireq_t;
typedef struct ah_http_ireq_err ah_http_ireq_err_t;
typedef struct ah_http_ires ah_http_ires_t;
typedef struct ah_http_ires_err ah_http_ires_err_t;
typedef struct ah_http_oreq ah_http_oreq_t;
typedef struct ah_http_ores ah_http_ores_t;
typedef struct ah_http_req_line ah_http_req_line_t;
typedef struct ah_http_server ah_http_server_t;
typedef struct ah_http_server_vtab ah_http_server_vtab_t;
typedef struct ah_http_stat_line ah_http_stat_line_t;
typedef struct ah_http_ver ah_http_ver_t;

typedef union ah_http_obody ah_http_obody_t;

typedef void (*ah_http_obody_cb)(ah_bufs_t*);

struct ah_http_client {
    AH_I_HTTP_CLIENT_FIELDS
};

struct ah_http_client_vtab {
    void (*on_open)(ah_http_client_t* cln, ah_err_t err);
    void (*on_connect)(ah_http_client_t* cln, ah_err_t err);
    void (*on_close)(ah_http_client_t* cln, ah_err_t err);

    void (*on_req_sent)(ah_http_client_t* cln, ah_http_oreq_t* req);

    void (*on_res_alloc_head)(ah_http_client_t* cln, ah_http_ires_t** res, ah_buf_t* buf);
    void (*on_res_alloc_more)(ah_http_client_t* cln, ah_buf_t* buf);

    void (*on_res_line)(ah_http_client_t* cln, ah_http_ires_t* res);
    void (*on_res_headers)(ah_http_client_t* cln, ah_http_ires_t* res);
    void (*on_res_chunk)(ah_http_client_t* cln, ah_http_ires_t* res, const ah_http_chunk_t* chunk);
    void (*on_res_data)(ah_http_client_t* cln, ah_http_ires_t* res, const ah_http_data_t* data);
    void (*on_res_err)(ah_http_client_t* cln, ah_http_ires_t* res, const ah_http_ires_err_t* err);
    void (*on_res_end)(ah_http_client_t* cln, ah_http_ires_t* res);
};

struct ah_http_server {
    AH_I_HTTP_SERVER_FIELDS
};

struct ah_http_server_vtab {
    void (*on_open)(ah_http_server_t* srv, ah_err_t err);
    void (*on_listen)(ah_http_server_t* srv, ah_err_t err);
    void (*on_close)(ah_http_server_t* srv, ah_err_t err);

    void (*on_req_alloc_head)(ah_http_server_t* srv, ah_http_ireq_t** req, ah_buf_t* buf, ah_http_ores_t** res);
    void (*on_req_alloc_more)(ah_http_server_t* srv, ah_buf_t* buf, ah_http_ores_t* res);

    void (*on_req_line)(ah_http_server_t* srv, ah_http_ireq_t* req, ah_http_ores_t* res);
    void (*on_req_headers)(ah_http_server_t* srv, ah_http_ireq_t* req, ah_http_ores_t* res);
    void (*on_req_chunk)(ah_http_client_t* cln, ah_http_ireq_t* req, const ah_http_chunk_t* chunk, ah_http_ores_t* res);
    void (*on_req_data)(ah_http_server_t* srv, ah_http_ireq_t* req, const ah_http_data_t* data, ah_http_ores_t* res);
    void (*on_req_err)(ah_http_server_t* srv, ah_http_ireq_t* req, const ah_http_ireq_err_t* err, ah_http_ores_t* res);
    void (*on_req_end)(ah_http_server_t* srv, ah_http_ireq_t* req, ah_http_ores_t* res);

    void (*on_res_sent)(ah_http_server_t* srv, ah_http_ores_t* res);
};

struct ah_http_ver {
    uint8_t major;
    uint8_t minor;
};

struct ah_http_req_line {
    ah_str_t method;
    ah_str_t target;
    ah_http_ver_t version;
};

struct ah_http_stat_line {
    ah_http_ver_t version;
    uint16_t code;
    ah_str_t reason;
};

struct ah_http_hmap {
    AH_I_HTTP_HMAP_FIELDS
};

struct ah_http_hmap_value_iter {
    AH_I_HTTP_HMAP_VALUE_ITER_FIELDS
};

struct ah_http_ireq {
    ah_http_req_line_t req_line;
    ah_http_hmap_t headers;
    void* user_data;
};

struct ah_http_ireq_err {
    const char* msg;
    uint16_t code;
    uint16_t stat_code;
    ah_err_t err;
};

struct ah_http_ires {
    ah_http_stat_line_t stat_line;
    ah_http_hmap_t headers;
    void* user_data;
};

struct ah_http_ires_err {
    const char* msg;
    uint16_t code;
    ah_err_t err;
};

struct ah_http_header {
    char* name;
    ah_str_t value;
};

struct ah_http_hlist {
    ah_http_header_t* pairs; // Array terminated by { NULL, * } pair.
};

union ah_http_obody {
    AH_I_HTTP_OBODY_FIELDS
};

struct ah_http_oreq {
    ah_http_req_line_t req_line;
    ah_http_hlist_t headers;
    ah_http_obody_t body;
    void* user_data; // Will be passed on to the corresponding ah_http_ires_t.
};

struct ah_http_ores {
    ah_http_stat_line_t stat_line;
    ah_http_hlist_t headers;
    ah_http_obody_t body;
    void* user_data;
};

struct ah_http_chunk {
    size_t size;
    ah_str_t ext;
};

struct ah_http_data {
    const ah_buf_t* buf;
    size_t nread;
    size_t nleft;
};

ah_extern ah_err_t ah_http_client_init(ah_http_client_t* cln, ah_tcp_trans_t trans, const ah_http_client_vtab_t* vtab);
ah_extern ah_err_t ah_http_client_open(ah_http_client_t* cln, const ah_sockaddr_t* laddr);
ah_extern ah_err_t ah_http_client_connect(ah_http_client_t* cln, const ah_sockaddr_t* raddr);
ah_extern ah_err_t ah_http_client_request(ah_http_client_t* cln, const ah_http_oreq_t* req);
ah_extern ah_err_t ah_http_client_close(ah_http_client_t* cln);

ah_inline ah_tcp_conn_t* ah_http_client_get_conn(ah_http_client_t* cln)
{
    ah_assert_if_debug(cln != NULL);
    return &cln->_conn;
}

ah_inline void* ah_http_client_get_user_data(ah_http_client_t* cln)
{
    ah_assert_if_debug(cln != NULL);
    return ah_tcp_conn_get_user_data(&cln->_conn);
}

ah_inline void ah_http_client_set_user_data(ah_http_client_t* cln, void* user_data)
{
    ah_assert_if_debug(cln != NULL);
    ah_tcp_conn_set_user_data(&cln->_conn, user_data);
}

ah_extern ah_err_t ah_http_server_init(ah_http_server_t* srv, ah_tcp_trans_t trans, const ah_http_server_vtab_t* vtab);
ah_extern ah_err_t ah_http_server_open(ah_http_server_t* srv, const ah_sockaddr_t* laddr);
ah_extern ah_err_t ah_http_server_listen(ah_http_server_t* srv, unsigned backlog);
ah_extern ah_err_t ah_http_server_respond(ah_http_server_t* srv, const ah_http_ores_t* res);
ah_extern ah_err_t ah_http_server_close(ah_http_server_t* srv);

ah_inline ah_tcp_listener_t* ah_http_server_get_listener(ah_http_server_t* srv)
{
    ah_assert_if_debug(srv != NULL);
    return &srv->_ln;
}

ah_inline void* ah_http_server_get_user_data(ah_http_server_t* srv)
{
    ah_assert_if_debug(srv != NULL);
    return ah_tcp_listener_get_user_data(&srv->_ln);
}

ah_inline void ah_http_server_set_user_data(ah_http_server_t* srv, void* user_data)
{
    ah_assert_if_debug(srv != NULL);
    ah_tcp_listener_set_user_data(&srv->_ln, user_data);
}

ah_extern ah_err_t ah_http_hmap_init(struct ah_http_hmap* hmap, struct ah_i_http_hmap_header* headers, size_t len);
ah_extern ah_err_t ah_http_hmap_add(struct ah_http_hmap* hmap, ah_str_t name, ah_str_t value);
ah_extern const ah_str_t* ah_http_hmap_get_value(const ah_http_hmap_t* headers, ah_str_t name, bool* has_next);
ah_extern ah_http_hmap_value_iter_t ah_http_hmap_get_values(const ah_http_hmap_t* headers, ah_str_t name);
ah_extern const ah_str_t* ah_http_hmap_next_value(ah_http_hmap_value_iter_t* iter);

ah_inline ah_http_obody_t ah_http_obody_buf(ah_buf_t buf)
{
    return (ah_http_obody_t) { ._as_buf._kind = AH_I_HTTP_OBODY_KIND_BUF, ._as_buf._buf = buf };
}

ah_inline ah_http_obody_t ah_http_obody_bufs(ah_bufs_t bufs)
{
    return (ah_http_obody_t) { ._as_bufs._kind = AH_I_HTTP_OBODY_KIND_BUFS, ._as_bufs._bufs = bufs };
}

ah_inline ah_http_obody_t ah_http_obody_callback(ah_http_obody_cb cb)
{
    return (ah_http_obody_t) { ._as_callback._kind = AH_I_HTTP_OBODY_KIND_CALLBACK, ._as_callback._cb = cb };
}

ah_inline ah_http_obody_t ah_http_obody_cstr(char* cstr)
{
    ah_buf_t buf;
    ah_err_t err = ah_buf_init(&buf, (uint8_t*) cstr, strlen(cstr));
    ah_assert(err == 0);
    return ah_http_obody_buf(buf);
}

ah_inline ah_http_obody_t ah_http_obody_str(ah_str_t str)
{
    ah_buf_t buf;
    ah_err_t err = ah_buf_init(&buf, (uint8_t*) ah_str_get_ptr(&str), ah_str_get_len(&str));
    ah_assert(err == 0);
    return ah_http_obody_buf(buf);
}

#endif
