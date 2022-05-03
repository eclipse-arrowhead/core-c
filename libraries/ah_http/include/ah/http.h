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

#define AH_HTTP_IREQ_ERR_ASTERISK_FORM_WITHOUT_OPTIONS  1u
#define AH_HTTP_IREQ_ERR_AUTHORITY_FORM_WITHOUT_CONNECT 2u
#define AH_HTTP_IREQ_ERR_CONTENT_LENGTH_RESPECIFIED     3u
#define AH_HTTP_IREQ_ERR_HEADERS_TOO_LARGE              4u
#define AH_HTTP_IREQ_ERR_HEADERS_TOO_MANY               10u
#define AH_HTTP_IREQ_ERR_HOST_NOT_SPECIFIED             5u
#define AH_HTTP_IREQ_ERR_HOST_RESPECIFIED               6u
#define AH_HTTP_IREQ_ERR_REQUEST_LINE_TOO_LONG          7u
#define AH_HTTP_IREQ_ERR_UNEXPECTED_BODY                8u
#define AH_HTTP_IREQ_ERR_VERSION_NOT_SUPPORTED          9u

#define AH_HTTP_IRES_ERR_HEADERS_TOO_LARGE     1u
#define AH_HTTP_IRES_ERR_HEADERS_TOO_MANY      5u
#define AH_HTTP_IRES_ERR_STATUS_LINE_TOO_LONG  2u
#define AH_HTTP_IRES_ERR_UNEXPECTED_BODY       3u
#define AH_HTTP_IRES_ERR_VERSION_NOT_SUPPORTED 4u

typedef uint16_t ah_http_ireq_err_t;
typedef uint16_t ah_http_ires_err_t;

typedef struct ah_http_client ah_http_client_t;
typedef struct ah_http_hmap ah_http_hmap_t;
typedef struct ah_http_hmap_value_iter ah_http_hmap_value_iter_t;
typedef struct ah_http_ireq ah_http_ireq_t;
typedef struct ah_http_server_vtab ah_http_server_vtab_t;
typedef struct ah_http_ires ah_http_ires_t;
typedef struct ah_http_client_vtab ah_http_client_vtab_t;
typedef struct ah_http_header ah_http_header_t;
typedef struct ah_http_hlist ah_http_hlist_t;
typedef struct ah_http_oreq ah_http_oreq_t;
typedef struct ah_http_ores ah_http_ores_t;
typedef struct ah_http_req_line ah_http_req_line_t;
typedef struct ah_http_server ah_http_server_t;
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

    void (*on_res_alloc)(ah_http_client_t* cln, ah_http_ires_t** res, ah_buf_t* buf);
    void (*on_res_line)(ah_http_client_t* cln, ah_http_ires_t* res);
    void (*on_res_headers)(ah_http_client_t* cln, ah_http_ires_t* res);
    void (*on_res_err)(ah_http_client_t* cln, ah_http_ires_t* res, ah_http_ires_err_t ires_err);

    void (*on_res_body_alloc)(ah_http_client_t* cln, ah_bufs_t* bufs, size_t n_expected_bytes);
    void (*on_res_body)(ah_http_client_t* cln, ah_http_ires_t* res, ah_bufs_t bufs, size_t rem);
    void (*on_res_body_received)(ah_http_client_t* cln, ah_http_ires_t* res);
};

struct ah_http_server {
    AH_I_HTTP_SERVER_FIELDS
};

struct ah_http_server_vtab {
    void (*on_open)(ah_http_server_t* srv, ah_err_t err);
    void (*on_listen)(ah_http_server_t* srv, ah_err_t err);
    void (*on_close)(ah_http_server_t* srv, ah_err_t err);

    void (*on_client_alloc)(ah_http_server_t* srv, ah_http_client_t** cln);
    void (*on_client_accept)(ah_http_server_t* srv, ah_http_client_t* cln, const ah_sockaddr_t* cln_addr, ah_err_t err);
    void (*on_client_close)(ah_http_server_t* srv, ah_http_client_t* cln);

    void (*on_req_alloc)(ah_http_server_t* srv, ah_http_ireq_t** req, ah_buf_t* buf, ah_http_ores_t** res);
    void (*on_req_line)(ah_http_server_t* srv, ah_http_ireq_t* req, ah_http_ores_t* res);
    void (*on_req_headers)(ah_http_server_t* srv, ah_http_ireq_t* req, ah_http_ores_t* res);
    void (*on_req_err)(ah_http_server_t* srv, ah_http_ireq_t* req, ah_http_ireq_err_t cause, ah_http_ores_t* res);

    void (*on_body_alloc)(ah_http_server_t* srv, ah_bufs_t* bufs, size_t n_expected_bytes);
    void (*on_body_chunk)(ah_http_server_t* srv, ah_http_ireq_t* req, ah_bufs_t bufs, size_t rem, ah_http_ores_t* res);
    void (*on_body_received)(ah_http_server_t* srv, ah_http_ireq_t* req, ah_http_ores_t* res);

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
    ah_http_client_t* client;

    ah_http_req_line_t req_line;
    ah_http_hmap_t headers;

    void* user_data;
};

struct ah_http_ires {
    ah_http_stat_line_t stat_line;
    ah_http_hmap_t headers;

    const ah_sockaddr_t* server_addr;
    void* user_data;
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

ah_inline void ah_http_client_init(ah_http_client_t* cln, ah_tcp_trans_t trans, const ah_http_client_vtab_t* vtab)
{
    ah_assert_if_debug(cln != NULL);
    ah_assert_if_debug(trans._loop != NULL);
    ah_assert_if_debug(trans._vtab != NULL);
    ah_assert_if_debug(vtab != NULL);

    trans._vtab->init(&cln->_sock, trans._loop);
    cln->_trans = trans;
    cln->_vtab = vtab;
}

ah_extern ah_err_t ah_http_client_open(ah_http_client_t* cln, const ah_sockaddr_t* laddr);
ah_extern ah_err_t ah_http_client_connect(ah_http_client_t* cln, const ah_sockaddr_t* raddr);
ah_extern ah_err_t ah_http_client_request(ah_http_client_t* cln, const ah_http_oreq_t* req);
ah_extern ah_err_t ah_http_client_close(ah_http_client_t* cln);

ah_inline ah_tcp_sock_t* ah_http_client_get_sock(ah_http_client_t* srv)
{
    ah_assert_if_debug(srv != NULL);
    return &srv->_sock;
}

ah_inline void* ah_http_client_get_user_data(ah_http_client_t* cln)
{
    ah_assert_if_debug(cln != NULL);
    return cln->_user_data;
}

ah_inline void ah_http_client_set_user_data(ah_http_client_t* cln, void* user_data)
{
    ah_assert_if_debug(cln != NULL);
    cln->_user_data = user_data;
}

ah_extern void ah_http_server_init(ah_http_server_t* srv, ah_tcp_trans_t trans, const ah_http_server_vtab_t* vtab);
ah_extern ah_err_t ah_http_server_open(ah_http_server_t* srv, const ah_sockaddr_t* laddr);
ah_extern ah_err_t ah_http_server_listen(ah_http_server_t* srv, unsigned backlog);
ah_extern ah_err_t ah_http_server_respond(ah_http_server_t* srv, const ah_http_ores_t* res);
ah_extern ah_err_t ah_http_server_close(ah_http_server_t* srv);

ah_inline ah_tcp_sock_t* ah_http_server_get_sock(ah_http_server_t* srv)
{
    ah_assert_if_debug(srv != NULL);
    return &srv->_sock;
}

ah_inline void* ah_http_server_get_user_data(ah_http_server_t* srv)
{
    ah_assert_if_debug(srv != NULL);
    return srv->_user_data;
}

// `capacity` must be one of {0, 1, 2, 4, 8, 16, 32, 64, 128 or 256}. If not,
// every incoming connection will fail with AH_EDOM. Defaults to 16 if 0 is
// given or if never specified.
ah_inline void ah_http_server_set_req_header_capacity(ah_http_server_t* srv, size_t capacity)
{
    ah_assert_if_debug(srv != NULL);
    ah_assert_if_debug(capacity != 0u && ((capacity & (capacity - 1u)) == 0u));
    srv->_req_header_capacity = capacity;
}

ah_inline void ah_http_server_set_user_data(ah_http_server_t* srv, void* user_data)
{
    ah_assert_if_debug(srv != NULL);
    srv->_user_data = user_data;
}

ah_extern const ah_str_t* ah_http_hmap_get_value(const ah_http_hmap_t* headers, ah_str_t name, bool* has_next);
ah_extern ah_http_hmap_value_iter_t ah_http_hmap_get_values(const ah_http_hmap_t* headers, ah_str_t name);
ah_extern const ah_str_t* ah_http_hmap_next_value(ah_http_hmap_value_iter_t* iter);

ah_inline ah_http_obody_t ah_http_obody_buf(ah_buf_t buf)
{
    return (ah_http_obody_t) { ._as_buf._kind = AH_I_HTTP_OBODY_KIND_BUF, ._as_buf._buf = buf };
}

ah_inline ah_http_obody_t ah_http_obody_bufs(ah_bufs_t bufs)
{
    return (ah_http_obody_t) { ._as_bufs._kind = AH_I_HTTP_OBODY_KIND_BUFVEC, ._as_bufs._bufs = bufs };
}

ah_inline ah_http_obody_t ah_http_obody_callback(ah_http_obody_cb cb)
{
    return (ah_http_obody_t) { ._as_callback._kind = AH_I_HTTP_OBODY_KIND_CALLBACK, ._as_callback._cb = cb };
}

ah_inline ah_http_obody_t ah_http_obody_cstr(char* cstr)
{
    return ah_http_obody_buf((ah_buf_t) { ._octets = (uint8_t*) cstr, ._size = strlen(cstr) });
}

ah_inline ah_http_obody_t ah_http_obody_str(ah_str_t str)
{
    return ah_http_obody_buf((ah_buf_t) { ._octets = (uint8_t*) ah_str_get_ptr(&str), ._size = ah_str_get_len(&str) });
}

#endif
