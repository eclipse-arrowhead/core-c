// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_HTTP_H_
#define AH_INTERNAL_HTTP_H_

#include <ah/buf.h>
#include <ah/defs.h>
#include <ah/tcp.h>
#include <stddef.h>

#define AH_I_HTTP_OBODY_KIND_BUF      1u
#define AH_I_HTTP_OBODY_KIND_BUFS     2u
#define AH_I_HTTP_OBODY_KIND_CALLBACK 3u

#define AH_I_HTTP_CLIENT_FIELDS          \
 ah_tcp_conn_t _conn;                    \
 const ah_tcp_trans_vtab_t* _trans_vtab; \
 const ah_http_client_vtab_t* _vtab;     \
 struct ah_i_http_oreq_queue _req_queue; \
 ah_buf_rw_t _res_buf_rw;                \
 size_t _n_expected_bytes;               \
 uint16_t _n_expected_responses;         \
 uint16_t _state;

#define AH_I_HTTP_SERVER_FIELDS          \
 ah_tcp_listener_t _ln;                  \
 const ah_tcp_trans_vtab_t* _trans_vtab; \
 const ah_http_server_vtab_t* _vtab;

#define AH_I_HTTP_HMAP_FIELDS \
 uint16_t _mask;              \
 uint16_t _count;             \
 struct ah_i_http_hmap_header* _headers;

#define AH_I_HTTP_HMAP_VALUE_ITER_FIELDS      \
 const struct ah_i_http_hmap_header* _header; \
 size_t _value_off;

#define AH_I_HTTP_OBODY_FIELDS         \
 struct ah_i_http_obody_any _as_any;   \
 struct ah_i_http_obody_buf _as_buf;   \
 struct ah_i_http_obody_bufs _as_bufs; \
 struct ah_i_http_obody_callback _as_callback;

#define AH_I_HTTP_OREQ_FIELDS \
 ah_http_oreq_t* _next;

#define AH_I_HTTP_ORES_FIELDS \
 ah_http_ores_t* _next;

#define AH_I_HTTP_OBODY_COMMON \
 int _kind;

struct ah_i_http_hmap_header {
    const char* _name;
    const char* _value;
    struct ah_i_http_hmap_header* _next_with_same_name;
};

struct ah_i_http_obody_any {
    AH_I_HTTP_OBODY_COMMON
};

struct ah_i_http_obody_buf {
    AH_I_HTTP_OBODY_COMMON
    ah_buf_t _buf;
};

struct ah_i_http_obody_bufs {
    AH_I_HTTP_OBODY_COMMON
    ah_bufs_t _bufs;
};

struct ah_i_http_obody_callback {
    AH_I_HTTP_OBODY_COMMON
    void (*_cb)(void* user_data, ah_bufs_t* bufs);
    void* _user_data;
};

struct ah_i_http_oreq_queue {
    struct ah_http_oreq* _head;
    struct ah_http_oreq* _end;
};

#endif
