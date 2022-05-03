// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_HTTP_H_
#define AH_INTERNAL_HTTP_H_

#include <ah/buf.h>
#include <ah/defs.h>
#include <ah/str.h>
#include <ah/tcp.h>
#include <stddef.h>

#define AH_I_HTTP_OBODY_KIND_BUF      1u
#define AH_I_HTTP_OBODY_KIND_BUFVEC   2u
#define AH_I_HTTP_OBODY_KIND_CALLBACK 3u

#define AH_I_HTTP_CLIENT_FIELDS                                                                                        \
    ah_tcp_conn_t _conn;                                                                                               \
    ah_tcp_trans_t _trans;                                                                                             \
    const ah_http_client_vtab_t* _vtab;

#define AH_I_HTTP_SERVER_FIELDS                                                                                        \
    ah_tcp_listener_t _ln;                                                                                             \
    ah_tcp_trans_t _trans;                                                                                             \
    const ah_http_server_vtab_t* _vtab;                                                                                \
    uint16_t _req_header_capacity;

#define AH_I_HTTP_HMAP_FIELDS                                                                                          \
    uint16_t _mask;                                                                                                    \
    uint16_t _count;                                                                                                   \
    struct ah_i_http_hmap_header* _headers;

#define AH_I_HTTP_HMAP_VALUE_ITER_FIELDS const struct ah_i_http_hmap_header* _header;

#define AH_I_HTTP_OBODY_FIELDS                                                                                         \
    struct ah_i_http_obody_any _as_any;                                                                                \
    struct ah_i_http_obody_buf _as_buf;                                                                                \
    struct ah_i_http_obody_bufs _as_bufs;                                                                              \
    struct ah_i_http_obody_callback _as_callback;

#define AH_I_HTTP_OBODY_COMMON int _kind;

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
    void (*_cb)(ah_bufs_t* bufs);
};

struct ah_i_http_hmap_header {
    ah_str_t _name;
    ah_str_t _value;
    struct ah_i_http_hmap_header* _next_with_same_name;
};

#endif
