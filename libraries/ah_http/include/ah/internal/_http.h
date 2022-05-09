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
#define AH_I_HTTP_OBODY_KIND_BUFS     2u
#define AH_I_HTTP_OBODY_KIND_CALLBACK 3u

#define AH_I_HTTP_CLIENT_FIELDS          \
 ah_tcp_conn_t _conn;                    \
 const ah_tcp_trans_vtab_t* _trans_vtab; \
 const ah_http_client_vtab_t* _vtab;     \
 size_t _i_n_bytes_expected;             \
 struct ah_i_http_parser _i_parser;      \
 ah_http_ires_t* _i_res;                 \
 uint8_t _i_hmap_size_log2;              \
 uint8_t _i_state;                       \
 uint8_t _o_state;                       \
 uint8_t _n_pending_responses;

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

#define AH_I_HTTP_OBODY_COMMON \
 int _kind;

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

// The following data layout is used by an HTTP parser. The block of numbers
// represents the block of memory that is being parsed. The arrows above it show
// where the struct pointers point into that memory. The dotted region
// indicators below the memory denote what memory is generally readable,
// generally writable and remains to be parsed.
//
//                        _off       _limit                   _end
//                          |           |                       |
//                          V           V                       V
//              +---+---+---+---+---+---+---+---+---+---+---+---+
// Memory block | 1 | 7 | 3 | 2 | 4 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
//              +---+---+---+---+---+---+---+---+---+---+---+---+
//               :.....................: :.....................:
//                          :                       :
//                   Readable bytes           Writable bytes
//                           :.........:
//                                :
//                       Not yet parsed bytes
//
// The _off and _limit pointers are updated as the memory region is parsed and
// filled with more received data, respectively. If the not yet parsed region
// does not contain a complete grammatical unit (such as a header name/value
// pair) and does not have room for more received bytes, those not yet parsed
// bytes must be copied over into a new memory buffer before parsing can
// continue.
struct ah_i_http_parser {
    const uint8_t* _off;
    const uint8_t* _limit;
    const uint8_t* _end;
};

#endif
