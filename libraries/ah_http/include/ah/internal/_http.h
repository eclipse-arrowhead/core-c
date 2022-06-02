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

#define AH_I_HTTP_BODY_KIND_EMPTY    0u
#define AH_I_HTTP_BODY_KIND_OVERRIDE 1u
#define AH_I_HTTP_BODY_KIND_MSG      2u

#define AH_I_HTTP_CLIENT_FIELDS           \
 ah_tcp_conn_t _conn;                     \
 const ah_sockaddr_t* _raddr;             \
 const struct ah_http_client_vtab* _vtab; \
 struct ah_i_http_msg_queue _out_queue;   \
 ah_buf_rw_t _in_buf_rw;                  \
 size_t _in_n_expected_bytes;             \
 size_t _in_n_expected_responses;         \
 uint8_t _in_state;                       \
 bool _is_keeping_connection_open;        \
 bool _is_local;                          \
 bool _is_preventing_realloc;

#define AH_I_HTTP_SERVER_FIELDS      \
 ah_tcp_listener_t _ln;              \
 const ah_http_server_vtab_t* _vtab; \
 const ah_http_client_vtab_t* _client_vtab;

#define AH_I_HTTP_BODY_FIELDS       \
 struct ah_i_http_body_any _as_any; \
 struct ah_i_http_body_msg _as_msg;

#define AH_I_HTTP_CHUNK_FIELDS \
 ah_tcp_msg_t _line;

#define AH_I_HTTP_MSG_FIELDS \
 struct ah_http_msg* _next;  \
 ah_tcp_msg_t _head;  \
 unsigned _n_pending_tcp_msgs;

#define AH_I_HTTP_TRAILER_FIELDS \
 ah_tcp_msg_t _msg;

#define AH_I_HTTP_OBODY_COMMON \
 unsigned _kind;

struct ah_i_http_body_any {
    AH_I_HTTP_OBODY_COMMON
};

struct ah_i_http_body_msg {
    AH_I_HTTP_OBODY_COMMON
    ah_tcp_msg_t _msg;
};

struct ah_i_http_msg_queue {
    struct ah_http_msg* _head;
    struct ah_http_msg* _end;
};

#endif
