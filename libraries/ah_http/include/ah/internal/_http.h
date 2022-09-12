// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_HTTP_H_
#define AH_INTERNAL_HTTP_H_

#include "_http.gen"

#include <ah/buf.h>
#include <ah/defs.h>
#include <ah/internal/collections/list.h>
#include <ah/rw.h>
#include <ah/tcp.h>
#include <stddef.h>

#define AH_I_HTTP_CLIENT_FIELDS    \
 ah_tcp_conn_t* _conn;             \
 const ah_sockaddr_t* _raddr;      \
                                   \
 ah_http_client_obs_t _obs;        \
                                   \
 struct ah_i_slab* _owning_slab;   \
                                   \
 struct ah_i_list _out_queue;      \
                                   \
 size_t _in_n_expected_bytes;      \
 size_t _in_n_expected_responses;  \
 uint8_t _in_state;                \
                                   \
 bool _is_keeping_connection_open; \
 bool _is_local;

#define AH_I_HTTP_SERVER_FIELDS \
 ah_tcp_listener_t _ln;         \
 ah_http_server_obs_t _obs;     \
 struct ah_i_slab _client_slab;

#define AH_I_HTTP_CHUNK_FIELDS \
 ah_tcp_out_t* _out;

#define AH_I_HTTP_HEAD_FIELDS        \
 ah_tcp_out_t* _out;                 \
 struct ah_i_list_entry _list_entry; \
 uint16_t _n_pending_tcp_outs;       \
 bool _is_done_adding_tcp_outs;

#define AH_I_HTTP_TRAILER_FIELDS \
 ah_tcp_out_t* _out;

#endif
