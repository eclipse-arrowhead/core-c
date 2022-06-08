// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_TLS_H_
#define AH_INTERNAL_TLS_H_

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cache.h>

#define AH_I_TLS_CLIENT_FIELDS                          \
 ah_tcp_trans_t _trans;                                 \
 const ah_tcp_conn_cbs_t* _conn_cbs;                    \
                                                        \
 ah_buf_t _recv_ciphertext_buf;                         \
 struct ah_i_mbedtls_send_queue _send_ciphertext_queue; \
                                                        \
 bool _is_handshake_done;                               \
 bool _is_handshaking_on_next_read_data;                \
 bool _is_stopping_reads_on_handshake_completion;       \
                                                        \
 struct ah_i_mbedtls_errs _errs;                        \
 ah_mbedtls_on_handshake_done_cb _on_handshake_done_cb; \
                                                        \
 struct ah_mbedtls_server* _server;                     \
 mbedtls_ssl_context _ssl;                              \
                                                        \
 struct ah_mbedtls_client* _next_free;

#define AH_I_TLS_SERVER_FIELDS                          \
 ah_tcp_trans_t _trans;                                 \
 const ah_tcp_conn_cbs_t* _conn_cbs;                    \
 const ah_tcp_listener_cbs_t* _ln_cbs;                  \
                                                        \
 struct ah_i_mbedtls_errs _errs;                        \
 ah_mbedtls_on_handshake_done_cb _on_handshake_done_cb; \
                                                        \
 mbedtls_ssl_config* _ssl_conf;                         \
                                                        \
 struct ah_i_mbedtls_client_allocator _client_allocator;

struct ah_tcp_conn;

struct ah_i_mbedtls_client_allocator {
    struct ah_i_tls_client_page* _page_list;
    struct ah_mbedtls_client* _free_list;
};

struct ah_i_mbedtls_errs {
    int _last_mbedtls_err;
    int _pending_ah_err;
};

struct ah_i_mbedtls_send_queue {
    size_t _capacity;
    size_t _index_read;
    size_t _index_write;
    struct ah_i_mbedtls_send_queue_entry* _entries;
};

#endif
