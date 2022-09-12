// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_TLS_H_
#define AH_INTERNAL_TLS_H_

#include "_mbedtls.gen"

#include <ah/internal/collections/ring.h>
#include <ah/internal/collections/slab.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cache.h>

#define AH_I_TLS_CLIENT_FIELDS                          \
 ah_tcp_conn_t* _conn;                                  \
 ah_tcp_conn_obs_t _conn_obs;                           \
 ah_tcp_trans_t _trans;                                 \
                                                        \
 ah_tcp_in_t* _in_ciphertext;                           \
 ah_tcp_in_t* _in_plaintext;                            \
                                                        \
 struct ah_i_ring _out_queue_ciphertext;                \
                                                        \
 bool _is_handshake_done;                               \
                                                        \
 struct ah_i_mbedtls_errs _errs;                        \
 ah_mbedtls_on_handshake_done_cb _on_handshake_done_cb; \
                                                        \
 struct ah_mbedtls_server* _server;                     \
 mbedtls_ssl_context _ssl;                              \
                                                        \
 struct ah_mbedtls_client* _next_free;

#define AH_I_TLS_SERVER_FIELDS                          \
 ah_tcp_listener_obs_t _ln_obs;                         \
 ah_tcp_trans_t _trans;                                 \
                                                        \
 struct ah_i_mbedtls_errs _errs;                        \
 ah_mbedtls_on_handshake_done_cb _on_handshake_done_cb; \
                                                        \
 mbedtls_ssl_config* _ssl_conf;                         \
                                                        \
 struct ah_i_slab _client_slab;

struct ah_i_mbedtls_errs {
    int _last_mbedtls_err;
    int _pending_ah_err;
};

#endif
