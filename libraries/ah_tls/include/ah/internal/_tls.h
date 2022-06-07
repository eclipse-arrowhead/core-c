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

#define AH_I_TLS_CERT_FIELDS \
 mbedtls_x509_crt _x509_crt;

#define AH_I_TLS_CERT_STORE_FIELDS \
 mbedtls_x509_crt* _authorities;   \
 mbedtls_x509_crt* _own_chain;     \
 mbedtls_pk_context* _own_key;     \
 mbedtls_x509_crl* _revocations;

#define AH_I_TLS_CRL_FIELDS \
 mbedtls_x509_crl _x509_crl;

#define AH_I_TLS_CTX_FIELDS                           \
 ah_tcp_trans_t _trans;                               \
 const ah_tcp_conn_cbs_t* _conn_cbs;                  \
 const ah_tcp_listener_cbs_t* _ln_cbs;                \
 ah_tls_cert_store_t* _certs;                         \
 ah_tls_on_handshake_done_cb _on_handshake_done;      \
 ah_buf_t _recv_ciphertext_buf;                       \
 struct ah_i_tls_send_queue _send_ciphertext_queue;   \
 bool _is_closing_on_next_write_done             : 1; \
 bool _is_handshake_done                         : 1; \
 bool _is_handshaking_on_next_read_data          : 1; \
 bool _is_shutting_down_wr_on_next_write_done    : 1; \
 bool _is_stopping_reads_on_handshake_completion : 1; \
                                                      \
 int _last_mbedtls_err;                               \
 ah_err_t _pending_ah_err;                            \
                                                      \
 mbedtls_ctr_drbg_context _ctr_drbg;                  \
 mbedtls_entropy_context _entropy;                    \
 mbedtls_ssl_context _ssl;                            \
 mbedtls_ssl_cache_context _ssl_cache;                \
 mbedtls_ssl_config _ssl_conf;

#define AH_I_TLS_KEYS_FIELDS \
 mbedtls_pk_context _pk_cxt;

struct ah_i_tls_send_queue {
    size_t _capacity;
    size_t _index_read;
    size_t _index_write;
    struct ah_tcp_msg* _entries;
};

#endif
