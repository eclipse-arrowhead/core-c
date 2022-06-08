// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_MBEDTLS_H_
#define AH_MBEDTLS_H_

#include "internal/_mbedtls.h"

#include <ah/tcp.h>
#include <stdbool.h>

typedef struct ah_mbedtls_cert_store ah_mbedtls_cert_store_t;
typedef struct ah_tls_client ah_tls_client_t;
typedef struct ah_tls_server ah_tls_server_t;

typedef void (*ah_tls_on_handshake_done_cb)(ah_tcp_conn_t* conn, const mbedtls_x509_crt* peer_chain, ah_err_t err);

// TLS certificate store.
struct ah_mbedtls_cert_store {
    mbedtls_x509_crt* authorities; // May be NULL if server.
    mbedtls_x509_crt* own_chain;   // May be NULL if client.
    mbedtls_pk_context* own_key;   // May be NULL if client.
    mbedtls_x509_crl* revocations; // May be NULL.
};

// TLS client context.
struct ah_tls_client {
    AH_I_TLS_CLIENT_FIELDS
};

// TLS server context.
struct ah_tls_server {
    AH_I_TLS_SERVER_FIELDS
};

ah_extern ah_err_t ah_tls_client_init(ah_tls_client_t* client, ah_tcp_trans_t trans, ah_mbedtls_cert_store_t* certs, ah_tls_on_handshake_done_cb on_handshake_done_cb);
ah_extern ah_tcp_trans_t ah_tls_client_as_trans(ah_tls_client_t* client);
ah_extern ah_tls_client_t* ah_tls_client_get_from_conn(ah_tcp_conn_t* conn);
ah_extern int ah_tls_client_get_last_mbedtls_err(ah_tls_client_t* client);
ah_extern int ah_tls_client_get_last_mbedtls_err_from_conn(ah_tcp_conn_t* conn);
ah_extern mbedtls_ctr_drbg_context* ah_tls_client_get_drbg_context(ah_tls_client_t* client);
ah_extern mbedtls_entropy_context* ah_tls_client_get_entropy_context(ah_tls_client_t* client);
ah_extern mbedtls_ssl_config* ah_tls_client_get_ssl_config(ah_tls_client_t* client);
ah_extern mbedtls_ssl_context* ah_tls_client_get_ssl_context(ah_tls_client_t* client);
ah_extern void ah_tls_client_term(ah_tls_client_t* client);

ah_extern ah_err_t ah_tls_server_init(ah_tls_server_t* server, ah_tcp_trans_t trans, ah_mbedtls_cert_store_t* certs, ah_tls_on_handshake_done_cb on_handshake_done_cb);
ah_extern ah_tls_server_t* ah_tls_server_get_from_listener(ah_tcp_listener_t* ln);
ah_extern int ah_tls_server_get_last_mbedtls_err(ah_tls_server_t* server);
ah_extern mbedtls_ctr_drbg_context* ah_tls_server_get_drbg_context(ah_tls_server_t* server);
ah_extern mbedtls_entropy_context* ah_tls_server_get_entropy_context(ah_tls_server_t* server);
ah_extern mbedtls_ssl_cache_context* ah_tls_server_get_ssl_cache_context(ah_tls_server_t* server);
ah_extern mbedtls_ssl_config* ah_tls_server_get_ssl_config(ah_tls_server_t* server);
ah_extern ah_tcp_trans_t ah_tls_server_as_trans(ah_tls_server_t* server);
ah_extern void ah_tls_server_term(ah_tls_server_t* server);

#endif
