// SPDX-License-Identifier: EPL-2.0

#ifndef AH_MBEDTLS_H_
#define AH_MBEDTLS_H_

/**
 * @file
 * Transport Layer Security (TLS) integration using MbedTLS.
 *
 * @see https://tls.mbed.org/
 */

#include "internal/_mbedtls.h"

#include <ah/tcp.h>
#include <stdbool.h>

typedef struct ah_mbedtls_client ah_mbedtls_client_t;
typedef struct ah_mbedtls_server ah_mbedtls_server_t;

typedef void (*ah_mbedtls_on_handshake_done_cb)(ah_tcp_conn_t* conn, const mbedtls_x509_crt* peer_chain, ah_err_t err);

// MbedTLS client context.
struct ah_mbedtls_client {
    AH_I_TLS_CLIENT_FIELDS
};

// MbedTLS server context.
struct ah_mbedtls_server {
    AH_I_TLS_SERVER_FIELDS
};

// The provided SSL config must be set to client mode.
ah_extern ah_err_t ah_mbedtls_client_init(ah_mbedtls_client_t* client, ah_tcp_trans_t trans, mbedtls_ssl_config* ssl_conf, ah_mbedtls_on_handshake_done_cb on_handshake_done_cb);
ah_extern ah_tcp_trans_t ah_mbedtls_client_as_trans(ah_mbedtls_client_t* client);
ah_extern int ah_mbedtls_client_get_last_err(ah_mbedtls_client_t* client);
ah_extern mbedtls_ssl_context* ah_mbedtls_client_get_ssl_context(ah_mbedtls_client_t* client);
ah_extern void ah_mbedtls_client_term(ah_mbedtls_client_t* client);

ah_extern ah_mbedtls_client_t* ah_mbedtls_conn_get_client(ah_tcp_conn_t* conn);
ah_extern int ah_mbedtls_conn_get_last_err(ah_tcp_conn_t* conn);
ah_extern mbedtls_ssl_context* ah_mbedtls_conn_get_ssl_context(ah_tcp_conn_t* conn);

// The provided SSL config must be set to server mode.
ah_extern ah_err_t ah_mbedtls_server_init(ah_mbedtls_server_t* server, ah_tcp_trans_t trans, mbedtls_ssl_config* ssl_conf, ah_mbedtls_on_handshake_done_cb on_handshake_done_cb);
ah_extern int ah_mbedtls_server_get_last_err(ah_mbedtls_server_t* server);
ah_extern mbedtls_ssl_config* ah_mbedtls_server_get_ssl_config(ah_mbedtls_server_t* server);
ah_extern ah_tcp_trans_t ah_mbedtls_server_as_trans(ah_mbedtls_server_t* server);
ah_extern void ah_mbedtls_server_term(ah_mbedtls_server_t* server);

ah_extern ah_mbedtls_server_t* ah_mbedtls_listener_get_server(ah_tcp_listener_t* ln);
ah_extern int ah_mbedtls_listener_get_last_err(ah_tcp_listener_t* ln);
ah_extern mbedtls_ssl_config* ah_mbedtls_listener_get_ssl_config(ah_tcp_listener_t* ln);

#endif
