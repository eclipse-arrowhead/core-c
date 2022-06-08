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

// The provided SSL config must be set in client mode.
ah_extern ah_err_t ah_mbedtls_client_init(ah_mbedtls_client_t* client, ah_tcp_trans_t trans, mbedtls_ssl_config* ssl_conf, ah_mbedtls_on_handshake_done_cb on_handshake_done_cb);
ah_extern ah_tcp_trans_t ah_mbedtls_client_as_trans(ah_mbedtls_client_t* client);
ah_extern ah_mbedtls_client_t* ah_mbedtls_client_get_from_conn(ah_tcp_conn_t* conn);
ah_extern int ah_mbedtls_client_get_last_err(ah_mbedtls_client_t* client);
ah_extern int ah_mbedtls_client_get_last_err_from_conn(ah_tcp_conn_t* conn);
ah_extern void ah_mbedtls_client_term(ah_mbedtls_client_t* client);

// The provided SSL config must be set in server mode.
ah_extern ah_err_t ah_mbedtls_server_init(ah_mbedtls_server_t* server, ah_tcp_trans_t trans, mbedtls_ssl_config* ssl_conf, ah_mbedtls_on_handshake_done_cb on_handshake_done_cb);
ah_extern ah_mbedtls_server_t* ah_mbedtls_server_get_from_listener(ah_tcp_listener_t* ln);
ah_extern int ah_mbedtls_server_get_last_err(ah_mbedtls_server_t* server);
ah_extern ah_tcp_trans_t ah_mbedtls_server_as_trans(ah_mbedtls_server_t* server);
ah_extern void ah_mbedtls_server_term(ah_mbedtls_server_t* server);

#endif
