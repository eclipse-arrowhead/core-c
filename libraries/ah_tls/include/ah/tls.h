// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_TLS_H_
#define AH_TLS_H_

#include "internal/_tls.h"

#include <ah/tcp.h>
#include <stdbool.h>

#define AH_TLS_CERT_KIND_NONE 0x00
#define AH_TLS_CERT_KIND_X509 0x01

#define AH_TLS_CERT_FMT_NONE 0x00
#define AH_TLS_CERT_FMT_ASN1 0x01
#define AH_TLS_CERT_FMT_PEM  0x02

#define AH_TLS_VER_1_2 0x12
#define AH_TLS_VER_1_3 0x13

typedef int ah_tls_err_t;

typedef struct ah_tls_cert ah_tls_cert_t;
typedef struct ah_tls_cert_store ah_tls_cert_store_t;
typedef struct ah_tls_client ah_tls_client_t;
typedef struct ah_tls_crl ah_tls_crl_t;
typedef struct ah_tls_keys ah_tls_keys_t;
typedef struct ah_tls_server ah_tls_server_t;

typedef void (*ah_tls_on_handshake_done_cb)(ah_tcp_conn_t* conn, const ah_tls_cert_t* peer_chain, ah_err_t err);

// TLS-compatible certificate (always an X.509 certificate).
struct ah_tls_cert {
    AH_I_TLS_CERT_FIELDS
};

// TLS certificate store, containing trusted certificate roots, one personal
// certificate chain, one personal public/private key pair and one certificate
// revocation list.
struct ah_tls_cert_store {
    AH_I_TLS_CERT_STORE_FIELDS
};

// TLS client context.
struct ah_tls_client {
    AH_I_TLS_CLIENT_FIELDS
};

// TLS certificate revocation list.
struct ah_tls_crl {
    AH_I_TLS_CRL_FIELDS
};

// Public/private key pair.
struct ah_tls_keys {
    AH_I_TLS_KEYS_FIELDS
};

// TLS server context.
struct ah_tls_server {
    AH_I_TLS_SERVER_FIELDS
};

ah_extern ah_err_t ah_tls_client_init(ah_tls_client_t* client, ah_tcp_trans_t trans, ah_tls_cert_store_t* certs, ah_tls_on_handshake_done_cb on_handshake_done_cb);
ah_extern ah_tcp_trans_t ah_tls_client_as_trans(ah_tls_client_t* client);
ah_extern ah_tls_client_t* ah_tls_client_get_from_conn(ah_tcp_conn_t* conn);
ah_extern ah_tls_err_t ah_tls_client_get_last_error(ah_tls_client_t* client);
ah_extern ah_tls_err_t ah_tls_client_get_last_error_from_conn(ah_tcp_conn_t* conn);
ah_extern void ah_tls_client_term(ah_tls_client_t* client);

#endif
