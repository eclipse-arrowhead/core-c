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
typedef struct ah_tls_crl ah_tls_crl_t;
typedef struct ah_tls_ctx ah_tls_ctx_t;
typedef struct ah_tls_key ah_tls_key_t;

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

// TLS certificate revocation list.
struct ah_tls_crl {
    AH_I_TLS_CRL_FIELDS
};

// TLS context.
struct ah_tls_ctx {
    AH_I_TLS_CTX_FIELDS
};

// Public/private key pair.
struct ah_tls_key {
    AH_I_TLS_KEYS_FIELDS
};

ah_extern ah_err_t ah_tls_ctx_init(ah_tls_ctx_t* ctx, ah_tcp_trans_t trans, ah_tls_cert_store_t* certs);
ah_extern ah_tls_err_t ah_tls_ctx_get_last_error(ah_tls_ctx_t* ctx);
ah_extern ah_tcp_trans_t ah_tls_ctx_get_transport(ah_tls_ctx_t* ctx);
ah_extern void ah_tls_ctx_term(ah_tls_ctx_t* ctx);

#endif
