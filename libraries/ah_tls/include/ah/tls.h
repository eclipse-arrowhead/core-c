// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_TLS_H_
#define AH_TLS_H_

#include "internal/_tls.h"

#include <ah/defs.h>
#include <stddef.h>
#include <stdint.h>

typedef struct ah_tls_x509_cert ah_tls_x509_cert_t;
typedef struct ah_tls_priv_key ah_tls_priv_key_t;

struct ah_tls_x509_cert {
    int todo;
};

struct ah_tls_priv_key {
    int todo;
};

ah_err_t ah_tls_x509_cert_parse_der(ah_tls_x509_cert_t* cert, const uint8_t* der, size_t len);
ah_err_t ah_tls_x509_cert_parse_pem(ah_tls_x509_cert_t* cert, const char* pem, size_t len);

#endif
