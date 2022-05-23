// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/tls.h"

#include <ah/err.h>
#include <wolfssl/ssl.h>

ah_err_t ah_tls_x509_cert_parse_der(ah_tls_x509_cert_t* cert, const uint8_t* der, size_t len)
{
    (void) cert;
    (void) der;
    (void) len;
    return AH_EOPNOTSUPP;
}

ah_err_t ah_tls_x509_cert_parse_pem(ah_tls_x509_cert_t* cert, const char* pem, size_t len)
{
    (void) cert;
    (void) pem;
    (void) len;
    return AH_EOPNOTSUPP;
}
