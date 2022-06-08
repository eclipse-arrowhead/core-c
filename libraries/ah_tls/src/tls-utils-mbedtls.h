// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_TLS_UTILS_MBEDTLS_H_
#define SRC_TLS_UTILS_MBEDTLS_H_

#include "ah/tls.h"

const ah_tls_cert_t* ah_i_tls_cert_from_mbedtls(const mbedtls_x509_crt* crt);
ah_err_t ah_i_tls_mbedtls_res_to_err(struct ah_i_tls_errs* errs, int res);

#endif
