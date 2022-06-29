// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_TLS_UTILS_H_
#define SRC_TLS_UTILS_H_

#include "ah/mbedtls.h"

extern const ah_tcp_vtab_t ah_i_mbedtls_tcp_vtab;

ah_err_t ah_i_mbedtls_res_to_err(struct ah_i_mbedtls_errs* errs, int res);

#endif
