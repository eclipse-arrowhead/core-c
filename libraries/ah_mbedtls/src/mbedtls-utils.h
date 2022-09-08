// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_TLS_UTILS_H_
#define SRC_TLS_UTILS_H_

#include "ah/mbedtls.h"

extern const ah_tcp_trans_vtab_t ah_i_mbedtls_tcp_vtab;

ah_err_t ah_i_mbedtls_res_to_err(struct ah_i_mbedtls_errs* errs, int res);

#endif
