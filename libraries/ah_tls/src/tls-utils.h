// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_TLS_UTILS_H_
#define SRC_TLS_UTILS_H_

#include "ah/tls.h"

extern const ah_tcp_vtab_t ah_i_tls_tcp_vtab;

ah_tls_err_t ah_i_tls_ctx_init(struct ah_i_tls_ctx* ctx, ah_tls_cert_store_t* certs, ah_tls_on_handshake_done_cb on_handshake_done_cb, int endpoint);
void ah_i_tls_ctx_term(struct ah_i_tls_ctx* ctx);

#endif
