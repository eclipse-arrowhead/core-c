// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_TLS_CLIENT_H_
#define SRC_TLS_CLIENT_H_

#include "ah/tls.h"

extern const ah_tcp_conn_cbs_t ah_i_tls_tcp_conn_cbs;

ah_err_t ah_i_tls_client_init(ah_tls_client_t* client, ah_tcp_trans_t trans, struct ah_i_tls_ctx* ctx);

ah_err_t ah_i_tls_client_open(void* client_, ah_tcp_conn_t* conn, const ah_sockaddr_t* laddr);
ah_err_t ah_i_tls_client_connect(void* client_, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr);
ah_err_t ah_i_tls_client_read_start(void* client_, ah_tcp_conn_t* conn);
ah_err_t ah_i_tls_client_read_stop(void* client_, ah_tcp_conn_t* conn);
ah_err_t ah_i_tls_client_write(void* client_, ah_tcp_conn_t* conn, ah_tcp_msg_t* msg);
ah_err_t ah_i_tls_client_shutdown(void* client_, ah_tcp_conn_t* conn, ah_tcp_shutdown_t flags);
ah_err_t ah_i_tls_client_close(void* client_, ah_tcp_conn_t* conn);

#endif
