// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_TLS_SERVER_H_
#define SRC_TLS_SERVER_H_

#include "ah/tls.h"

void ah_i_tls_server_free_accepted_client(ah_tls_server_t* server, ah_tls_client_t* client);

ah_err_t ah_i_tls_server_open(void* server_, ah_tcp_listener_t* ln, const ah_sockaddr_t* laddr);
ah_err_t ah_i_tls_server_listen(void* server_, ah_tcp_listener_t* ln, unsigned backlog, const ah_tcp_conn_cbs_t* conn_cbs);
ah_err_t ah_i_tls_server_close(void* server_, ah_tcp_listener_t* ln);

#endif
