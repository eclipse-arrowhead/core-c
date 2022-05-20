// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_HTTP_CLIENT_H_
#define SRC_HTTP_CLIENT_H_

#include "ah/http.h"

void ah_i_http_client_init_accepted(ah_http_client_t* cln, ah_http_server_t* srv, const ah_sockaddr_t* raddr);
const ah_tcp_conn_vtab_t* ah_i_http_client_get_conn_vtab();

#endif
