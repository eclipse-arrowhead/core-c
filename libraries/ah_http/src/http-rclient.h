// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_HTTP_RCLIENT_H_
#define SRC_HTTP_RCLIENT_H_

#include "ah/http.h"

ah_err_t ah_i_http_rclient_init(ah_http_rclient_t* cln, ah_http_server_t* srv, const ah_sockaddr_t* raddr);
const ah_tcp_conn_vtab_t* ah_i_http_rclient_get_conn_vtab();

#endif
