// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_HTTP_UTILS_H_
#define SRC_HTTP_UTILS_H_

#include "ah/http.h"

ah_http_lclient_t* ah_i_http_upcast_to_lclient(ah_tcp_conn_t* conn);
ah_http_rclient_t* ah_i_http_upcast_to_rclient(ah_tcp_conn_t* conn);
ah_http_server_t* ah_i_http_upcast_to_server(ah_tcp_listener_t* ln);

#endif
