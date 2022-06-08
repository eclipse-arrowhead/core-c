// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "tls-utils.h"
#include "tls-client.h"
#include "tls-server.h"

const ah_tcp_vtab_t ah_i_tls_tcp_vtab = {
    .conn_open = ah_i_tls_client_open,
    .conn_connect = ah_i_tls_client_connect,
    .conn_read_start = ah_i_tls_client_read_start,
    .conn_read_stop = ah_i_tls_client_read_stop,
    .conn_write = ah_i_tls_client_write,
    .conn_shutdown = ah_i_tls_client_shutdown,
    .conn_close = ah_i_tls_client_close,

    .listener_open = ah_i_tls_server_open,
    .listener_listen = ah_i_tls_server_listen,
    .listener_close = ah_i_tls_server_close,
};

