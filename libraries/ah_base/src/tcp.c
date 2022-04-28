// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/tcp.h"

ah_extern ah_tcp_trans_t ah_tcp_transport(ah_loop_t* loop)
{
    ah_assert_if_debug(loop != NULL);

    static const ah_tcp_vtab_t s_vtab = {
        .open = ah_tcp_open,
        .connect = ah_tcp_connect,
        .listen = ah_tcp_listen,
        .read_start = ah_tcp_read_start,
        .read_stop = ah_tcp_read_stop,
        .write = ah_tcp_write,
        .shutdown = ah_tcp_shutdown,
        .close = ah_tcp_close,
    };

    return (ah_tcp_trans_t) {
        ._vtab = &s_vtab,
        ._loop = loop,
        ._data = NULL,
    };
}
