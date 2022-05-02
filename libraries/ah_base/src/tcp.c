// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/tcp.h"

#include "ah/err.h"
#include "ah/loop.h"

ah_extern ah_err_t ah_tcp_conn_init(ah_tcp_conn_t* conn, ah_loop_t* loop, const ah_tcp_conn_vtab_t* vtab)
{
    if (conn == NULL || loop == NULL || vtab == NULL) {
        return AH_EINVAL;
    }
    if (vtab->on_open == NULL || vtab->on_connect == NULL || vtab->on_close == NULL) {
        return AH_EINVAL;
    }
    if ((vtab->on_read_alloc == NULL) != (vtab->on_read_done == NULL)) {
        return AH_EINVAL;
    }
    if (ah_loop_is_term(loop)) {
        return AH_ESTATE;
    }

    *conn = (ah_tcp_conn_t) {
        ._loop = loop,
        ._vtab = vtab,
        ._state = AH_I_TCP_CONN_STATE_CLOSED,
    };

    return AH_ENONE;
}

ah_extern ah_err_t ah_tcp_listener_init(ah_tcp_listener_t* ln, ah_loop_t* loop, const ah_tcp_listener_vtab_t* vtab)
{
    if (ln == NULL || loop == NULL || vtab == NULL) {
        return AH_EINVAL;
    }
    if (vtab->on_open == NULL || vtab->on_listen == NULL || vtab->on_close == NULL) {
        return AH_EINVAL;
    }
    if (vtab->on_conn_alloc == NULL || vtab->on_conn_accept == NULL) {
        return AH_EINVAL;
    }
    if (ah_loop_is_term(loop)) {
        return AH_ESTATE;
    }

    *ln = (ah_tcp_listener_t) {
        ._loop = loop,
        ._vtab = vtab,
        ._state = AH_I_TCP_LISTENER_STATE_CLOSED,
    };

    return AH_ENONE;
}

ah_extern void ah_tcp_trans_init(ah_tcp_trans_t* trans, ah_loop_t* loop)
{
    ah_assert_if_debug(loop != NULL);

    static const ah_tcp_trans_vtab_t s_vtab = {
        .conn_init = ah_tcp_conn_init,
        .conn_open = ah_tcp_conn_open,
        .conn_connect = ah_tcp_conn_connect,
        .conn_read_start = ah_tcp_conn_read_start,
        .conn_read_stop = ah_tcp_conn_read_stop,
        .conn_write = ah_tcp_conn_write,
        .conn_shutdown = ah_tcp_conn_shutdown,
        .conn_close = ah_tcp_conn_close,

        .listener_init = ah_tcp_listener_init,
        .listener_open = ah_tcp_listener_open,
        .listener_listen = ah_tcp_listener_listen,
        .listener_close = ah_tcp_listener_close,

    };

    *trans = (ah_tcp_trans_t) {
        ._vtab = &s_vtab,
        ._loop = loop,
        ._data = NULL,
    };
}
