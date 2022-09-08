// SPDX-License-Identifier: EPL-2.0

#include "ah/tcp.h"

#include "ah/err.h"
#include "ah/intrin.h"
#include "tcp-trans-default.h"

ah_extern ah_tcp_trans_t ah_tcp_trans_get_default(void)
{
    static const ah_tcp_trans_vtab_t s_vtab = {
        .conn_init = ah_i_tcp_trans_default_conn_init,
        .conn_open = ah_i_tcp_trans_default_conn_open,
        .conn_connect = ah_i_tcp_trans_default_conn_connect,
        .conn_read_start = ah_i_tcp_trans_default_conn_read_start,
        .conn_read_stop = ah_i_tcp_trans_default_conn_read_stop,
        .conn_write = ah_i_tcp_trans_default_conn_write,
        .conn_shutdown = ah_i_tcp_trans_default_conn_shutdown,
        .conn_close = ah_i_tcp_trans_default_conn_close,
        .conn_term = ah_i_tcp_trans_default_conn_term,
        .conn_get_family = ah_i_tcp_trans_default_conn_get_family,
        .conn_get_laddr = ah_i_tcp_trans_default_conn_get_laddr,
        .conn_get_raddr = ah_i_tcp_trans_default_conn_get_raddr,
        .conn_get_loop = ah_i_tcp_trans_default_conn_get_loop,
        .conn_get_obs_ctx = ah_i_tcp_trans_default_conn_get_obs_ctx,
        .conn_is_closed = ah_i_tcp_trans_default_conn_is_closed,
        .conn_is_readable = ah_i_tcp_trans_default_conn_is_readable,
        .conn_is_reading = ah_i_tcp_trans_default_conn_is_reading,
        .conn_is_writable = ah_i_tcp_trans_default_conn_is_writable,
        .conn_set_keepalive = ah_i_tcp_trans_default_conn_set_keepalive,
        .conn_set_nodelay = ah_i_tcp_trans_default_conn_set_nodelay,
        .conn_set_reuseaddr = ah_i_tcp_trans_default_conn_set_reuseaddr,

        .listener_init = ah_i_tcp_trans_default_listener_init,
        .listener_open = ah_i_tcp_trans_default_listener_open,
        .listener_listen = ah_i_tcp_trans_default_listener_listen,
        .listener_close = ah_i_tcp_trans_default_listener_close,
        .listener_term = ah_i_tcp_trans_default_listener_term,
        .listener_get_family = ah_i_tcp_trans_default_listener_get_family,
        .listener_get_laddr = ah_i_tcp_trans_default_listener_get_laddr,
        .listener_get_loop = ah_i_tcp_trans_default_listener_get_loop,
        .listener_get_obs_ctx = ah_i_tcp_trans_default_listener_get_obs_ctx,
        .listener_is_closed = ah_i_tcp_trans_default_listener_is_closed,
        .listener_set_keepalive = ah_i_tcp_trans_default_listener_set_keepalive,
        .listener_set_nodelay = ah_i_tcp_trans_default_listener_set_nodelay,
        .listener_set_reuseaddr = ah_i_tcp_trans_default_listener_set_reuseaddr,
        .listener_prepare = ah_i_tcp_trans_default_listener_prepare,
    };

    return (ah_tcp_trans_t) {
        .vtab = &s_vtab,
        .ctx = NULL,
    };
}

ah_extern bool ah_tcp_trans_vtab_is_valid(const ah_tcp_trans_vtab_t* vtab)
{
    return vtab != NULL
        && vtab->conn_init != NULL
        && vtab->conn_open != NULL
        && vtab->conn_connect != NULL
        && vtab->conn_read_start != NULL
        && vtab->conn_read_stop != NULL
        && vtab->conn_write != NULL
        && vtab->conn_shutdown != NULL
        && vtab->conn_close != NULL
        && vtab->conn_term != NULL
        && vtab->conn_get_family != NULL
        && vtab->conn_get_laddr != NULL
        && vtab->conn_get_raddr != NULL
        && vtab->conn_get_loop != NULL
        && vtab->conn_get_obs_ctx != NULL
        && vtab->conn_is_closed != NULL
        && vtab->conn_is_readable != NULL
        && vtab->conn_is_reading != NULL
        && vtab->conn_is_writable != NULL
        && vtab->conn_set_keepalive != NULL
        && vtab->conn_set_nodelay != NULL
        && vtab->conn_set_reuseaddr != NULL
        && vtab->listener_init != NULL
        && vtab->listener_open != NULL
        && vtab->listener_listen != NULL
        && vtab->listener_close != NULL
        && vtab->listener_term != NULL
        && vtab->listener_get_family != NULL
        && vtab->listener_get_laddr != NULL
        && vtab->listener_get_loop != NULL
        && vtab->listener_get_obs_ctx != NULL
        && vtab->listener_is_closed != NULL
        && vtab->listener_set_keepalive != NULL
        && vtab->listener_set_nodelay != NULL
        && vtab->listener_set_reuseaddr != NULL
        && vtab->listener_prepare != NULL;
}
