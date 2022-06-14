// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/tcp.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"

ah_err_t ah_i_tcp_conn_open(void* ctx, ah_tcp_conn_t* conn, const ah_sockaddr_t* laddr);
ah_err_t ah_i_tcp_conn_connect(void* ctx, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr);
ah_err_t ah_i_tcp_conn_read_start(void* ctx, ah_tcp_conn_t* conn);
ah_err_t ah_i_tcp_conn_read_stop(void* ctx, ah_tcp_conn_t* conn);
ah_err_t ah_i_tcp_conn_write(void* ctx, ah_tcp_conn_t* conn, ah_tcp_msg_t* msg);
ah_err_t ah_i_tcp_conn_shutdown(void* ctx, ah_tcp_conn_t* conn, ah_tcp_shutdown_t flags);
ah_err_t ah_i_tcp_conn_close(void* ctx, ah_tcp_conn_t* conn);

ah_err_t ah_i_tcp_listener_open(void* ctx, ah_tcp_listener_t* ln, const ah_sockaddr_t* laddr);
ah_err_t ah_i_tcp_listener_listen(void* ctx, ah_tcp_listener_t* ln, unsigned backlog, const ah_tcp_conn_cbs_t* conn_cbs);
ah_err_t ah_i_tcp_listener_close(void* ctx, ah_tcp_listener_t* ln);

ah_extern ah_tcp_trans_t ah_tcp_trans_get_default(void)
{
    static const ah_tcp_vtab_t s_vtab = {
        .conn_open = ah_i_tcp_conn_open,
        .conn_connect = ah_i_tcp_conn_connect,
        .conn_read_start = ah_i_tcp_conn_read_start,
        .conn_read_stop = ah_i_tcp_conn_read_stop,
        .conn_write = ah_i_tcp_conn_write,
        .conn_shutdown = ah_i_tcp_conn_shutdown,
        .conn_close = ah_i_tcp_conn_close,

        .listener_open = ah_i_tcp_listener_open,
        .listener_listen = ah_i_tcp_listener_listen,
        .listener_close = ah_i_tcp_listener_close,
    };

    return (ah_tcp_trans_t) {
        .vtab = &s_vtab,
        .ctx = NULL,
    };
}

ah_extern bool ah_tcp_vtab_is_valid(const ah_tcp_vtab_t* vtab)
{
    if (vtab == NULL) {
        return false;
    }
    if (vtab->conn_open == NULL || vtab->conn_connect == NULL) {
        return false;
    }
    if (vtab->conn_read_start == NULL || vtab->conn_read_stop == NULL || vtab->conn_write == NULL) {
        return false;
    }
    if (vtab->conn_shutdown == NULL || vtab->conn_close == NULL) {
        return false;
    }
    if (vtab->listener_open == NULL || vtab->listener_listen == NULL || vtab->listener_close == NULL) {
        return false;
    }
    return true;
}

ah_extern ah_err_t ah_tcp_conn_init(ah_tcp_conn_t* conn, ah_loop_t* loop, ah_tcp_trans_t trans, const ah_tcp_conn_cbs_t* cbs)
{
    if (conn == NULL || loop == NULL || !ah_tcp_vtab_is_valid(trans.vtab) || cbs == NULL) {
        return AH_EINVAL;
    }
    if (cbs->on_open == NULL || cbs->on_connect == NULL || cbs->on_close == NULL) {
        return AH_EINVAL;
    }

    *conn = (ah_tcp_conn_t) {
        ._loop = loop,
        ._trans = trans,
        ._cbs = cbs,
        ._state = AH_I_TCP_CONN_STATE_CLOSED,
    };

    return AH_ENONE;
}

ah_extern ah_err_t ah_tcp_conn_open(ah_tcp_conn_t* conn, const ah_sockaddr_t* laddr)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_trans.vtab == NULL || conn->_trans.vtab->conn_open == NULL) {
        return AH_ESTATE;
    }
    return conn->_trans.vtab->conn_open(conn->_trans.ctx, conn, laddr);
}

ah_extern ah_err_t ah_tcp_conn_connect(ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_trans.vtab == NULL || conn->_trans.vtab->conn_connect == NULL) {
        return AH_ESTATE;
    }
    return conn->_trans.vtab->conn_connect(conn->_trans.ctx, conn, raddr);
}

ah_extern ah_err_t ah_tcp_conn_read_start(ah_tcp_conn_t* conn)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_trans.vtab == NULL || conn->_trans.vtab->conn_read_start == NULL) {
        return AH_ESTATE;
    }
    return conn->_trans.vtab->conn_read_start(conn->_trans.ctx, conn);
}

ah_extern ah_err_t ah_tcp_conn_read_stop(ah_tcp_conn_t* conn)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_trans.vtab == NULL || conn->_trans.vtab->conn_read_stop == NULL) {
        return AH_ESTATE;
    }
    return conn->_trans.vtab->conn_read_stop(conn->_trans.ctx, conn);
}

ah_extern ah_err_t ah_tcp_conn_write(ah_tcp_conn_t* conn, ah_tcp_msg_t* msg)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_trans.vtab == NULL || conn->_trans.vtab->conn_write == NULL) {
        return AH_ESTATE;
    }
    return conn->_trans.vtab->conn_write(conn->_trans.ctx, conn, msg);
}

ah_extern ah_err_t ah_tcp_conn_shutdown(ah_tcp_conn_t* conn, ah_tcp_shutdown_t flags)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_trans.vtab == NULL || conn->_trans.vtab->conn_shutdown == NULL) {
        return AH_ESTATE;
    }
    return conn->_trans.vtab->conn_shutdown(conn->_trans.ctx, conn, flags);
}

ah_extern ah_err_t ah_tcp_conn_close(ah_tcp_conn_t* conn)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_trans.vtab == NULL || conn->_trans.vtab->conn_close == NULL) {
        return AH_ESTATE;
    }
    return conn->_trans.vtab->conn_close(conn->_trans.ctx, conn);
}

ah_extern ah_loop_t* ah_tcp_conn_get_loop(const ah_tcp_conn_t* conn)
{
    ah_assert(conn != NULL);

    return conn->_loop;
}

ah_extern ah_tcp_shutdown_t ah_tcp_conn_get_shutdown_flags(const ah_tcp_conn_t* conn)
{
    ah_assert(conn != NULL);

    return conn->_shutdown_flags;
}

ah_extern void* ah_tcp_conn_get_user_data(const ah_tcp_conn_t* conn)
{
    ah_assert(conn != NULL);

    return conn->_user_data;
}

ah_extern bool ah_tcp_conn_is_closed(const ah_tcp_conn_t* conn)
{
    ah_assert(conn != NULL);

    return conn->_state == AH_I_TCP_CONN_STATE_CLOSED;
}

ah_extern bool ah_tcp_conn_is_readable(const ah_tcp_conn_t* conn)
{
    ah_assert(conn != NULL);

    return conn->_state >= AH_I_TCP_CONN_STATE_CONNECTED
        && (conn->_shutdown_flags & AH_TCP_SHUTDOWN_RD) == 0u;
}

ah_extern bool ah_tcp_conn_is_readable_and_writable(const ah_tcp_conn_t* conn)
{
    ah_assert(conn != NULL);

    return conn->_state >= AH_I_TCP_CONN_STATE_CONNECTED
        && (conn->_shutdown_flags & AH_TCP_SHUTDOWN_RDWR) == 0u;
}

ah_extern bool ah_tcp_conn_is_reading(const ah_tcp_conn_t* conn)
{
    ah_assert(conn != NULL);

    return conn->_state == AH_I_TCP_CONN_STATE_READING;
}

ah_extern bool ah_tcp_conn_is_writable(const ah_tcp_conn_t* conn)
{
    ah_assert(conn != NULL);

    return conn->_state >= AH_I_TCP_CONN_STATE_CONNECTED
        && (conn->_shutdown_flags & AH_TCP_SHUTDOWN_WR) == 0u;
}

ah_extern void ah_tcp_conn_set_user_data(ah_tcp_conn_t* conn, void* user_data)
{
    ah_assert(conn != NULL);

    conn->_user_data = user_data;
}

ah_extern ah_err_t ah_tcp_listener_init(ah_tcp_listener_t* ln, ah_loop_t* loop, ah_tcp_trans_t trans, const ah_tcp_listener_cbs_t* cbs)
{
    if (ln == NULL || loop == NULL || !ah_tcp_vtab_is_valid(trans.vtab) || cbs == NULL) {
        return AH_EINVAL;
    }
    if (cbs->on_open == NULL || cbs->on_listen == NULL || cbs->on_close == NULL) {
        return AH_EINVAL;
    }
    if (cbs->on_accept == NULL) {
        return AH_EINVAL;
    }

    *ln = (ah_tcp_listener_t) {
        ._loop = loop,
        ._trans = trans,
        ._cbs = cbs,
        ._state = AH_I_TCP_LISTENER_STATE_CLOSED,
    };

    return ah_i_slab_init(&ln->_conn_slab, 1u, sizeof(ah_tcp_conn_t));
}

ah_extern ah_err_t ah_tcp_listener_open(ah_tcp_listener_t* ln, const ah_sockaddr_t* laddr)
{
    if (ln == NULL) {
        return AH_EINVAL;
    }
    if (ln->_trans.vtab == NULL || ln->_trans.vtab->listener_open == NULL) {
        return AH_ESTATE;
    }
    return ln->_trans.vtab->listener_open(ln->_trans.ctx, ln, laddr);
}

ah_extern ah_err_t ah_tcp_listener_listen(ah_tcp_listener_t* ln, unsigned backlog, const ah_tcp_conn_cbs_t* conn_cbs)
{
    if (ln == NULL) {
        return AH_EINVAL;
    }
    if (ln->_trans.vtab == NULL || ln->_trans.vtab->listener_listen == NULL) {
        return AH_ESTATE;
    }
    return ln->_trans.vtab->listener_listen(ln->_trans.ctx, ln, backlog, conn_cbs);
}

ah_extern ah_err_t ah_tcp_listener_close(ah_tcp_listener_t* ln)
{
    if (ln == NULL) {
        return AH_EINVAL;
    }
    if (ln->_trans.vtab == NULL || ln->_trans.vtab->listener_close == NULL) {
        return AH_ESTATE;
    }
    return ln->_trans.vtab->listener_close(ln->_trans.ctx, ln);
}

ah_extern ah_loop_t* ah_tcp_listener_get_loop(const ah_tcp_listener_t* ln)
{
    ah_assert(ln != NULL);

    return ln->_loop;
}

ah_extern void* ah_tcp_listener_get_user_data(const ah_tcp_listener_t* ln)
{
    ah_assert(ln != NULL);

    return ln->_user_data;
}

ah_extern bool ah_tcp_listener_is_closed(ah_tcp_listener_t* ln)
{
    ah_assert(ln != NULL);

    return ln->_state == AH_I_TCP_LISTENER_STATE_CLOSED;
}

ah_extern void ah_tcp_listener_set_user_data(ah_tcp_listener_t* ln, void* user_data)
{
    ah_assert(ln != NULL);

    ln->_user_data = user_data;
}
