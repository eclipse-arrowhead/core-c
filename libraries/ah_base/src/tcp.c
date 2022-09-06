// SPDX-License-Identifier: EPL-2.0

#include "ah/tcp.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"
#include "ah/sock.h"
#include "tcp-trans-default.h"

ah_extern ah_err_t ah_tcp_conn_init(ah_tcp_conn_t* conn, ah_loop_t* loop, ah_tcp_trans_t trans, ah_tcp_conn_obs_t obs)
{
    if (ah_unlikely(conn == NULL || trans.vtab == NULL || trans.vtab->conn_init == NULL)) {
        return AH_EINVAL;
    }

    (void) memset(conn, 0, sizeof(*conn));

    return trans.vtab->conn_init(trans.ctx, conn, loop, trans, obs);
}

ah_extern ah_err_t ah_tcp_conn_open(ah_tcp_conn_t* conn, const ah_sockaddr_t* laddr)
{
    if (ah_unlikely(conn == NULL || conn->_trans.vtab == NULL || conn->_trans.vtab->conn_open == NULL)) {
        return AH_EINVAL;
    }
    return conn->_trans.vtab->conn_open(conn->_trans.ctx, conn, laddr);
}

ah_extern ah_err_t ah_tcp_conn_connect(ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr)
{
    if (ah_unlikely(conn == NULL || conn->_trans.vtab == NULL || conn->_trans.vtab->conn_connect == NULL)) {
        return AH_EINVAL;
    }
    return conn->_trans.vtab->conn_connect(conn->_trans.ctx, conn, raddr);
}

ah_extern ah_err_t ah_tcp_conn_read_start(ah_tcp_conn_t* conn)
{
    if (ah_unlikely(conn == NULL || conn->_trans.vtab == NULL || conn->_trans.vtab->conn_read_start == NULL)) {
        return AH_EINVAL;
    }
    return conn->_trans.vtab->conn_read_start(conn->_trans.ctx, conn);
}

ah_extern ah_err_t ah_tcp_conn_read_stop(ah_tcp_conn_t* conn)
{
    if (ah_unlikely(conn == NULL || conn->_trans.vtab == NULL || conn->_trans.vtab->conn_read_stop == NULL)) {
        return AH_EINVAL;
    }
    return conn->_trans.vtab->conn_read_stop(conn->_trans.ctx, conn);
}

ah_extern ah_err_t ah_tcp_conn_write(ah_tcp_conn_t* conn, ah_tcp_out_t* out)
{
    if (ah_unlikely(conn == NULL || conn->_trans.vtab == NULL || conn->_trans.vtab->conn_write == NULL)) {
        return AH_EINVAL;
    }
    return conn->_trans.vtab->conn_write(conn->_trans.ctx, conn, out);
}

ah_extern ah_err_t ah_tcp_conn_shutdown(ah_tcp_conn_t* conn, uint8_t flags)
{
    if (ah_unlikely(conn == NULL || conn->_trans.vtab == NULL || conn->_trans.vtab->conn_shutdown == NULL)) {
        return AH_EINVAL;
    }
    return conn->_trans.vtab->conn_shutdown(conn->_trans.ctx, conn, flags);
}

ah_extern ah_err_t ah_tcp_conn_close(ah_tcp_conn_t* conn)
{
    if (ah_unlikely(conn == NULL || conn->_trans.vtab == NULL || conn->_trans.vtab->conn_close == NULL)) {
        return AH_EINVAL;
    }
    return conn->_trans.vtab->conn_close(conn->_trans.ctx, conn);
}

ah_extern ah_err_t ah_tcp_conn_term(ah_tcp_conn_t* conn)
{
    if (ah_unlikely(conn == NULL || conn->_trans.vtab == NULL || conn->_trans.vtab->conn_term == NULL)) {
        return AH_EINVAL;
    }
    return conn->_trans.vtab->conn_term(conn->_trans.ctx, conn);
}

ah_extern int ah_tcp_conn_get_family(const ah_tcp_conn_t* conn)
{
    if (ah_unlikely(conn == NULL || conn->_trans.vtab == NULL || conn->_trans.vtab->conn_get_family == NULL)) {
        return AH_EINVAL;
    }
    return conn->_trans.vtab->conn_get_family(conn->_trans.ctx, conn);
}

ah_extern ah_err_t ah_tcp_conn_get_laddr(const ah_tcp_conn_t* conn, ah_sockaddr_t* laddr)
{
    if (ah_unlikely(conn == NULL || conn->_trans.vtab == NULL || conn->_trans.vtab->conn_get_laddr == NULL)) {
        return AH_EINVAL;
    }
    return conn->_trans.vtab->conn_get_laddr(conn->_trans.ctx, conn, laddr);
}

ah_extern ah_err_t ah_tcp_conn_get_raddr(const ah_tcp_conn_t* conn, ah_sockaddr_t* raddr)
{
    if (ah_unlikely(conn == NULL || conn->_trans.vtab == NULL || conn->_trans.vtab->conn_get_raddr == NULL)) {
        return AH_EINVAL;
    }
    return conn->_trans.vtab->conn_get_raddr(conn->_trans.ctx, conn, raddr);
}

ah_extern ah_loop_t* ah_tcp_conn_get_loop(const ah_tcp_conn_t* conn)
{
    if (ah_unlikely(conn == NULL || conn->_trans.vtab == NULL || conn->_trans.vtab->conn_get_loop == NULL)) {
        return NULL;
    }
    return conn->_trans.vtab->conn_get_loop(conn->_trans.ctx, conn);
}

ah_extern void* ah_tcp_conn_get_obs_ctx(const ah_tcp_conn_t* conn)
{
    if (ah_unlikely(conn == NULL || conn->_trans.vtab == NULL || conn->_trans.vtab->conn_get_obs_ctx == NULL)) {
        return NULL;
    }
    return conn->_trans.vtab->conn_get_obs_ctx(conn->_trans.ctx, conn);
}

ah_extern bool ah_tcp_conn_is_closed(const ah_tcp_conn_t* conn)
{
    if (ah_unlikely(conn == NULL || conn->_trans.vtab == NULL || conn->_trans.vtab->conn_is_closed == NULL)) {
        return true;
    }
    return conn->_trans.vtab->conn_is_closed(conn->_trans.ctx, conn);
}

ah_extern bool ah_tcp_conn_is_readable(const ah_tcp_conn_t* conn)
{
    if (ah_unlikely(conn == NULL || conn->_trans.vtab == NULL || conn->_trans.vtab->conn_is_readable == NULL)) {
        return false;
    }
    return conn->_trans.vtab->conn_is_readable(conn->_trans.ctx, conn);
}

ah_extern bool ah_tcp_conn_is_reading(const ah_tcp_conn_t* conn)
{
    if (ah_unlikely(conn == NULL || conn->_trans.vtab == NULL || conn->_trans.vtab->conn_is_reading == NULL)) {
        return false;
    }
    return conn->_trans.vtab->conn_is_reading(conn->_trans.ctx, conn);
}

ah_extern bool ah_tcp_conn_is_writable(const ah_tcp_conn_t* conn)
{
    if (ah_unlikely(conn == NULL || conn->_trans.vtab == NULL || conn->_trans.vtab->conn_is_writable == NULL)) {
        return false;
    }
    return conn->_trans.vtab->conn_is_writable(conn->_trans.ctx, conn);
}

ah_extern ah_err_t ah_tcp_conn_set_keepalive(ah_tcp_conn_t* conn, bool is_enabled)
{
    if (ah_unlikely(conn == NULL || conn->_trans.vtab == NULL || conn->_trans.vtab->conn_set_keepalive == NULL)) {
        return AH_EINVAL;
    }
    return conn->_trans.vtab->conn_set_keepalive(conn->_trans.ctx, conn, is_enabled);
}

ah_extern ah_err_t ah_tcp_conn_set_nodelay(ah_tcp_conn_t* conn, bool is_enabled)
{
    if (ah_unlikely(conn == NULL || conn->_trans.vtab == NULL || conn->_trans.vtab->conn_set_nodelay == NULL)) {
        return AH_EINVAL;
    }
    return conn->_trans.vtab->conn_set_nodelay(conn->_trans.ctx, conn, is_enabled);
}

ah_extern ah_err_t ah_tcp_conn_set_reuseaddr(ah_tcp_conn_t* conn, bool is_enabled)
{
    if (ah_unlikely(conn == NULL || conn->_trans.vtab == NULL || conn->_trans.vtab->conn_set_reuseaddr == NULL)) {
        return AH_EINVAL;
    }
    return conn->_trans.vtab->conn_set_reuseaddr(conn->_trans.ctx, conn, is_enabled);
}

ah_extern bool ah_tcp_conn_cbs_is_valid_for_acceptance(const ah_tcp_conn_cbs_t* cbs)
{
    return cbs != NULL
        && cbs->on_read != NULL
        && cbs->on_write != NULL
        && cbs->on_close != NULL;
}

ah_extern bool ah_tcp_conn_cbs_is_valid_for_connection(const ah_tcp_conn_cbs_t* cbs)
{
    return cbs != NULL
        && cbs->on_open != NULL
        && cbs->on_connect != NULL
        && ah_tcp_conn_cbs_is_valid_for_acceptance(cbs);
}

ah_extern ah_err_t ah_tcp_listener_init(ah_tcp_listener_t* ln, ah_loop_t* loop, ah_tcp_trans_t trans, ah_tcp_listener_obs_t obs)
{
    if (ah_unlikely(ln == NULL || trans.vtab == NULL || trans.vtab->listener_init == NULL)) {
        return AH_EINVAL;
    }

    (void) memset(ln, 0, sizeof(*ln));

    return trans.vtab->listener_init(trans.ctx, ln, loop, trans, obs);
}

ah_extern ah_err_t ah_tcp_listener_open(ah_tcp_listener_t* ln, const ah_sockaddr_t* laddr)
{
    if (ah_unlikely(ln == NULL || ln->_trans.vtab == NULL || ln->_trans.vtab->listener_open == NULL)) {
        return AH_EINVAL;
    }
    return ln->_trans.vtab->listener_open(ln->_trans.ctx, ln, laddr);
}

ah_extern ah_err_t ah_tcp_listener_listen(ah_tcp_listener_t* ln, unsigned backlog)
{
    if (ah_unlikely(ln == NULL || ln->_trans.vtab == NULL || ln->_trans.vtab->listener_listen == NULL)) {
        return AH_EINVAL;
    }
    return ln->_trans.vtab->listener_listen(ln->_trans.ctx, ln, backlog);
}

ah_extern ah_err_t ah_tcp_listener_close(ah_tcp_listener_t* ln)
{
    if (ah_unlikely(ln == NULL || ln->_trans.vtab == NULL || ln->_trans.vtab->listener_close == NULL)) {
        return AH_EINVAL;
    }
    return ln->_trans.vtab->listener_close(ln->_trans.ctx, ln);
}

ah_extern ah_err_t ah_tcp_listener_term(ah_tcp_listener_t* ln)
{
    if (ah_unlikely(ln == NULL || ln->_trans.vtab == NULL || ln->_trans.vtab->listener_term == NULL)) {
        return AH_EINVAL;
    }
    return ln->_trans.vtab->listener_term(ln->_trans.ctx, ln);
}

ah_extern int ah_tcp_listener_get_family(const ah_tcp_listener_t* ln)
{
    if (ah_unlikely(ln == NULL || ln->_trans.vtab == NULL || ln->_trans.vtab->listener_get_family == NULL)) {
        return -1;
    }
    return ln->_trans.vtab->listener_get_family(ln->_trans.ctx, ln);
}

ah_extern ah_err_t ah_tcp_listener_get_laddr(const ah_tcp_listener_t* ln, ah_sockaddr_t* laddr)
{
    if (ah_unlikely(ln == NULL || ln->_trans.vtab == NULL || ln->_trans.vtab->listener_get_laddr == NULL)) {
        return -1;
    }
    return ln->_trans.vtab->listener_get_laddr(ln->_trans.ctx, ln, laddr);
}

ah_extern ah_loop_t* ah_tcp_listener_get_loop(const ah_tcp_listener_t* ln)
{
    if (ah_unlikely(ln == NULL || ln->_trans.vtab == NULL || ln->_trans.vtab->listener_get_loop == NULL)) {
        return NULL;
    }
    return ln->_trans.vtab->listener_get_loop(ln->_trans.ctx, ln);
}

ah_extern void* ah_tcp_listener_get_obs_ctx(const ah_tcp_listener_t* ln)
{
    if (ah_unlikely(ln == NULL || ln->_trans.vtab == NULL || ln->_trans.vtab->listener_get_obs_ctx == NULL)) {
        return NULL;
    }
    return ln->_trans.vtab->listener_get_obs_ctx(ln->_trans.ctx, ln);
}

ah_extern bool ah_tcp_listener_is_closed(ah_tcp_listener_t* ln)
{
    if (ah_unlikely(ln == NULL || ln->_trans.vtab == NULL || ln->_trans.vtab->listener_is_closed == NULL)) {
        return true;
    }
    return ln->_trans.vtab->listener_is_closed(ln->_trans.ctx, ln);
}

ah_extern ah_err_t ah_tcp_listener_set_keepalive(ah_tcp_listener_t* ln, bool is_enabled)
{
    if (ah_unlikely(ln == NULL || ln->_trans.vtab == NULL || ln->_trans.vtab->listener_set_keepalive == NULL)) {
        return AH_EINVAL;
    }
    return ln->_trans.vtab->listener_set_keepalive(ln->_trans.ctx, ln, is_enabled);
}

ah_extern ah_err_t ah_tcp_listener_set_nodelay(ah_tcp_listener_t* ln, bool is_enabled)
{
    if (ah_unlikely(ln == NULL || ln->_trans.vtab == NULL || ln->_trans.vtab->listener_set_nodelay == NULL)) {
        return AH_EINVAL;
    }
    return ln->_trans.vtab->listener_set_nodelay(ln->_trans.ctx, ln, is_enabled);
}

ah_extern ah_err_t ah_tcp_listener_set_reuseaddr(ah_tcp_listener_t* ln, bool is_enabled)
{
    if (ah_unlikely(ln == NULL || ln->_trans.vtab == NULL || ln->_trans.vtab->listener_set_reuseaddr == NULL)) {
        return AH_EINVAL;
    }
    return ln->_trans.vtab->listener_set_reuseaddr(ln->_trans.ctx, ln, is_enabled);
}

ah_extern bool ah_tcp_listener_cbs_is_valid(const ah_tcp_listener_cbs_t* cbs)
{
    return cbs != NULL
        && cbs->on_open != NULL
        && cbs->on_listen != NULL
        && cbs->on_accept != NULL
        && cbs->on_close != NULL;
}
