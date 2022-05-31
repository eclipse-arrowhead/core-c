// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/tcp.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"

ah_err_t ah_i_tcp_conn_open(ah_tcp_conn_t* conn, const ah_sockaddr_t* laddr);
ah_err_t ah_i_tcp_conn_connect(ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr);
ah_err_t ah_i_tcp_conn_read_start(ah_tcp_conn_t* conn);
ah_err_t ah_i_tcp_conn_read_stop(ah_tcp_conn_t* conn);
ah_err_t ah_i_tcp_conn_write(ah_tcp_conn_t* conn, ah_tcp_msg_t* msg); // May modify ah_bufs_t items in msg.
ah_err_t ah_i_tcp_conn_shutdown(ah_tcp_conn_t* conn, ah_tcp_shutdown_t flags);
ah_err_t ah_i_tcp_conn_close(ah_tcp_conn_t* conn);

ah_err_t ah_i_tcp_listener_open(ah_tcp_listener_t* ln, const ah_sockaddr_t* laddr);
ah_err_t ah_i_tcp_listener_listen(ah_tcp_listener_t* ln, unsigned backlog, const ah_tcp_conn_vtab_t* conn_vtab);
ah_err_t ah_i_tcp_listener_close(ah_tcp_listener_t* ln);

ah_extern ah_tcp_trans_t ah_tcp_trans_get_default(void)
{
    static const ah_tcp_trans_vtab_t s_vtab = {
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
        .data = NULL,
    };
}

ah_extern ah_err_t ah_tcp_conn_init(ah_tcp_conn_t* conn, ah_loop_t* loop, ah_tcp_trans_t trans, const ah_tcp_conn_vtab_t* vtab)
{
    if (conn == NULL || loop == NULL || trans.vtab == NULL || vtab == NULL) {
        return AH_EINVAL;
    }
    if (vtab->on_open == NULL || vtab->on_connect == NULL || vtab->on_close == NULL) {
        return AH_EINVAL;
    }
    if ((vtab->on_read_alloc == NULL) != (vtab->on_read_data == NULL)) {
        return AH_EINVAL;
    }

    *conn = (ah_tcp_conn_t) {
        ._loop = loop,
        ._trans = trans,
        ._vtab = vtab,
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
        return AH_EINVAL;
    }
    return conn->_trans.vtab->conn_open(conn, laddr);
}

ah_extern ah_err_t ah_tcp_conn_connect(ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_trans.vtab == NULL || conn->_trans.vtab->conn_connect == NULL) {
        return AH_EINVAL;
    }
    return conn->_trans.vtab->conn_connect(conn, raddr);
}

ah_extern ah_err_t ah_tcp_conn_read_start(ah_tcp_conn_t* conn)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_trans.vtab == NULL || conn->_trans.vtab->conn_read_start == NULL) {
        return AH_EINVAL;
    }
    return conn->_trans.vtab->conn_read_start(conn);
}

ah_extern ah_err_t ah_tcp_conn_read_stop(ah_tcp_conn_t* conn)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_trans.vtab == NULL || conn->_trans.vtab->conn_read_stop == NULL) {
        return AH_EINVAL;
    }
    return conn->_trans.vtab->conn_read_stop(conn);
}

ah_extern ah_err_t ah_tcp_conn_write(ah_tcp_conn_t* conn, ah_tcp_msg_t* msg)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_trans.vtab == NULL || conn->_trans.vtab->conn_write == NULL) {
        return AH_EINVAL;
    }
    return conn->_trans.vtab->conn_write(conn, msg);
}

ah_extern ah_err_t ah_tcp_conn_shutdown(ah_tcp_conn_t* conn, ah_tcp_shutdown_t flags)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_trans.vtab == NULL || conn->_trans.vtab->conn_shutdown == NULL) {
        return AH_EINVAL;
    }
    return conn->_trans.vtab->conn_shutdown(conn, flags);
}

ah_extern ah_err_t ah_tcp_conn_close(ah_tcp_conn_t* conn)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_trans.vtab == NULL || conn->_trans.vtab->conn_close == NULL) {
        return AH_EINVAL;
    }
    return conn->_trans.vtab->conn_close(conn);
}

ah_extern ah_loop_t* ah_tcp_conn_get_loop(const ah_tcp_conn_t* conn)
{
    ah_assert(conn != NULL);

    return conn->_loop;
}

ah_extern void* ah_tcp_conn_get_trans_data(const ah_tcp_conn_t* conn)
{
    ah_assert(conn != NULL);

    return conn->_trans.data;
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

ah_extern ah_err_t ah_tcp_listener_init(ah_tcp_listener_t* ln, ah_loop_t* loop, ah_tcp_trans_t trans, const ah_tcp_listener_vtab_t* vtab)
{
    if (ln == NULL || loop == NULL || trans.vtab == NULL || vtab == NULL) {
        return AH_EINVAL;
    }
    if (vtab->on_open == NULL || vtab->on_listen == NULL || vtab->on_close == NULL) {
        return AH_EINVAL;
    }
    if (vtab->on_conn_alloc == NULL || vtab->on_conn_accept == NULL) {
        return AH_EINVAL;
    }

    *ln = (ah_tcp_listener_t) {
        ._loop = loop,
        ._trans = trans,
        ._vtab = vtab,
        ._state = AH_I_TCP_LISTENER_STATE_CLOSED,
    };

    return AH_ENONE;
}

ah_extern ah_err_t ah_tcp_listener_open(ah_tcp_listener_t* ln, const ah_sockaddr_t* laddr)
{
    if (ln == NULL) {
        return AH_EINVAL;
    }
    if (ln->_trans.vtab == NULL || ln->_trans.vtab->listener_open == NULL) {
        return AH_EINVAL;
    }
    return ln->_trans.vtab->listener_open(ln, laddr);
}

ah_extern ah_err_t ah_tcp_listener_listen(ah_tcp_listener_t* ln, unsigned backlog, const ah_tcp_conn_vtab_t* conn_vtab)
{
    if (ln == NULL) {
        return AH_EINVAL;
    }
    if (ln->_trans.vtab == NULL || ln->_trans.vtab->listener_listen == NULL) {
        return AH_EINVAL;
    }
    return ln->_trans.vtab->listener_listen(ln, backlog, conn_vtab);
}

ah_extern ah_err_t ah_tcp_listener_close(ah_tcp_listener_t* ln)
{
    if (ln == NULL) {
        return AH_EINVAL;
    }
    if (ln->_trans.vtab == NULL || ln->_trans.vtab->listener_close == NULL) {
        return AH_EINVAL;
    }
    return ln->_trans.vtab->listener_close(ln);
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

bool ah_i_tcp_msg_queue_is_empty(struct ah_i_tcp_msg_queue* queue)
{
    ah_assert_if_debug(queue != NULL);

    return queue->_head == NULL;
}

bool ah_i_tcp_msg_queue_is_empty_then_add(struct ah_i_tcp_msg_queue* queue, ah_tcp_msg_t* msg)
{
    ah_assert_if_debug(queue != NULL);
    ah_assert_if_debug(msg != NULL);

    msg->_next = NULL;

    if (queue->_head == NULL) {
        queue->_head = msg;
        queue->_end = msg;
        return true;
    }

    queue->_end->_next = msg;
    queue->_end = msg;

    return false;
}

ah_tcp_msg_t* ah_i_tcp_msg_queue_get_head(struct ah_i_tcp_msg_queue* queue)
{
    ah_assert_if_debug(queue != NULL);
    ah_assert_if_debug(queue->_head != NULL);

    return queue->_head;
}

void ah_i_tcp_msg_queue_remove_unsafe(struct ah_i_tcp_msg_queue* queue)
{
    ah_assert_if_debug(queue != NULL);
    ah_assert_if_debug(queue->_head != NULL);
    ah_assert_if_debug(queue->_end != NULL);

    ah_tcp_msg_t* msg = queue->_head;
    queue->_head = msg->_next;

#ifndef NDEBUG

    msg->_next = NULL;

    if (queue->_head == NULL) {
        queue->_end = NULL;
    }

#endif
}
