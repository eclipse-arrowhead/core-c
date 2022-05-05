// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/tcp.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"

#include <stddef.h>
#include <sys/socket.h>

static void s_on_conn_connect(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe);
static void s_on_conn_read(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe);
static void s_on_conn_write(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe);
static void s_on_conn_close(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe);

static void s_on_listener_accept(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe);
static void s_on_listener_close(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe);

static ah_err_t s_prep_conn_read(ah_tcp_conn_t* conn);
static ah_err_t s_prep_conn_write(ah_tcp_conn_t* conn);

ah_extern ah_err_t ah_tcp_conn_connect(ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr)
{
    if (conn == NULL || raddr == NULL || !ah_sockaddr_is_ip(raddr)) {
        return AH_EINVAL;
    }
    if (conn->_state != AH_I_TCP_CONN_STATE_OPEN) {
        return AH_ESTATE;
    }

    ah_i_loop_evt_t* evt;
    struct io_uring_sqe* sqe;

    ah_err_t err = ah_i_loop_evt_alloc_with_sqe(conn->_loop, &evt, &sqe);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_conn_connect;
    evt->_subject = conn;

    io_uring_prep_connect(sqe, conn->_fd, ah_i_sockaddr_const_into_bsd(raddr), ah_i_sockaddr_get_size(raddr));
    io_uring_sqe_set_data(sqe, evt);

    conn->_state = AH_I_TCP_CONN_STATE_CONNECTING;

    return AH_ENONE;
}

static void s_on_conn_connect(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(cqe != NULL);

    ah_tcp_conn_t* conn = evt->_subject;
    ah_assert_if_debug(conn != NULL);

    ah_err_t err;

    if (ah_likely(cqe->res == 0)) {
        conn->_state = AH_I_TCP_CONN_STATE_CONNECTED;

        ah_tcp_shutdown_t shutdown_flags = 0u;

        if (conn->_vtab->on_read_data == NULL) {
            shutdown_flags |= AH_TCP_SHUTDOWN_RD;
        }
        if (conn->_vtab->on_write_done == NULL) {
            shutdown_flags |= AH_TCP_SHUTDOWN_WR;
        }
        err = ah_tcp_conn_shutdown(conn, shutdown_flags);
    }
    else {
        conn->_state = AH_I_TCP_CONN_STATE_OPEN;
        err = -(cqe->res);
    }

    conn->_vtab->on_connect(conn, err);
}

ah_extern ah_err_t ah_tcp_conn_read_start(ah_tcp_conn_t* conn)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state != AH_I_TCP_CONN_STATE_CONNECTED || (conn->_shutdown_flags & AH_TCP_SHUTDOWN_RD) != 0) {
        return AH_ESTATE;
    }

    ah_err_t err = s_prep_conn_read(conn);
    if (err != AH_ENONE) {
        return err;
    }

    conn->_state = AH_I_TCP_CONN_STATE_READING;

    return AH_ENONE;
}

static ah_err_t s_prep_conn_read(ah_tcp_conn_t* conn)
{
    ah_assert_if_debug(conn != NULL);

    ah_i_loop_evt_t* evt;
    struct io_uring_sqe* sqe;

    ah_err_t err = ah_i_loop_evt_alloc_with_sqe(conn->_loop, &evt, &sqe);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_conn_read;
    evt->_subject = conn;

    conn->_recv_buf = (ah_but_t) { 0u };
    conn->_vtab->on_read_alloc(conn, &conn->_recv_buf);

    if (conn->_state != AH_I_TCP_CONN_STATE_READING) {
        return AH_ENONE;
    }

    if (ah_buf_is_empty(&conn->_recv_buf)) {
        return AH_ENOBUFS;
    }

    io_uring_prep_recv(sqe, conn->_fd, ah_buf_get_base(&conn->_recv_buf), ah_buf_get_size(&conn->_recv_buf), 0);
    io_uring_sqe_set_data(sqe, evt);

    return AH_ENONE;
}

static void s_on_conn_read(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(cqe != NULL);

    ah_tcp_conn_t* conn = evt->_subject;
    ah_assert_if_debug(conn != NULL);

    if (conn->_state != AH_I_TCP_CONN_STATE_READING) {
        return;
    }

    ah_err_t err;

    if (ah_unlikely(cqe->res < 0)) {
        err = -(cqe->res);
        goto report_err;
    }

    conn->_vtab->on_read_data(conn, &conn->_recv_buf, cqe->res);
#ifndef NDEBUG
    conn->_recv_buf = (ah_but_t) { 0u };
#endif

    if (conn->_state != AH_I_TCP_CONN_STATE_READING) {
        return;
    }

    err = s_prep_conn_read(conn);
    if (err != AH_ENONE) {
        goto report_err;
    }

    return;

report_err:
    conn->_vtab->on_read_err(conn, err);
}

ah_extern ah_err_t ah_tcp_conn_read_stop(ah_tcp_conn_t* conn)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state != AH_I_TCP_CONN_STATE_READING) {
        return conn->_state == AH_I_TCP_CONN_STATE_CONNECTED ? AH_ESTATE : AH_ENONE;
    }

    conn->_state = AH_I_TCP_CONN_STATE_CONNECTED;

    return AH_ENONE;
}

ah_extern ah_err_t ah_tcp_conn_write(ah_tcp_conn_t* conn, ah_tcp_omsg_t* omsg)
{
    if (conn == NULL || omsg == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state < AH_I_TCP_CONN_STATE_CONNECTED || (conn->_shutdown_flags & AH_TCP_SHUTDOWN_WR) != 0) {
        return AH_ESTATE;
    }

    if (conn->_write_queue_head != NULL) {
        conn->_write_queue_end->_next = omsg;
        conn->_write_queue_end = omsg;
        return AH_ENONE;
    }

    conn->_write_queue_head = omsg;
    conn->_write_queue_end = omsg;

    return s_prep_conn_write(conn);
}

static ah_err_t s_prep_conn_write(ah_tcp_conn_t* conn)
{
    ah_i_loop_evt_t* evt;
    struct io_uring_sqe* sqe;

    ah_err_t err = ah_i_loop_evt_alloc_with_sqe(conn->_loop, &evt, &sqe);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_conn_write;
    evt->_subject = conn;

    ah_tcp_omsg_t* omsg = conn->_write_queue_head;

    io_uring_prep_writev(sqe, conn->_fd, omsg->_iov, omsg->_iovcnt, 0u);
    io_uring_sqe_set_data(sqe, evt);

    return AH_ENONE;
}

static void s_on_conn_write(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(cqe != NULL);

    ah_tcp_conn_t* conn = evt->_subject;
    ah_assert_if_debug(conn != NULL);
    ah_assert_if_debug(conn->_write_queue_head != NULL);

    if (conn->_state < AH_I_TCP_CONN_STATE_CONNECTED) {
        return;
    }

    ah_err_t err;

    if (ah_unlikely(cqe->res < 0)) {
        err = -(cqe->res);
    }
    else {
        err = AH_ENONE;
    }

report_err_and_prep_next:
    conn->_write_queue_head = conn->_write_queue_head->_next;
    conn->_vtab->on_write_done(conn, err);

    if (conn->_state < AH_I_TCP_CONN_STATE_CONNECTED) {
        return;
    }
    if (conn->_write_queue_head == NULL) {
        return;
    }

    err = s_prep_conn_write(conn);
    if (err != AH_ENONE) {
        goto report_err_and_prep_next;
    }
}

ah_extern ah_err_t ah_tcp_conn_close(ah_tcp_conn_t* conn)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state == AH_I_TCP_CONN_STATE_CLOSED) {
        return AH_ESTATE;
    }
#ifndef NDEBUG
    if (conn->_fd == 0) {
        return AH_ESTATE;
    }
#endif
    conn->_state = AH_I_TCP_CONN_STATE_CLOSED;

    ah_err_t err;

    ah_i_loop_evt_t* evt;
    struct io_uring_sqe* sqe;

    err = ah_i_loop_evt_alloc_with_sqe(conn->_loop, &evt, &sqe);

    if (err == AH_ENONE) {
        evt->_cb = s_on_conn_close;
        evt->_subject = conn;

        io_uring_prep_close(sqe, conn->_fd);
        io_uring_sqe_set_data(sqe, evt);

        return AH_ENONE;
    }

    // These events are safe to ignore. No other errors should be possible.
    ah_assert_if_debug(err == AH_ENOMEM || err == AH_ENOBUFS || err == AH_ESTATE);

    err = ah_i_sock_close(conn->_fd);
    if (err == AH_EINTR) {
        if (ah_i_loop_try_set_pending_err(conn->_loop, AH_EINTR)) {
            err = AH_ENONE;
        }
    }

#ifndef NDEBUG
    conn->_fd = 0;
#endif

    conn->_shutdown_flags = AH_TCP_SHUTDOWN_RDWR;
    conn->_vtab->on_close(conn, err);

    return AH_ENONE;
}

static void s_on_conn_close(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(cqe != NULL);

    ah_tcp_conn_t* conn = evt->_subject;
    ah_assert_if_debug(conn != NULL);

#ifndef NDEBUG
    conn->_fd = 0;
#endif

    conn->_shutdown_flags = AH_TCP_SHUTDOWN_RDWR;
    conn->_vtab->on_close(conn, -(cqe->res));
}

ah_extern ah_err_t ah_tcp_listener_listen(ah_tcp_listener_t* ln, unsigned backlog, const ah_tcp_conn_vtab_t* conn_vtab)
{
    if (ln == NULL || conn_vtab == NULL) {
        return AH_EINVAL;
    }
    if (conn_vtab->on_close == NULL) {
        return AH_EINVAL;
    }
    if (conn_vtab->on_read_alloc == NULL || conn_vtab->on_read_data == NULL || conn_vtab->on_read_err) {
        return AH_EINVAL;
    }
    if (conn_vtab->on_write_done == NULL) {
        return AH_EINVAL;
    }
    if (ln->_state != AH_I_TCP_LISTENER_STATE_OPEN) {
        return AH_ESTATE;
    }

    ah_err_t err;

    int backlog_int = (backlog == 0u ? 16 : backlog <= SOMAXCONN ? (int) backlog : SOMAXCONN);
    if (listen(ln->_fd, backlog_int) != 0) {
        err = errno;
        ln->_vtab->on_listen(ln, err);
        return AH_ENONE;
    }

    ah_i_loop_evt_t* evt;
    struct io_uring_sqe* sqe;

    err = ah_i_loop_evt_alloc_with_sqe(ln->_loop, &evt, &sqe);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_listener_accept;
    evt->_subject = ln;

    ln->_raddr_len = sizeof(ah_sockaddr_t);
    io_uring_prep_accept(sqe, ln->_fd, ah_i_sockaddr_into_bsd(&ln->_raddr), &ln->_raddr_len, 0);
    io_uring_sqe_set_data(sqe, evt);

    ln->_conn_vtab = conn_vtab;
    ln->_state = AH_I_TCP_LISTENER_STATE_LISTENING;
    ln->_vtab->on_listen(ln, AH_ENONE);

    return AH_ENONE;
}

static void s_on_listener_accept(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(cqe != NULL);

    ah_tcp_listener_t* ln = evt->_subject;
    ah_assert_if_debug(ln != NULL);

    if (ah_unlikely(cqe->res < 0)) {
        ln->_vtab->on_conn_err(ln, -cqe->res);
        goto prep_another_accept;
    }

    ah_tcp_conn_t* conn = NULL;
    ln->_vtab->on_conn_alloc(ln, &conn);
    if (conn == NULL) {
        ln->_vtab->on_conn_err(ln, AH_ENOBUFS);
        goto prep_another_accept;
    }

    *conn = (ah_tcp_conn_t) {
        ._loop = ln->_loop,
        ._vtab = ln->_conn_vtab,
        ._state = AH_I_TCP_CONN_STATE_CONNECTED,
        ._fd = cqe->res,
    };

    ln->_vtab->on_conn_accept(ln, conn, &ln->_raddr, AH_ENONE);

    ah_err_t err;
    ah_i_loop_evt_t* evt0;
    struct io_uring_sqe* sqe;

prep_another_accept:

    err = ah_i_loop_evt_alloc_with_sqe(ln->_loop, &evt0, &sqe);
    if (err != AH_ENONE) {
        ah_i_tcp_listener_force_close_with_err(ln, err);
        return;
    }

    evt0->_cb = s_on_listener_accept;
    evt0->_subject = ln;

    ln->_raddr_len = sizeof(ah_sockaddr_t);
    io_uring_prep_accept(sqe, ln->_fd, ah_i_sockaddr_into_bsd(&ln->_raddr), &ln->_raddr_len, 0);
    io_uring_sqe_set_data(sqe, evt0);
}

ah_extern ah_err_t ah_tcp_listener_close(ah_tcp_listener_t* ln)
{
    if (ln == NULL) {
        return AH_EINVAL;
    }
    if (ln->_state == AH_I_TCP_LISTENER_STATE_CLOSED) {
        return AH_ESTATE;
    }
#ifndef NDEBUG
    if (ln->_fd == 0) {
        return AH_ESTATE;
    }
#endif
    ln->_state = AH_I_TCP_LISTENER_STATE_CLOSED;

    ah_err_t err;

    ah_i_loop_evt_t* evt;
    struct io_uring_sqe* sqe;

    err = ah_i_loop_evt_alloc_with_sqe(ln->_loop, &evt, &sqe);

    if (err == AH_ENONE) {
        evt->_cb = s_on_listener_close;
        evt->_subject = ln;

        io_uring_prep_close(sqe, ln->_fd);
        io_uring_sqe_set_data(sqe, evt);

        return AH_ENONE;
    }

    // These events are safe to ignore. No other errors should be possible.
    ah_assert_if_debug(err == AH_ENOMEM || err == AH_ENOBUFS || err == AH_ESTATE);

    err = ah_i_sock_close(ln->_fd);
    if (err == AH_EINTR) {
        if (ah_i_loop_try_set_pending_err(ln->_loop, AH_EINTR)) {
            err = AH_ENONE;
        }
    }

#ifndef NDEBUG
    ln->_fd = 0;
#endif

    ln->_vtab->on_close(ln, err);

    return AH_ENONE;
}

static void s_on_listener_close(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(cqe != NULL);

    ah_tcp_listener_t* ln = evt->_subject;
    ah_assert_if_debug(ln != NULL);

#ifndef NDEBUG
    ln->_fd = 0;
#endif

    ln->_vtab->on_close(ln, -(cqe->res));
}
