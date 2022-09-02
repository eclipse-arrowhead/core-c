// SPDX-License-Identifier: EPL-2.0

#include "ah/tcp.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"

#include <stddef.h>
#include <sys/socket.h>

static void s_conn_on_connect(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe);
static void s_conn_on_read(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe);
static void s_conn_on_write(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe);
static void s_conn_on_close(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe);

static void s_conn_close(ah_tcp_conn_t* conn, ah_err_t err);
static ah_err_t s_conn_read_prep(ah_tcp_conn_t* conn);
static void s_conn_read_stop(ah_tcp_conn_t* conn);

static void s_listener_on_accept(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe);
static void s_listener_on_close(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe);

ah_err_t ah_i_tcp_trans_default_conn_connect(void* ctx, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr)
{
    (void) ctx;

    if (conn == NULL || raddr == NULL) {
        return AH_EINVAL;
    }
    if (!ah_sockaddr_is_ip(raddr)) {
        return AH_EAFNOSUPPORT;
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

    evt->_cb = s_conn_on_connect;
    evt->_subject = conn;

    io_uring_prep_connect(sqe, conn->_fd, ah_i_sockaddr_const_into_bsd(raddr), ah_i_sockaddr_get_size(raddr));
    io_uring_sqe_set_data(sqe, evt);

    conn->_state = AH_I_TCP_CONN_STATE_CONNECTING;

    return AH_ENONE;
}

static void s_conn_on_connect(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(cqe != NULL);

    ah_tcp_conn_t* conn = evt->_subject;
    ah_assert_if_debug(conn != NULL);

    ah_err_t err;

    if (ah_likely(cqe->res == 0)) {
        conn->_state = AH_I_TCP_CONN_STATE_CONNECTED;
        err = AH_ENONE;
    }
    else {
        conn->_state = AH_I_TCP_CONN_STATE_OPEN;
        err = -(cqe->res);
    }

    conn->_obs.cbs->on_connect(conn->_obs.ctx, conn, err);
}

ah_err_t ah_i_tcp_trans_default_conn_read_start(void* ctx, ah_tcp_conn_t* conn)
{
    (void) ctx;

    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state != AH_I_TCP_CONN_STATE_CONNECTED || (conn->_shutdown_flags & AH_TCP_SHUTDOWN_RD) != 0) {
        return AH_ESTATE;
    }

    ah_err_t err;

    err = ah_tcp_in_alloc_for(&conn->_in);
    if (err != AH_ENONE) {
        return err;
    }

    conn->_state = AH_I_TCP_CONN_STATE_READING;

    err = s_conn_read_prep(conn);
    if (err != AH_ENONE) {
        ah_tcp_in_free(conn->_in);
        return err;
    }

    return AH_ENONE;
}

static ah_err_t s_conn_read_prep(ah_tcp_conn_t* conn)
{
    ah_assert_if_debug(conn != NULL);
    ah_assert_if_debug(conn->_state == AH_I_TCP_CONN_STATE_READING);

    ah_err_t err;

    ah_buf_t dst = ah_rw_get_writable_as_buf(&conn->_in->rw);
    if (ah_buf_is_empty(&dst)) {
        return AH_EOVERFLOW;
    }

    ah_i_loop_evt_t* evt;
    struct io_uring_sqe* sqe;

    err = ah_i_loop_evt_alloc_with_sqe(conn->_loop, &evt, &sqe);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_conn_on_read;
    evt->_subject = conn;

    conn->_read_evt = evt;

    io_uring_prep_recv(sqe, conn->_fd, dst.base, dst.size, 0);
    io_uring_sqe_set_data(sqe, evt);

    return AH_ENONE;
}

static void s_conn_on_read(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(cqe != NULL);

    ah_tcp_conn_t* conn = evt->_subject;
    ah_assert_if_debug(conn != NULL);

    conn->_read_evt = NULL;

    if (conn->_state != AH_I_TCP_CONN_STATE_READING) {
        return;
    }

    ah_err_t err;

    if (ah_unlikely(cqe->res < 0)) {
        err = -(cqe->res);
        goto report_err;
    }

    if (ah_unlikely(cqe->res == 0)) {
        conn->_shutdown_flags |= AH_TCP_SHUTDOWN_RD;
        err = AH_EEOF;
        goto report_err;
    }

    if (ah_unlikely(AH_PSIZE < (size_t) cqe->res)) {
        err = AH_EDOM;
        goto report_err;
    }

    conn->_in->rw.w = &conn->_in->rw.w[(size_t) cqe->res];
    ah_assert_if_debug(conn->_in->rw.w <= conn->_in->rw.e);

    conn->_obs.cbs->on_read(conn->_obs.ctx, conn, conn->_in, AH_ENONE);

    if (conn->_state != AH_I_TCP_CONN_STATE_READING) {
        return;
    }

    if (!ah_rw_is_readable(&conn->_in->rw)) {
        ah_tcp_in_reset(conn->_in);
    }

    err = s_conn_read_prep(conn);
    if (err != AH_ENONE) {
        conn->_state = AH_I_TCP_CONN_STATE_CONNECTED;
        goto report_err;
    }

    return;

report_err:
    conn->_obs.cbs->on_read(conn->_obs.ctx, conn, NULL, err);
}

ah_err_t ah_i_tcp_trans_default_conn_read_stop(void* ctx, ah_tcp_conn_t* conn)
{
    (void) ctx;

    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state != AH_I_TCP_CONN_STATE_READING) {
        return AH_ESTATE;
    }
    conn->_state = AH_I_TCP_CONN_STATE_CONNECTED;

    s_conn_read_stop(conn);

    return AH_ENONE;
}

static void s_conn_read_stop(ah_tcp_conn_t* conn)
{
    ah_assert_if_debug(conn != NULL);

    if (conn->_in != NULL) {
        ah_tcp_in_free(conn->_in);
    }

    if (conn->_read_evt != NULL) {
        struct io_uring_sqe* sqe;
        if (ah_i_loop_alloc_sqe(conn->_loop, &sqe) == AH_ENONE) {
            io_uring_prep_cancel(sqe, conn->_read_evt, 0);
            conn->_read_evt = NULL;
        }
    }
}

ah_err_t ah_i_tcp_trans_default_conn_write(void* ctx, ah_tcp_conn_t* conn, ah_tcp_out_t* out)
{
    (void) ctx;

    if (conn == NULL || out == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state < AH_I_TCP_CONN_STATE_CONNECTED || (conn->_shutdown_flags & AH_TCP_SHUTDOWN_WR) != 0) {
        return AH_ESTATE;
    }

    ah_i_loop_evt_t* evt;
    struct io_uring_sqe* sqe;

    ah_err_t err = ah_i_loop_evt_alloc_with_sqe(conn->_loop, &evt, &sqe);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_conn_on_write;
    evt->_subject = out;

    out->_conn = conn;

    io_uring_prep_send(sqe, conn->_fd, out->buf.base, out->buf.size, 0);
    io_uring_sqe_set_data(sqe, evt);

    return AH_ENONE;
}

static void s_conn_on_write(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(cqe != NULL);

    ah_tcp_out_t* out = evt->_subject;
    ah_assert_if_debug(out != NULL);

    ah_tcp_conn_t* conn = out->_conn;
    ah_assert_if_debug(conn != NULL);

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

    conn->_obs.cbs->on_write(conn->_obs.ctx, conn, out, err);
}

ah_err_t ah_i_tcp_trans_default_conn_close(void* ctx, ah_tcp_conn_t* conn)
{
    (void) ctx;

    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state <= AH_I_TCP_CONN_STATE_CLOSED) {
        return AH_ESTATE;
    }
#ifndef NDEBUG
    if (conn->_fd == 0) {
        return AH_ESTATE;
    }
#endif
    conn->_state = AH_I_TCP_CONN_STATE_CLOSING;

    ah_err_t err;

    ah_i_loop_evt_t* evt;
    struct io_uring_sqe* sqe;

    err = ah_i_loop_evt_alloc_with_sqe(conn->_loop, &evt, &sqe);

    if (err == AH_ENONE) {
        evt->_cb = s_conn_on_close;
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

    s_conn_close(conn, err);

    return AH_ENONE;
}

static void s_conn_close(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_assert_if_debug(conn != NULL);

    conn->_shutdown_flags = AH_TCP_SHUTDOWN_RDWR;
    conn->_state = AH_I_TCP_CONN_STATE_CLOSED;
#ifndef NDEBUG
    conn->_fd = 0;
#endif

    s_conn_read_stop(conn);

    conn->_obs.cbs->on_close(conn->_obs.ctx, conn, err);
}

static void s_conn_on_close(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(cqe != NULL);

    s_conn_close(evt->_subject, -(cqe->res));
}

ah_err_t ah_i_tcp_trans_default_listener_listen(void* ctx, ah_tcp_listener_t* ln, unsigned backlog)
{
    (void) ctx;

    if (ln == NULL) {
        return AH_EINVAL;
    }
    if (ln->_state != AH_I_TCP_LISTENER_STATE_OPEN) {
        return AH_ESTATE;
    }

    ah_err_t err;

    int backlog_int = (backlog == 0u ? 16 : backlog <= SOMAXCONN ? (int) backlog
                                                                 : SOMAXCONN);
    if (listen(ln->_fd, backlog_int) != 0) {
        err = errno;
        ln->_obs.cbs->on_listen(ln->_obs.ctx, ln, err);
        return AH_ENONE;
    }

    ah_i_loop_evt_t* evt;
    struct io_uring_sqe* sqe;

    err = ah_i_loop_evt_alloc_with_sqe(ln->_loop, &evt, &sqe);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_listener_on_accept;
    evt->_subject = ln;

    ln->_raddr_len = sizeof(ah_sockaddr_t);
    io_uring_prep_accept(sqe, ln->_fd, ah_i_sockaddr_into_bsd(&ln->_raddr), &ln->_raddr_len, 0);
    io_uring_sqe_set_data(sqe, evt);

    ln->_state = AH_I_TCP_LISTENER_STATE_LISTENING;

    ln->_obs.cbs->on_listen(ln->_obs.ctx, ln, AH_ENONE);

    return AH_ENONE;
}

static void s_listener_on_accept(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(cqe != NULL);

    ah_tcp_listener_t* ln = evt->_subject;
    ah_assert_if_debug(ln != NULL);

    ah_err_t err;

    if (ah_unlikely(cqe->res < 0)) {
        err = -(cqe->res);
        goto handle_err;
    }

    ah_tcp_conn_t* conn = ah_i_slab_alloc(&ln->_conn_slab);
    if (conn == NULL) {
        err = AH_ENOMEM;
        goto handle_err;
    }

    ah_tcp_trans_t trans;
    err = ln->_trans.vtab->trans_prepare(ln->_trans.ctx, &trans);
    if (err != AH_ENONE) {
        ah_i_slab_free(&ln->_conn_slab, conn);
        goto handle_err;
    }

    *conn = (ah_tcp_conn_t) {
        ._loop = ln->_loop,
        ._trans = trans,
        ._owning_slab = &ln->_conn_slab,
        ._sock_family = ln->_sock_family,
        ._state = AH_I_TCP_CONN_STATE_CONNECTED,
        ._fd = cqe->res,
    };

    ln->_obs.cbs->on_accept(ln->_obs.ctx, ln, conn, &conn->_obs, &ln->_raddr, AH_ENONE);

    if (ah_tcp_listener_is_closed(ln)) {
        return;
    }

    if (!ah_tcp_conn_cbs_is_valid_for_acceptance(conn->_obs.cbs)) {
        err = AH_ESTATE;
        goto handle_err;
    }

    ah_i_loop_evt_t* evt0;
    struct io_uring_sqe* sqe;

    err = ah_i_loop_evt_alloc_with_sqe(ln->_loop, &evt0, &sqe);
    if (err != AH_ENONE) {
        goto handle_err;
    }

    evt0->_cb = s_listener_on_accept;
    evt0->_subject = ln;

    ln->_raddr_len = sizeof(ah_sockaddr_t);
    io_uring_prep_accept(sqe, ln->_fd, ah_i_sockaddr_into_bsd(&ln->_raddr), &ln->_raddr_len, 0);
    io_uring_sqe_set_data(sqe, evt0);

    return;

handle_err:
    ln->_obs.cbs->on_accept(ln->_obs.ctx, ln, NULL, NULL, NULL, err);
}

ah_err_t ah_i_tcp_trans_default_listener_close(void* ctx, ah_tcp_listener_t* ln)
{
    (void) ctx;

    if (ln == NULL) {
        return AH_EINVAL;
    }
    if (ln->_state <= AH_I_TCP_LISTENER_STATE_CLOSED) {
        return AH_ESTATE;
    }
#ifndef NDEBUG
    if (ln->_fd == 0) {
        return AH_ESTATE;
    }
#endif
    ln->_state = AH_I_TCP_LISTENER_STATE_CLOSING;

    ah_err_t err;

    ah_i_loop_evt_t* evt;
    struct io_uring_sqe* sqe;

    err = ah_i_loop_evt_alloc_with_sqe(ln->_loop, &evt, &sqe);

    if (err == AH_ENONE) {
        evt->_cb = s_listener_on_close;
        evt->_subject = ln;

        io_uring_prep_close(sqe, ln->_fd);
        io_uring_sqe_set_data(sqe, evt);

        return AH_ENONE;
    }

    // These events are safe to ignore. No other errors should be possible.
    ah_assert_if_debug(err == AH_ENOMEM || err == AH_ENOBUFS || err == AH_ECANCELED);

    err = ah_i_sock_close(ln->_fd);
    if (err == AH_EINTR) {
        if (ah_i_loop_try_set_pending_err(ln->_loop, AH_EINTR)) {
            err = AH_ENONE;
        }
    }

    ln->_state = AH_I_TCP_LISTENER_STATE_CLOSED;
#ifndef NDEBUG
    ln->_fd = 0;
#endif

    ln->_obs.cbs->on_close(ln->_obs.ctx, ln, err);

    return AH_ENONE;
}

static void s_listener_on_close(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(cqe != NULL);

    ah_tcp_listener_t* ln = evt->_subject;
    ah_assert_if_debug(ln != NULL);

    ln->_state = AH_I_TCP_LISTENER_STATE_CLOSED;
#ifndef NDEBUG
    ln->_fd = 0;
#endif

    ln->_obs.cbs->on_close(ln->_obs.ctx, ln, -(cqe->res));
}
