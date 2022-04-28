// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/tcp.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"

#include <netinet/tcp.h>
#include <stddef.h>
#include <sys/socket.h>

static void s_on_accept(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe);
static void s_on_close(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe);
static void s_on_connect(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe);
static void s_on_read(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe);
static void s_on_write(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe);

static ah_err_t s_prep_read(ah_tcp_sock_t* sock, ah_tcp_read_ctx_t* ctx);

ah_extern ah_err_t ah_tcp_connect(ah_tcp_sock_t* sock, const ah_sockaddr_t* remote_addr, ah_tcp_connect_cb cb)
{
    if (sock == NULL || !ah_sockaddr_is_ip(remote_addr) || cb == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state != AH_I_TCP_STATE_OPEN) {
        return AH_ESTATE;
    }

    ah_i_loop_evt_t* evt;
    struct io_uring_sqe* sqe;

    ah_err_t err = ah_i_loop_evt_alloc_with_sqe(sock->_loop, &evt, &sqe);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_connect;
    evt->_body._as_tcp_connect._sock = sock;
    evt->_body._as_tcp_connect._cb = cb;

    io_uring_prep_connect(sqe, sock->_fd, ah_i_sockaddr_const_into_bsd(remote_addr),
        ah_i_sockaddr_get_size(remote_addr));
    io_uring_sqe_set_data(sqe, evt);

    sock->_state = AH_I_TCP_STATE_CONNECTING;

    return AH_ENONE;
}

static void s_on_connect(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(cqe != NULL);

    ah_tcp_sock_t* sock = evt->_body._as_tcp_connect._sock;
    ah_assert_if_debug(sock != NULL);

    ah_tcp_connect_cb cb = evt->_body._as_tcp_connect._cb;

    ah_err_t err;
    if (ah_unlikely(cqe->res != 0)) {
        err = -(cqe->res);
    }
    else {
        err = AH_ENONE;
    }

    if (ah_likely(err == AH_ENONE)) {
        sock->_state = AH_I_TCP_STATE_CONNECTED;
        sock->_state_read = AH_I_TCP_STATE_READ_STOPPED;
        sock->_state_write = AH_I_TCP_STATE_WRITE_STOPPED;
    }

    cb(sock, err);
}

ah_extern ah_err_t ah_tcp_listen(ah_tcp_sock_t* sock, unsigned backlog, ah_tcp_listen_ctx_t* ctx)
{
    if (sock == NULL || ctx == NULL || ctx->listen_cb == NULL || ctx->accept_cb == NULL || ctx->alloc_cb == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state != AH_I_TCP_STATE_OPEN) {
        return AH_ESTATE;
    }

    ah_err_t err;

    int backlog_int = (backlog == 0u || backlog > SOMAXCONN) ? SOMAXCONN : (int) backlog;
    if (listen(sock->_fd, backlog_int) != 0) {
        err = errno;
        ctx->listen_cb(sock, err);
        return AH_ENONE;
    }

    ah_i_loop_evt_t* evt;
    struct io_uring_sqe* sqe;

    err = ah_i_loop_evt_alloc_with_sqe(sock->_loop, &evt, &sqe);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_accept;
    evt->_body._as_tcp_listen._sock = sock;
    evt->_body._as_tcp_listen._ctx = ctx;

    ctx->_remote_addr_len = sizeof(ah_sockaddr_t);
    io_uring_prep_accept(sqe, sock->_fd, ah_i_sockaddr_into_bsd(&ctx->_remote_addr), &ctx->_remote_addr_len, 0);
    io_uring_sqe_set_data(sqe, evt);

    sock->_state = AH_I_TCP_STATE_LISTENING;
    ctx->listen_cb(sock, AH_ENONE);
    return AH_ENONE;
}

static void s_on_accept(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(cqe != NULL);

    ah_tcp_sock_t* listener = evt->_body._as_tcp_listen._sock;
    ah_assert_if_debug(listener != NULL);

    ah_tcp_listen_ctx_t* ctx = evt->_body._as_tcp_listen._ctx;
    ah_assert_if_debug(ctx != NULL);
    ah_assert_if_debug(ctx->listen_cb != NULL);
    ah_assert_if_debug(ctx->accept_cb != NULL);
    ah_assert_if_debug(ctx->alloc_cb != NULL);

    if (ah_unlikely(cqe->res < 0)) {
        ctx->accept_cb(listener, NULL, NULL, (ah_err_t) - (cqe->res));
        goto prep_another_accept;
    }

    ah_tcp_sock_t* conn = NULL;
    ctx->alloc_cb(listener, &conn);
    if (conn == NULL) {
        ctx->accept_cb(listener, NULL, NULL, AH_ENOBUFS);
        goto prep_another_accept;
    }
    *conn = (ah_tcp_sock_t) {
        ._loop = listener->_loop,
        ._fd = cqe->res,
        ._state = AH_I_TCP_STATE_CONNECTED,
        ._state_read = AH_I_TCP_STATE_READ_STOPPED,
        ._state_write = AH_I_TCP_STATE_WRITE_STOPPED,
    };

    ctx->accept_cb(listener, conn, &ctx->_remote_addr, AH_ENONE);

    ah_err_t err;
    ah_i_loop_evt_t* evt0;
    struct io_uring_sqe* sqe;

prep_another_accept:

    err = ah_i_loop_evt_alloc_with_sqe(listener->_loop, &evt0, &sqe);
    if (err != AH_ENONE) {
        ctx->listen_cb(listener, err);
        return;
    }

    evt0->_cb = s_on_accept;
    evt0->_body._as_tcp_listen._sock = listener;
    evt0->_body._as_tcp_listen._ctx = ctx;

    ctx->_remote_addr_len = sizeof(ah_sockaddr_t);
    io_uring_prep_accept(sqe, listener->_fd, ah_i_sockaddr_into_bsd(&ctx->_remote_addr), &ctx->_remote_addr_len, 0);
    io_uring_sqe_set_data(sqe, evt0);
}

ah_extern ah_err_t ah_tcp_read_start(ah_tcp_sock_t* sock, ah_tcp_read_ctx_t* ctx)
{
    if (sock == NULL || ctx == NULL || ctx->alloc_cb == NULL || ctx->read_cb == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state != AH_I_TCP_STATE_CONNECTED || sock->_state_read != AH_I_TCP_STATE_READ_STOPPED) {
        return AH_ESTATE;
    }

    ah_err_t err = s_prep_read(sock, ctx);
    if (err != AH_ENONE) {
        return err;
    }

    sock->_state_read = AH_I_TCP_STATE_READ_STARTED;

    return AH_ENONE;
}

static ah_err_t s_prep_read(ah_tcp_sock_t* sock, ah_tcp_read_ctx_t* ctx)
{
    ah_assert_if_debug(sock != NULL);
    ah_assert_if_debug(ctx != NULL);

    ah_i_loop_evt_t* evt;
    struct io_uring_sqe* sqe;

    ah_err_t err = ah_i_loop_evt_alloc_with_sqe(sock->_loop, &evt, &sqe);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_read;
    evt->_body._as_tcp_read._sock = sock;
    evt->_body._as_tcp_read._ctx = ctx;

    ctx->_bufs.items = NULL;
    ctx->_bufs.length = 0u;
    ctx->alloc_cb(sock, &ctx->_bufs, 0u);
    if (ctx->_bufs.items == NULL) {
        return AH_ENOBUFS;
    }

    struct iovec* iov;
    int iovcnt;
    err = ah_i_bufs_into_iovec(&ctx->_bufs, &iov, &iovcnt);
    if (err != AH_ENONE) {
        return err;
    }

    io_uring_prep_readv(sqe, sock->_fd, iov, iovcnt, 0);
    io_uring_sqe_set_data(sqe, evt);

    return AH_ENONE;
}

static void s_on_read(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(cqe != NULL);

    ah_tcp_sock_t* sock = evt->_body._as_tcp_read._sock;
    ah_assert_if_debug(sock != NULL);

    ah_tcp_read_ctx_t* ctx = evt->_body._as_tcp_read._ctx;
    ah_assert_if_debug(ctx != NULL);
    ah_assert_if_debug(ctx->read_cb != NULL);
    ah_assert_if_debug(ctx->alloc_cb != NULL);

    if (sock->_state != AH_I_TCP_STATE_CONNECTED || sock->_state_read != AH_I_TCP_STATE_READ_STARTED) {
        return;
    }

    ah_err_t err;

    if (ah_unlikely(cqe->res < 0)) {
        err = -(cqe->res);
        goto call_read_cb_with_err_and_return;
    }

    ctx->read_cb(sock, &ctx->_bufs, cqe->res, AH_ENONE);

    if (sock->_state_read != AH_I_TCP_STATE_READ_STARTED) {
        return;
    }

    err = s_prep_read(sock, ctx);
    if (err != AH_ENONE) {
        goto call_read_cb_with_err_and_return;
    }

    return;

call_read_cb_with_err_and_return:
    ctx->read_cb(sock, NULL, 0u, err);
}

ah_extern ah_err_t ah_tcp_read_stop(ah_tcp_sock_t* sock)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state_read != AH_I_TCP_STATE_READ_STARTED) {
        return AH_ESTATE;
    }
    sock->_state_read = AH_I_TCP_STATE_READ_STOPPED;

    return AH_ENONE;
}

ah_extern ah_err_t ah_tcp_write(ah_tcp_sock_t* sock, ah_tcp_write_ctx_t* ctx)
{
    if (sock == NULL || ctx == NULL || ctx->write_cb == NULL) {
        return AH_EINVAL;
    }
    if (ctx->bufs.items == NULL && ctx->bufs.length != 0u) {
        return AH_EINVAL;
    }
    if (sock->_state != AH_I_TCP_STATE_CONNECTED || sock->_state_write != AH_I_TCP_STATE_WRITE_STOPPED) {
        return AH_ESTATE;
    }

    ah_i_loop_evt_t* evt;
    struct io_uring_sqe* sqe;

    ah_err_t err = ah_i_loop_evt_alloc_with_sqe(sock->_loop, &evt, &sqe);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_write;
    evt->_body._as_tcp_write._sock = sock;
    evt->_body._as_tcp_write._ctx = ctx;

    struct iovec* iov;
    int iovcnt;
    err = ah_i_bufs_into_iovec(&ctx->bufs, &iov, &iovcnt);
    if (err != AH_ENONE) {
        return err;
    }

    io_uring_prep_writev(sqe, sock->_fd, iov, iovcnt, 0u);
    io_uring_sqe_set_data(sqe, evt);

    sock->_state_write = AH_I_TCP_STATE_WRITE_STARTED;

    return AH_ENONE;
}

static void s_on_write(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(cqe != NULL);

    ah_tcp_sock_t* sock = evt->_body._as_tcp_write._sock;
    ah_assert_if_debug(sock != NULL);

    ah_tcp_write_ctx_t* ctx = evt->_body._as_tcp_write._ctx;
    ah_assert_if_debug(ctx != NULL);
    ah_assert_if_debug(ctx->write_cb != NULL);
    ah_assert_if_debug(ctx->bufs.items != NULL || ctx->bufs.length == 0u);

    if (sock->_state != AH_I_TCP_STATE_CONNECTED || sock->_state_write != AH_I_TCP_STATE_WRITE_STARTED) {
        return;
    }

    ah_err_t err;

    if (ah_unlikely(cqe->res < 0)) {
        err = -(cqe->res);
    }
    else {
        err = AH_ENONE;
    }

    sock->_state_write = AH_I_TCP_STATE_WRITE_STOPPED;
    ctx->write_cb(sock, err);
}

ah_extern ah_err_t ah_tcp_close(ah_tcp_sock_t* sock, ah_tcp_close_cb cb)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if ((sock->_state & (AH_I_TCP_STATE_OPEN | AH_I_TCP_STATE_CONNECTED | AH_I_TCP_STATE_LISTENING)) == 0u) {
        return AH_ESTATE;
    }
#ifndef NDEBUG
    if (sock->_fd == 0) {
        return AH_ESTATE;
    }
#endif
    sock->_state = AH_I_TCP_STATE_CLOSED;

    ah_err_t err;

    if (cb != NULL) {
        ah_i_loop_evt_t* evt;
        struct io_uring_sqe* sqe;

        err = ah_i_loop_evt_alloc_with_sqe(sock->_loop, &evt, &sqe);
        if (err == AH_ENONE) {
            evt->_cb = s_on_close;
            evt->_body._as_tcp_close._sock = sock;
            evt->_body._as_tcp_close._cb = cb;

            io_uring_prep_close(sqe, sock->_fd);
            io_uring_sqe_set_data(sqe, evt);

            return AH_ENONE;
        }

        (void) ah_i_loop_try_set_pending_err(sock->_loop, err);
    }

    sock->_state_read = AH_I_TCP_STATE_READ_OFF;
    sock->_state_write = AH_I_TCP_STATE_WRITE_OFF;

    err = ah_i_sock_close(sock->_loop, sock->_fd);

#ifndef NDEBUG
    sock->_fd = 0;
#endif

    if (cb != NULL) {
        cb(sock, err);
    }

    return err;
}

static void s_on_close(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(cqe != NULL);

    ah_tcp_sock_t* sock = evt->_body._as_tcp_close._sock;
    ah_assert_if_debug(sock != NULL);

#ifndef NDEBUG
    sock->_fd = 0;
#endif

    ah_tcp_close_cb cb = evt->_body._as_tcp_close._cb;
    ah_assert_if_debug(cb != NULL);

    sock->_state_read = AH_I_TCP_STATE_READ_OFF;
    sock->_state_write = AH_I_TCP_STATE_WRITE_OFF;

    cb(sock, -(cqe->res));
}
