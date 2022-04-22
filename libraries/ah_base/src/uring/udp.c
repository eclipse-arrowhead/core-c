// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/udp.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"

static void s_on_close(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe);
static void s_on_recv(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe);
static void s_on_send(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe);

static ah_err_t s_prep_recv(ah_udp_sock_t* sock, ah_udp_recv_ctx_t* ctx);

ah_extern ah_err_t ah_udp_recv_start(ah_udp_sock_t* sock, ah_udp_recv_ctx_t* ctx)
{
    if (sock == NULL || ctx == NULL || ctx->alloc_cb == NULL || ctx->recv_cb == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open || sock->_is_receiving) {
        return AH_ESTATE;
    }

    ah_err_t err = s_prep_recv(sock, ctx);
    if (err != AH_ENONE) {
        return err;
    }

    sock->_is_receiving = true;

    return AH_ENONE;
}

static ah_err_t s_prep_recv(ah_udp_sock_t* sock, ah_udp_recv_ctx_t* ctx)
{
    ah_assert_if_debug(sock != NULL);
    ah_assert_if_debug(ctx != NULL);

    ah_i_loop_evt_t* evt;
    struct io_uring_sqe* sqe;

    ah_err_t err = ah_i_loop_evt_alloc_with_sqe(sock->_loop, &evt, &sqe);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_recv;
    evt->_body._as_udp_recv._sock = sock;
    evt->_body._as_udp_recv._ctx = ctx;

    struct ah_bufvec bufvec = { .items = NULL, .length = 0u };
    ctx->alloc_cb(sock, &bufvec, 0u);
    if (bufvec.items == NULL) {
        return AH_ENOBUFS;
    }

    struct iovec* iov;
    int iovcnt;
    err = ah_i_bufvec_into_iovec(&bufvec, &iov, &iovcnt);
    if (ah_unlikely(err != AH_ENONE)) {
        return err;
    }

    ctx->_msghdr = (struct msghdr) {
        .msg_name = ah_i_sockaddr_into_bsd(&ctx->_remote_addr),
        .msg_namelen = sizeof(ah_sockaddr_t),
        .msg_iov = iov,
        .msg_iovlen = iovcnt,
    };

    io_uring_prep_recvmsg(sqe, sock->_fd, &ctx->_msghdr, 0);
    io_uring_sqe_set_data(sqe, evt);

    return AH_ENONE;
}

static void s_on_recv(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(cqe != NULL);

    ah_udp_sock_t* sock = evt->_body._as_udp_recv._sock;
    ah_assert_if_debug(sock != NULL);

    ah_udp_recv_ctx_t* ctx = evt->_body._as_udp_recv._ctx;
    ah_assert_if_debug(ctx != NULL);
    ah_assert_if_debug(ctx->recv_cb != NULL);
    ah_assert_if_debug(ctx->alloc_cb != NULL);

    if (!sock->_is_open || !sock->_is_receiving) {
        return;
    }

    ah_err_t err;

    if (ah_unlikely(cqe->res < 0)) {
        err = -(cqe->res);
        goto call_recv_cb_with_err_and_return;
    }

    struct ah_bufvec bufvec;
    err = ah_i_bufvec_from_iovec(&bufvec, ctx->_msghdr.msg_iov, 0);
    if (err != AH_ENONE) {
        goto call_recv_cb_with_err_and_return;
    }
    bufvec.length = ctx->_msghdr.msg_iovlen;

    ctx->recv_cb(sock, &ctx->_remote_addr, &bufvec, cqe->res, AH_ENONE);

    if (!sock->_is_open) {
        return;
    }

    err = s_prep_recv(sock, ctx);
    if (err != AH_ENONE) {
        goto call_recv_cb_with_err_and_return;
    }

    return;

call_recv_cb_with_err_and_return:
    ctx->recv_cb(sock, NULL, NULL, 0u, err);
}

ah_extern ah_err_t ah_udp_recv_stop(ah_udp_sock_t* sock)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_receiving) {
        return AH_ESTATE;
    }
    sock->_is_receiving = false;

    return AH_ENONE;
}

ah_extern ah_err_t ah_udp_send(ah_udp_sock_t* sock, ah_udp_send_ctx_t* ctx)
{
    if (sock == NULL || ctx == NULL || ctx->send_cb == NULL) {
        return AH_EINVAL;
    }
    if (ctx->bufvec.items == NULL && ctx->bufvec.length != 0u) {
        return AH_EINVAL;
    }
    if (!sock->_is_open) {
        return AH_ESTATE;
    }

    ah_i_loop_evt_t* evt;
    struct io_uring_sqe* sqe;

    ah_err_t err = ah_i_loop_evt_alloc_with_sqe(sock->_loop, &evt, &sqe);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_send;
    evt->_body._as_udp_send._sock = sock;
    evt->_body._as_udp_send._ctx = ctx;

    struct iovec* iov;
    int iovcnt;
    err = ah_i_bufvec_into_iovec(&ctx->bufvec, &iov, &iovcnt);
    if (err != AH_ENONE) {
        return err;
    }

    ctx->_msghdr = (struct msghdr) {
        .msg_name = ah_i_sockaddr_into_bsd(&ctx->remote_addr),
        .msg_namelen = ah_i_sockaddr_get_size(&ctx->remote_addr),
        .msg_iov = iov,
        .msg_iovlen = iovcnt,
    };

    io_uring_prep_sendmsg(sqe, sock->_fd, &ctx->_msghdr, 0u);
    io_uring_sqe_set_data(sqe, evt);

    return AH_ENONE;
}

static void s_on_send(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(cqe != NULL);

    ah_udp_sock_t* sock = evt->_body._as_udp_send._sock;
    ah_assert_if_debug(sock != NULL);

    ah_udp_send_ctx_t* ctx = evt->_body._as_udp_send._ctx;
    ah_assert_if_debug(ctx != NULL);
    ah_assert_if_debug(ctx->send_cb != NULL);
    ah_assert_if_debug(ctx->bufvec.items != NULL || ctx->bufvec.length == 0u);

    ah_err_t err;

    if (ah_unlikely(cqe->res < 0)) {
        err = -(cqe->res);
        goto call_send_cb_with_sock_and_err;
    }

    err = AH_ENONE;

call_send_cb_with_sock_and_err:
    ctx->send_cb(sock, err);
}

ah_extern ah_err_t ah_udp_close(ah_udp_sock_t* sock, ah_udp_close_cb cb)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open) {
        return AH_ESTATE;
    }
#ifndef NDEBUG
    if (sock->_fd == 0) {
        return AH_ESTATE;
    }
#endif
    sock->_is_open = false;

    ah_err_t err;

    if (cb != NULL) {
        ah_i_loop_evt_t* evt;
        struct io_uring_sqe* sqe;

        err = ah_i_loop_evt_alloc_with_sqe(sock->_loop, &evt, &sqe);
        if (err == AH_ENONE) {
            evt->_cb = s_on_close;
            evt->_body._as_udp_close._sock = sock;
            evt->_body._as_udp_close._cb = cb;

            io_uring_prep_close(sqe, sock->_fd);
            io_uring_sqe_set_data(sqe, evt);

            return AH_ENONE;
        }

        (void) ah_i_loop_try_set_pending_err(sock->_loop, err);
    }

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

    ah_udp_sock_t* sock = evt->_body._as_udp_close._sock;
    ah_assert_if_debug(sock != NULL);

#ifndef NDEBUG
    sock->_fd = 0;
#endif

    ah_udp_close_cb cb = evt->_body._as_udp_close._cb;
    ah_assert_if_debug(cb != NULL);

    cb(sock, -(cqe->res));
}
