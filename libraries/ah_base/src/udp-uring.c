// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/udp.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"
#include "udp-in.h"

static void s_on_sock_close(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe);
static void s_on_sock_recv(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe);
static void s_on_sock_send(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe);

static void s_sock_close(ah_udp_sock_t* sock, ah_err_t err);
static void s_sock_recv_stop(ah_udp_sock_t* sock);
static ah_err_t s_sock_recv_prep(ah_udp_sock_t* sock);

ah_err_t ah_i_udp_sock_recv_start(void* ctx, ah_udp_sock_t* sock)
{
    (void) ctx;

    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state != AH_I_UDP_SOCK_STATE_OPEN || sock->_cbs->on_recv == NULL) {
        return AH_ESTATE;
    }

    ah_err_t err;

    err = ah_i_udp_in_alloc_for(&sock->_in);
    if (err != AH_ENONE) {
        return err;
    }

    sock->_in->raddr = &sock->_recv_addr;

    sock->_recv_msghdr = (struct msghdr) {
        .msg_name = ah_i_sockaddr_into_bsd(&sock->_recv_addr),
        .msg_namelen = sizeof(ah_sockaddr_t),
        .msg_iov = ah_i_buf_into_iovec(&sock->_in->buf),
        .msg_iovlen = 1u,
    };

    err = s_sock_recv_prep(sock);
    if (err != AH_ENONE) {
        ah_i_udp_in_free(sock->_in);
        return err;
    }

    sock->_state = AH_I_UDP_SOCK_STATE_RECEIVING;

    return AH_ENONE;
}

static ah_err_t s_sock_recv_prep(ah_udp_sock_t* sock)
{
    ah_assert_if_debug(sock != NULL);

    if (sock->_in->nrecv >= sock->_in->buf._size) {
        sock->_cbs->on_recv(sock, NULL, AH_EOVERFLOW);
        return AH_ENONE;
    }

    ah_i_loop_evt_t* evt;
    struct io_uring_sqe* sqe;

    ah_err_t err = ah_i_loop_evt_alloc_with_sqe(sock->_loop, &evt, &sqe);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_sock_recv;
    evt->_subject = sock;

    sock->_recv_evt = evt;

    sock->_in->buf._base += sock->_in->nrecv;
    sock->_in->buf._size -= sock->_in->nrecv;

    io_uring_prep_recvmsg(sqe, sock->_fd, &sock->_recv_msghdr, 0);
    io_uring_sqe_set_data(sqe, evt);

    return AH_ENONE;
}

static void s_on_sock_recv(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(cqe != NULL);

    ah_udp_sock_t* sock = evt->_subject;
    ah_assert_if_debug(sock != NULL);

    sock->_recv_evt = NULL;

    if (sock->_state != AH_I_UDP_SOCK_STATE_RECEIVING) {
        return;
    }

    ah_err_t err;

    if (ah_unlikely(cqe->res < 0)) {
        err = -(cqe->res);
        goto report_err;
    }

    if (ah_unlikely(AH_PSIZE < (size_t) cqe->res)) {
        err = AH_EDOM;
        goto report_err;
    }

    sock->_in->nrecv = (size_t) cqe->res;

    sock->_cbs->on_recv(sock, sock->_in, AH_ENONE);

    if (sock->_state != AH_I_UDP_SOCK_STATE_RECEIVING) {
        return;
    }

    ah_i_udp_in_reset(sock->_in);

    err = s_sock_recv_prep(sock);
    if (err != AH_ENONE) {
        goto report_err;
    }

    return;

report_err:
    (void) sock->_cbs->on_recv(sock, NULL, err);
}

ah_err_t ah_i_udp_sock_recv_stop(void* ctx, ah_udp_sock_t* sock)
{
    (void) ctx;

    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state != AH_I_UDP_SOCK_STATE_RECEIVING) {
        return AH_ESTATE;
    }
    sock->_state = AH_I_UDP_SOCK_STATE_OPEN;

    s_sock_recv_stop(sock);

    return AH_ENONE;
}

static void s_sock_recv_stop(ah_udp_sock_t* sock)
{
    ah_assert_if_debug(sock != NULL);

    if (sock->_in != NULL) {
        ah_i_udp_in_free(sock->_in);
    }

    if (sock->_recv_evt != NULL) {
        struct io_uring_sqe* sqe;
        if (ah_i_loop_alloc_sqe(sock->_loop, &sqe) == AH_ENONE) {
            io_uring_prep_cancel(sqe, sock->_recv_evt, 0);
            sock->_recv_evt = NULL;
        }
    }
}

ah_err_t ah_i_udp_sock_send(void* ctx, ah_udp_sock_t* sock, ah_udp_out_t* out)
{
    (void) ctx;

    if (sock == NULL || out == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state < AH_I_UDP_SOCK_STATE_OPEN || sock->_cbs->on_send == NULL) {
        return AH_ESTATE;
    }

    ah_i_loop_evt_t* evt;
    struct io_uring_sqe* sqe;

    ah_err_t err = ah_i_loop_evt_alloc_with_sqe(sock->_loop, &evt, &sqe);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_sock_send;
    evt->_subject = out;

    out->_msghdr.msg_name = (void*) ah_i_sockaddr_const_into_bsd(out->raddr);
    out->_msghdr.msg_namelen = ah_i_sockaddr_get_size(out->raddr);
    out->_msghdr.msg_iov = ah_i_buf_into_iovec((ah_buf_t*) &out->buf);
    out->_msghdr.msg_iovlen = 1u;
    out->_sock = sock;

    io_uring_prep_sendmsg(sqe, sock->_fd, &out->_msghdr, 0u);
    io_uring_sqe_set_data(sqe, evt);

    return AH_ENONE;
}

static void s_on_sock_send(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(cqe != NULL);

    ah_udp_out_t* out = evt->_subject;
    ah_assert_if_debug(out != NULL);

    ah_udp_sock_t* sock = out->_sock;
    ah_assert_if_debug(sock != NULL);

    ah_err_t err;

    if (ah_unlikely(cqe->res < 0)) {
        err = -(cqe->res);
        out->nsent = 0u;
    }
    else {
        err = AH_ENONE;
        out->nsent = cqe->res;
    }

    sock->_cbs->on_send(sock, out, err);
}

ah_err_t ah_i_udp_sock_close(void* ctx, ah_udp_sock_t* sock)
{
    (void) ctx;

    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state == AH_I_UDP_SOCK_STATE_CLOSED) {
        return AH_ESTATE;
    }
#ifndef NDEBUG
    if (sock->_fd == 0) {
        return AH_ESTATE;
    }
#endif
    sock->_state = AH_I_UDP_SOCK_STATE_CLOSED;

    ah_err_t err;

    ah_i_loop_evt_t* evt;
    struct io_uring_sqe* sqe;

    err = ah_i_loop_evt_alloc_with_sqe(sock->_loop, &evt, &sqe);
    if (err == AH_ENONE) {
        evt->_cb = s_on_sock_close;
        evt->_subject = sock;

        io_uring_prep_close(sqe, sock->_fd);
        io_uring_sqe_set_data(sqe, evt);

        return AH_ENONE;
    }

    // These events are safe to ignore. No other errors should be possible.
    ah_assert_if_debug(err == AH_ENOMEM || err == AH_ENOBUFS || err == AH_ESTATE);

    err = ah_i_sock_close(sock->_fd);
    if (err == AH_EINTR) {
        if (ah_i_loop_try_set_pending_err(sock->_loop, AH_EINTR)) {
            err = AH_ENONE;
        }
    }

    s_sock_close(sock, err);

    return AH_ENONE;
}

static void s_sock_close(ah_udp_sock_t* sock, ah_err_t err)
{
    ah_assert_if_debug(sock != NULL);

#ifndef NDEBUG
    sock->_fd = 0;
#endif

    s_sock_recv_stop(sock);

    sock->_cbs->on_close(sock, err);
}

static void s_on_sock_close(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(cqe != NULL);

    ah_udp_sock_t* sock = evt->_subject;
    ah_assert_if_debug(sock != NULL);

    s_sock_close(sock, -(cqe->res));
}
