// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/udp.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"

static void s_on_sock_close(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe);
static void s_on_sock_recv(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe);
static void s_on_sock_send(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe);

static ah_err_t s_prep_sock_recv(ah_udp_sock_t* sock);
static ah_err_t s_prep_sock_send(ah_udp_sock_t* sock);

ah_extern ah_err_t ah_udp_sock_recv_start(ah_udp_sock_t* sock)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open || sock->_is_receiving) {
        return AH_ESTATE;
    }

    sock->_is_receiving = true;

    ah_err_t err = s_prep_sock_recv(sock);
    if (err != AH_ENONE) {
        return err;
    }

    return AH_ENONE;
}

static ah_err_t s_prep_sock_recv(ah_udp_sock_t* sock)
{
    ah_assert_if_debug(sock != NULL);

    ah_i_loop_evt_t* evt;
    struct io_uring_sqe* sqe;

    ah_err_t err = ah_i_loop_evt_alloc_with_sqe(sock->_loop, &evt, &sqe);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_sock_recv;
    evt->_subject = sock;

    sock->_recv_buf = (ah_buf_t) { 0u };
    sock->_vtab->on_recv_alloc(sock, &sock->_recv_buf);

    if (!sock->_is_open || !sock->_is_receiving) {
        return AH_ENONE;
    }

    if (ah_buf_is_empty(&sock->_recv_buf)) {
        sock->_is_receiving = false;
        return AH_ENOBUFS;
    }

    sock->_recv_msghdr = (struct msghdr) {
        .msg_name = ah_i_sockaddr_into_bsd(&sock->_recv_addr),
        .msg_namelen = sizeof(ah_sockaddr_t),
        .msg_iov = ah_i_buf_into_iovec(&sock->_recv_buf),
        .msg_iovlen = 1,
    };

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

    if (!sock->_is_open || !sock->_is_receiving) {
        return;
    }

    ah_err_t err;
    ah_sockaddr_t* raddr;

    if (ah_unlikely(cqe->res < 0)) {
        err = -(cqe->res);
        raddr = NULL;
        goto report_err;
    }
    else {
        raddr = ah_i_sockaddr_from_bsd(sock->_recv_msghdr.msg_name);
    }

    sock->_vtab->on_recv_data(sock, &sock->_recv_buf, cqe->res, raddr);
#ifndef NDEBUG
    sock->_recv_buf = (ah_buf_t) { 0u };
#endif

    if (!sock->_is_open || !sock->_is_receiving) {
        return;
    }

    err = s_prep_sock_recv(sock);
    if (err != AH_ENONE) {
        goto report_err;
    }

    return;

report_err:
    sock->_vtab->on_recv_err(sock, raddr, err);
}

ah_extern ah_err_t ah_udp_sock_recv_stop(ah_udp_sock_t* sock)
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

ah_extern ah_err_t ah_udp_sock_send(ah_udp_sock_t* sock, ah_udp_obufs_t* obufs)
{
    if (sock == NULL || obufs == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open || sock->_vtab->on_send_done == NULL) {
        return AH_ESTATE;
    }

    if (sock->_send_queue_head != NULL) {
        sock->_send_queue_end->_next = obufs;
        sock->_send_queue_end = obufs;
        return AH_ENONE;
    }

    sock->_send_queue_head = obufs;
    sock->_send_queue_end = obufs;

    return s_prep_sock_send(sock);
}

static ah_err_t s_prep_sock_send(ah_udp_sock_t* sock)
{
    ah_i_loop_evt_t* evt;
    struct io_uring_sqe* sqe;

    ah_err_t err = ah_i_loop_evt_alloc_with_sqe(sock->_loop, &evt, &sqe);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_sock_send;
    evt->_subject = sock;

    ah_udp_obufs_t* obufs = sock->_send_queue_head;

    io_uring_prep_sendmsg(sqe, sock->_fd, &obufs->_msghdr, 0u);
    io_uring_sqe_set_data(sqe, evt);

    return AH_ENONE;
}

static void s_on_sock_send(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(cqe != NULL);

    ah_udp_sock_t* sock = evt->_subject;
    ah_assert_if_debug(sock != NULL);

    ah_err_t err;
    size_t n_bytes_sent;

    if (ah_unlikely(cqe->res < 0)) {
        err = -(cqe->res);
        n_bytes_sent = 0u;
    }
    else {
        err = AH_ENONE;
        n_bytes_sent = cqe->res;
    }

    ah_udp_obufs_t* obufs = sock->_send_queue_head;
    sock->_send_queue_head = obufs->_next;

report_err_and_prep_next:
    sock->_vtab->on_send_done(sock, n_bytes_sent, ah_i_sockaddr_const_from_bsd(obufs->_msghdr.msg_name), err);

    if (sock->_send_queue_head == NULL) {
        return;
    }

    err = s_prep_sock_send(sock);
    if (err != AH_ENONE) {
        obufs = sock->_send_queue_head;
        sock->_send_queue_head = obufs->_next;
        goto report_err_and_prep_next;
    }
}

ah_extern ah_err_t ah_udp_sock_close(ah_udp_sock_t* sock)
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

#ifndef NDEBUG
    sock->_fd = 0;
#endif

    sock->_vtab->on_close(sock, err);

    return AH_ENONE;
}

static void s_on_sock_close(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(cqe != NULL);

    ah_udp_sock_t* sock = evt->_subject;
    ah_assert_if_debug(sock != NULL);

#ifndef NDEBUG
    sock->_fd = 0;
#endif

    sock->_vtab->on_close(sock, -(cqe->res));
}
