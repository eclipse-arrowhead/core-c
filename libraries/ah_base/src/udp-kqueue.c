// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/udp.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"

static void s_on_sock_recv(ah_i_loop_evt_t* evt, struct kevent* kev);
static void s_on_sock_send(ah_i_loop_evt_t* evt, struct kevent* kev);

static ah_err_t s_prep_sock_send(ah_udp_sock_t* sock);

ah_extern ah_err_t ah_udp_sock_recv_start(ah_udp_sock_t* sock)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open || sock->_is_receiving || sock->_vtab->on_recv_data == NULL) {
        return AH_ESTATE;
    }

    ah_i_loop_evt_t* evt;
    struct kevent* kev;

    ah_err_t err = ah_i_loop_evt_alloc_with_kev(sock->_loop, &evt, &kev);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_sock_recv;
    evt->_subject = sock;

    EV_SET(kev, sock->_fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0u, 0, evt);

    sock->_is_receiving = true;

    return AH_ENONE;
}

static void s_on_sock_recv(ah_i_loop_evt_t* evt, struct kevent* kev)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(kev != NULL);

    ah_udp_sock_t* sock = evt->_subject;
    ah_assert_if_debug(sock != NULL);

    if (!sock->_is_open || !sock->_is_receiving) {
        return;
    }

    ah_err_t err;
    ah_bufs_t bufs = { .items = NULL, .length = 0u };
    ah_sockaddr_t* raddr = NULL;

    if (ah_unlikely((kev->flags & EV_ERROR) != 0)) {
        err = (ah_err_t) kev->data;
        goto report_err;
    }

    if (kev->data == 0) {
        err = AH_EEOF;
        goto report_err;
    }

    sock->_vtab->on_recv_alloc(sock, &bufs);

    struct iovec* iov;
    int iovcnt;
    err = ah_i_bufs_into_iovec(&bufs, &iov, &iovcnt);
    if (ah_unlikely(err != AH_ENONE)) {
        goto report_err;
    }

    ah_sockaddr_t name;
    socklen_t namelen = sizeof(name);

    struct msghdr msghdr = {
        .msg_name = ah_i_sockaddr_into_bsd(&name),
        .msg_namelen = namelen,
        .msg_iov = iov,
        .msg_iovlen = iovcnt,
    };

    ssize_t n_bytes_read = recvmsg(sock->_fd, &msghdr, 0);
    if (n_bytes_read < 0) {
        err = errno;
        goto report_err;
    }

    raddr = &name;

    if (n_bytes_read == 0) {
        // We know there are bytes left to read, so the only thing that
        // could cause 0 bytes being read is bufs having no allocated space.
        err = AH_ENOBUFS;
        goto report_err;
    }

    sock->_vtab->on_recv_data(sock, bufs, n_bytes_read, raddr);

    if (!sock->_is_open) {
        return;
    }

    if (ah_unlikely((kev->flags & EV_EOF) != 0)) {
        err = kev->fflags != 0 ? (ah_err_t) kev->fflags : AH_EEOF;
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

    struct kevent* kev;
    ah_err_t err = ah_i_loop_alloc_kev(sock->_loop, &kev);
    if (err != AH_ENONE) {
        return err;
    }

    EV_SET(kev, sock->_fd, EVFILT_READ, EV_DELETE, 0, 0u, NULL);

    sock->_is_receiving = false;

    return AH_ENONE;
}

ah_extern ah_err_t ah_udp_sock_send(ah_udp_sock_t* sock, ah_udp_omsg_t* omsg)
{
    if (sock == NULL || omsg == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open || sock->_vtab->on_send_done == NULL) {
        return AH_ESTATE;
    }

    if (sock->_send_queue_head != NULL) {
        sock->_send_queue_end->_next = omsg;
        sock->_send_queue_end = omsg;
        return AH_ENONE;
    }

    sock->_send_queue_head = omsg;
    sock->_send_queue_end = omsg;

    return s_prep_sock_send(sock);
}

static ah_err_t s_prep_sock_send(ah_udp_sock_t* sock)
{
    ah_i_loop_evt_t* evt;
    struct kevent* kev;

    ah_err_t err = ah_i_loop_evt_alloc_with_kev(sock->_loop, &evt, &kev);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_sock_send;
    evt->_subject = sock;

    EV_SET(kev, sock->_fd, EVFILT_WRITE, EV_ADD | EV_ONESHOT, 0u, 0, evt);

    return AH_ENONE;
}

static void s_on_sock_send(ah_i_loop_evt_t* evt, struct kevent* kev)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(kev != NULL);

    ah_udp_sock_t* sock = evt->_subject;
    ah_assert_if_debug(sock != NULL);
    ah_assert_if_debug(sock->_send_queue_head != NULL);

    if (!sock->_is_open) {
        return;
    }

    ah_err_t err;
    ssize_t res = 0;

    ah_udp_omsg_t* omsg = sock->_send_queue_head;
    sock->_send_queue_head = omsg->_next;

    if (ah_unlikely((kev->flags & EV_ERROR) != 0)) {
        err = (ah_err_t) kev->data;
        goto report_err_and_prep_next;
    }

    if (ah_unlikely((kev->flags & EV_EOF) != 0)) {
        err = kev->fflags != 0 ? (ah_err_t) kev->fflags : AH_EEOF;
        goto report_err_and_prep_next;
    }

    res = sendmsg(sock->_fd, &omsg->_msghdr, 0);
    if (ah_unlikely(res < 0)) {
        err = errno;
        res = 0;
        goto report_err_and_prep_next;
    }

    err = AH_ENONE;

report_err_and_prep_next:
    sock->_vtab->on_send_done(sock, (size_t) res, ah_i_sockaddr_const_from_bsd(omsg->_msghdr.msg_name), err);

    if (sock->_send_queue_head == NULL) {
        return;
    }

    err = s_prep_sock_send(sock);
    if (err != AH_ENONE) {
        sock->_send_queue_head = sock->_send_queue_head->_next;
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

    ah_err_t err = ah_i_sock_close(sock->_fd);
    if (err == AH_EINTR) {
        if (ah_i_loop_try_set_pending_err(sock->_loop, AH_EINTR)) {
            err = AH_ENONE;
        }
    }

#ifndef NDEBUG
    sock->_fd = 0;
#endif

    sock->_vtab->on_close(sock, err);

    return err;
}
