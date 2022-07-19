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

static void s_on_sock_recv(ah_i_loop_evt_t* evt, struct kevent* kev);
static void s_on_sock_send(ah_i_loop_evt_t* evt, struct kevent* kev);

static ah_err_t s_sock_send_prep(ah_udp_sock_t* sock);

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

    ah_i_loop_evt_t* evt;
    struct kevent* kev;

    err = ah_i_loop_evt_alloc_with_kev(sock->_loop, &evt, &kev);
    if (err != AH_ENONE) {
        ah_i_udp_in_free(sock->_in);
        return err;
    }

    evt->_cb = s_on_sock_recv;
    evt->_subject = sock;

    EV_SET(kev, sock->_fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0u, 0, evt);

    sock->_state = AH_I_UDP_SOCK_STATE_RECEIVING;

    return AH_ENONE;
}

static void s_on_sock_recv(ah_i_loop_evt_t* evt, struct kevent* kev)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(kev != NULL);

    ah_udp_sock_t* sock = evt->_subject;
    ah_assert_if_debug(sock != NULL);

    if (sock->_state != AH_I_UDP_SOCK_STATE_RECEIVING) {
        return;
    }

    ah_err_t err;

    if (ah_unlikely((kev->flags & EV_ERROR) != 0)) {
        err = (ah_err_t) kev->data;
        goto report_err;
    }

    if (ah_unlikely(kev->data == 0)) {
        err = AH_EEOF;
        goto report_err;
    }

    ah_sockaddr_t raddr;
    struct sockaddr* address = ah_i_sockaddr_into_bsd(&raddr);
    socklen_t address_len = sizeof(raddr);

    ssize_t nrecv = recvfrom(sock->_fd, sock->_in->buf.base, sock->_in->buf.size, 0, address, &address_len);
    if (nrecv <= 0) {
        // We know there are bytes left to read, so zero bytes being read should not be possible.
        err = nrecv == 0 ? AH_EINTERN : errno;
        goto report_err;
    }

    sock->_in->nrecv = (size_t) nrecv;
    sock->_in->raddr = &raddr;

    sock->_cbs->on_recv(sock, sock->_in, AH_ENONE);

    if (sock->_state != AH_I_UDP_SOCK_STATE_RECEIVING) {
        return;
    }

    ah_i_udp_in_reset(sock->_in);

    if (ah_unlikely((kev->flags & EV_EOF) != 0)) {
        err = kev->fflags != 0 ? (ah_err_t) kev->fflags : AH_EEOF;
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

    if (sock->_in != NULL) {
        ah_i_udp_in_free(sock->_in);
        sock->_in = NULL;
    }

    struct kevent* kev;
    if (ah_i_loop_alloc_kev(sock->_loop, &kev) == AH_ENONE) {
        EV_SET(kev, sock->_fd, EVFILT_READ, EV_DELETE, 0, 0u, NULL);
    }

    return AH_ENONE;
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

    out->_msghdr = (struct msghdr) {
        .msg_name = (void*) ah_i_sockaddr_const_into_bsd(out->raddr),
        .msg_namelen = ah_i_sockaddr_get_size(out->raddr),
        .msg_iov = ah_i_buf_into_iovec(&out->buf),
        .msg_iovlen = 1u,
    };

    const bool is_preparing_another_write = ah_i_list_is_empty(&sock->_out_queue);

    ah_i_list_push(&sock->_out_queue, out, offsetof(ah_udp_out_t, _list_entry));

    if (is_preparing_another_write) {
        return s_sock_send_prep(sock);
    }

    return AH_ENONE;
}

static ah_err_t s_sock_send_prep(ah_udp_sock_t* sock)
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

    if (sock->_state < AH_I_UDP_SOCK_STATE_OPEN) {
        return;
    }

    ah_err_t err;
    ssize_t res = 0;

    ah_udp_out_t* out = ah_i_list_peek(&sock->_out_queue, offsetof(ah_udp_out_t, _list_entry));

    if (ah_unlikely(out == NULL)) {
        err = AH_EINTERN;
        goto report_err_and_prep_next;
    }

    if (ah_unlikely((kev->flags & EV_ERROR) != 0)) {
        err = (ah_err_t) kev->data;
        goto report_err_and_prep_next;
    }

    if (ah_unlikely((kev->flags & EV_EOF) != 0)) {
        err = kev->fflags != 0 ? (ah_err_t) kev->fflags : AH_EEOF;
        goto report_err_and_prep_next;
    }

    res = sendmsg(sock->_fd, &out->_msghdr, 0);
    if (ah_unlikely(res < 0)) {
        err = errno;
        res = 0;
        goto report_err_and_prep_next;
    }

    err = AH_ENONE;

report_err_and_prep_next:
    ah_i_list_skip(&sock->_out_queue);

    out->nsent = (size_t) res;

    sock->_cbs->on_send(sock, out, err);

    if (sock->_state < AH_I_UDP_SOCK_STATE_OPEN) {
        return;
    }
    if (ah_i_list_is_empty(&sock->_out_queue)) {
        return;
    }

    err = s_sock_send_prep(sock);
    if (err != AH_ENONE) {
        goto report_err_and_prep_next;
    }
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

    ah_err_t err = ah_i_sock_close(sock->_fd);
    if (err == AH_EINTR) {
        if (ah_i_loop_try_set_pending_err(sock->_loop, AH_EINTR)) {
            err = AH_ENONE;
        }
    }

#ifndef NDEBUG
    sock->_fd = 0;
#endif

    if (sock->_in != NULL) {
        ah_i_udp_in_free(sock->_in);
    }

    sock->_cbs->on_close(sock, err);

    return err;
}
