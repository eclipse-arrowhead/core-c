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

bool ah_i_udp_msg_queue_is_empty(struct ah_i_udp_msg_queue* queue);
bool ah_i_udp_msg_queue_is_empty_then_add(struct ah_i_udp_msg_queue* queue, ah_udp_msg_t* msg);
ah_udp_msg_t* ah_i_udp_msg_queue_get_head(struct ah_i_udp_msg_queue* queue);
void ah_i_udp_msg_queue_remove_unsafe(struct ah_i_udp_msg_queue* queue);

ah_err_t ah_i_udp_sock_recv_start(void* ctx, ah_udp_sock_t* sock)
{
    (void) ctx;

    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state != AH_I_UDP_SOCK_STATE_OPEN || sock->_cbs->on_recv_data == NULL) {
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
    ah_buf_t buf = (ah_buf_t) { 0u };
    ah_sockaddr_t* raddr = NULL;

    if (ah_unlikely((kev->flags & EV_ERROR) != 0)) {
        err = (ah_err_t) kev->data;
        goto report_err;
    }

    if (kev->data == 0) {
        err = AH_EEOF;
        goto report_err;
    }

    sock->_cbs->on_recv_alloc(sock, &buf);

    if (sock->_state != AH_I_UDP_SOCK_STATE_RECEIVING) {
        return;
    }

    ah_sockaddr_t raddr_buf;
    struct sockaddr* name = ah_i_sockaddr_into_bsd(&raddr_buf);
    socklen_t namelen = sizeof(raddr_buf);

    ssize_t nread = recvfrom(sock->_fd, ah_buf_get_base(&buf), ah_buf_get_size(&buf), 0, name, &namelen);
    if (nread < 0) {
        err = errno;
        goto report_err;
    }

    raddr = &raddr_buf;

    if (nread == 0) {
        // We know there are bytes left to read, so the only thing that
        // could cause 0 bytes being read is bufs having no allocated space.
        err = AH_ENOBUFS;
        goto report_err;
    }

    sock->_cbs->on_recv_data(sock, buf, nread, raddr, 0);

    if (sock->_state != AH_I_UDP_SOCK_STATE_RECEIVING) {
        return;
    }

    if (ah_unlikely((kev->flags & EV_EOF) != 0)) {
        err = kev->fflags != 0 ? (ah_err_t) kev->fflags : AH_EEOF;
        goto report_err;
    }

    return;

report_err:
    sock->_cbs->on_recv_data(sock, (ah_buf_t) { 0u }, 0u, raddr, err);
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

    struct kevent* kev;
    ah_err_t err = ah_i_loop_alloc_kev(sock->_loop, &kev);
    if (err != AH_ENONE) {
        return err;
    }

    EV_SET(kev, sock->_fd, EVFILT_READ, EV_DELETE, 0, 0u, NULL);

    sock->_state = AH_I_UDP_SOCK_STATE_OPEN;

    return AH_ENONE;
}

ah_err_t ah_i_udp_sock_send(void* ctx, ah_udp_sock_t* sock, ah_udp_msg_t* msg)
{
    (void) ctx;

    if (sock == NULL || msg == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state < AH_I_UDP_SOCK_STATE_OPEN || sock->_cbs->on_send_done == NULL) {
        return AH_ESTATE;
    }

    msg->_msghdr = (struct msghdr) {
        .msg_name = (void*) ah_i_sockaddr_const_into_bsd(msg->raddr),
        .msg_namelen = ah_i_sockaddr_get_size(msg->raddr),
        .msg_iov = ah_i_buf_into_iovec(&msg->buf),
        .msg_iovlen = 1u,
    };

    if (ah_i_udp_msg_queue_is_empty_then_add(&sock->_msg_queue, msg)) {
        return s_prep_sock_send(sock);
    }

    return AH_ENONE;
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

    if (sock->_state < AH_I_UDP_SOCK_STATE_OPEN) {
        return;
    }

    ah_err_t err;
    ssize_t res = 0;

    ah_udp_msg_t* msg = ah_i_udp_msg_queue_get_head(&sock->_msg_queue);

    if (ah_unlikely((kev->flags & EV_ERROR) != 0)) {
        err = (ah_err_t) kev->data;
        goto report_err_and_prep_next;
    }

    if (ah_unlikely((kev->flags & EV_EOF) != 0)) {
        err = kev->fflags != 0 ? (ah_err_t) kev->fflags : AH_EEOF;
        goto report_err_and_prep_next;
    }

    res = sendmsg(sock->_fd, &msg->_msghdr, 0);
    if (ah_unlikely(res < 0)) {
        err = errno;
        res = 0;
        goto report_err_and_prep_next;
    }

    err = AH_ENONE;

report_err_and_prep_next:
    ah_i_udp_msg_queue_remove_unsafe(&sock->_msg_queue);
    sock->_cbs->on_send_done(sock, (size_t) res, ah_i_sockaddr_const_from_bsd(msg->_msghdr.msg_name), err);

    if (sock->_state < AH_I_UDP_SOCK_STATE_OPEN) {
        return;
    }
    if (ah_i_udp_msg_queue_is_empty(&sock->_msg_queue)) {
        return;
    }

    err = s_prep_sock_send(sock);
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

    sock->_cbs->on_close(sock, err);

    return err;
}

bool ah_i_udp_msg_queue_is_empty(struct ah_i_udp_msg_queue* queue)
{
    ah_assert_if_debug(queue != NULL);

    return queue->_head == NULL;
}

bool ah_i_udp_msg_queue_is_empty_then_add(struct ah_i_udp_msg_queue* queue, ah_udp_msg_t* msg)
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

ah_udp_msg_t* ah_i_udp_msg_queue_get_head(struct ah_i_udp_msg_queue* queue)
{
    ah_assert_if_debug(queue != NULL);
    ah_assert_if_debug(queue->_head != NULL);

    return queue->_head;
}

void ah_i_udp_msg_queue_remove_unsafe(struct ah_i_udp_msg_queue* queue)
{
    ah_assert_if_debug(queue != NULL);
    ah_assert_if_debug(queue->_head != NULL);
    ah_assert_if_debug(queue->_end != NULL);

    ah_udp_msg_t* msg = queue->_head;
    queue->_head = msg->_next;

#ifndef NDEBUG

    msg->_next = NULL;

    if (queue->_head == NULL) {
        queue->_end = NULL;
    }

#endif
}
