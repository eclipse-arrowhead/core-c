// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/udp.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"
#include "winapi.h"

#include <ws2ipdef.h>

static void s_on_sock_recv(ah_i_loop_evt_t* evt);
static void s_on_sock_send(ah_i_loop_evt_t* evt);

static ah_err_t s_prep_sock_recv(ah_udp_sock_t* sock);
static ah_err_t s_prep_sock_send(ah_udp_sock_t* sock);

ah_err_t ah_i_udp_sock_recv_start(void* ctx, ah_udp_sock_t* sock)
{
    (void) ctx;

    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state != AH_I_UDP_SOCK_STATE_OPEN || sock->_cbs->on_recv_data == NULL) {
        return AH_ESTATE;
    }

    sock->_state = AH_I_UDP_SOCK_STATE_RECEIVING;

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

    ah_err_t err = ah_i_loop_evt_alloc(sock->_loop, &evt);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_sock_recv;
    evt->_subject = sock;

    sock->_recv_buf = (ah_buf_t) { 0u };
    sock->_cbs->on_recv_alloc(sock, &sock->_recv_buf);

    if (sock->_state != AH_I_UDP_SOCK_STATE_RECEIVING) {
        return AH_ENONE;
    }

    if (ah_buf_is_empty(&sock->_recv_buf)) {
        sock->_state = AH_I_UDP_SOCK_STATE_OPEN;
        return AH_ENOBUFS;
    }

    WSABUF* buffer = ah_i_buf_into_wsabuf(&conn->_recv_buf);

    struct sockaddr* from = ah_i_sockaddr_into_bsd(&sock->recv_addr);
    LPINT fromlen = &sock->recv_addr_ln;

    int res = WSARecvFrom(sock->_fd, buffer, 1u, NULL, &sock->_recv_flags, from, fromlen, &evt->_overlapped, NULL);
    if (res == SOCKET_ERROR) {
        err = WSAGetLastError();
        if (err != WSA_IO_PENDING) {
            return err;
        }
    }

    return AH_ENONE;
}

static void s_on_sock_recv(ah_i_loop_evt_t* evt)
{
    ah_assert_if_debug(evt != NULL);

    ah_udp_sock_t* sock = evt->_subject;
    ah_assert_if_debug(sock != NULL);

    if (sock->_state != AH_I_UDP_SOCK_STATE_RECEIVING) {
        return;
    }

    ah_err_t err;
    ah_sockaddr_t* raddr;

    DWORD nrecv;
    err = ah_i_loop_evt_get_result(evt, &nrecv);
    if (err != AH_ENONE) {
        raddr = NULL;
        goto report_err;
    }

    raddr = ah_i_sockaddr_from_bsd(sock->_recv_addr);

    sock->_cbs->on_recv_data(sock, &sock->_recv_buf, nrecv, raddr);
#ifndef NDEBUG
    sock->_recv_buf = (ah_buf_t) { 0u };
#endif

    if (sock->_state != AH_I_UDP_SOCK_STATE_RECEIVING) {
        return;
    }

    err = s_prep_sock_recv(sock);
    if (err != AH_ENONE) {
        goto report_err;
    }

    return;

report_err:
    sock->_cbs->on_recv_data(sock, NULL, 0u, raddr, err);
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

    return AH_ENONE;
}

ah_err_t ah_i_udp_sock_send(void* ctx, ah_udp_sock_t* sock, ah_udp_out_t* out)
{
    (void) ctx;

    if (sock == NULL || out == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state < AH_I_UDP_SOCK_STATE_OPEN || sock->_cbs->on_send_done == NULL) {
        return AH_ESTATE;
    }

    if (ah_i_udp_out_queue_is_empty_then_add(&sock->_out_queue, out)) {
        return s_prep_sock_send(sock);
    }

    return AH_ENONE;
}

static ah_err_t s_prep_sock_send(ah_udp_sock_t* sock)
{
    ah_i_loop_evt_t* evt;

    ah_err_t err = ah_i_loop_evt_alloc(sock->_loop, &evt);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_sock_send;
    evt->_subject = sock;

    ah_udp_out_t* out = ah_i_udp_out_queue_get_head(&sock->_out_queue);

    int res = WSASendMsg(sock->_fd, &out->_wsamsg, 0u, NULL, &evt->_overlapped, NULL);
    if (res == SOCKET_ERROR) {
        err = WSAGetLastError();
        if (err == WSA_IO_PENDING) {
            err = AH_ENONE;
        }
    }

    return err;
}

static void s_on_sock_send(ah_i_loop_evt_t* evt)
{
    ah_assert_if_debug(evt != NULL);

    ah_udp_sock_t* sock = evt->_subject;
    ah_assert_if_debug(sock != NULL);

    ah_err_t err;

    DWORD nsent;
    err = ah_i_loop_evt_get_result(evt, &nsent);
    if (err != AH_ENONE) {
        nsent = 0u;
    }

    ah_udp_out_t* out;

report_err_and_prep_next:
    out = ah_i_udp_out_queue_get_head(&sock->_msg_queue);
    ah_i_udp_msg_queue_remove_unsafe(&sock->_msg_queue);

    sock->_cbs->on_send_done(sock, nsent, ah_i_sockaddr_from_bsd(msg->_wsamsg.name), err);

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
