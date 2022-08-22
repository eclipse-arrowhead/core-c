// SPDX-License-Identifier: EPL-2.0

#include "ah/udp.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"
#include "winapi.h"

#include <ws2ipdef.h>

static void s_on_sock_recv(ah_i_loop_evt_t* evt);
static void s_on_sock_send(ah_i_loop_evt_t* evt);

static ah_err_t s_sock_recv_prep(ah_udp_sock_t* sock);
static void s_sock_recv_stop(ah_udp_sock_t* sock);

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

    err = ah_udp_in_alloc_for(&sock->_in);
    if (err != AH_ENONE) {
        return err;
    }

    err = s_sock_recv_prep(sock);
    if (err != AH_ENONE) {
        ah_udp_in_free(sock->_in);
        return err;
    }

    sock->_state = AH_I_UDP_SOCK_STATE_RECEIVING;

    return AH_ENONE;
}

static ah_err_t s_sock_recv_prep(ah_udp_sock_t* sock)
{
    ah_assert_if_debug(sock != NULL);

    ah_i_loop_evt_t* evt;

    ah_err_t err = ah_i_loop_evt_alloc(sock->_loop, &evt);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_sock_recv;
    evt->_subject = sock;

    sock->_in->_recv_from_len = sizeof(sock->_in->_recv_from);
    sock->_in->raddr = &sock->_in->_recv_from;

    WSABUF* buffer = ah_i_buf_into_wsabuf(&sock->_in->buf);

    DWORD* flags = &sock->_in->_recv_flags;
    struct sockaddr* from = ah_i_sockaddr_into_bsd(&sock->_in->_recv_from);
    INT* fromlen = &sock->_in->_recv_from_len;

    int res = WSARecvFrom(sock->_fd, buffer, 1u, NULL, flags, from, fromlen, &evt->_overlapped, NULL);
    if (res == SOCKET_ERROR) {
        err = WSAGetLastError();
        if (err != WSA_IO_PENDING) {
            if (err == WSA_OPERATION_ABORTED) {
                err = AH_EEOF;
            }
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

    DWORD nrecv;
    err = ah_i_loop_evt_get_wsa_result(evt, sock->_fd, &nrecv);
    if (err != AH_ENONE) {
        goto report_err;
    }

    if (ah_unlikely(AH_PSIZE < nrecv)) {
        err = AH_EDOM;
        goto report_err;
    }

    sock->_in->nrecv = nrecv;

    sock->_cbs->on_recv(sock, sock->_in, AH_ENONE);

    if (sock->_state != AH_I_UDP_SOCK_STATE_RECEIVING) {
        return;
    }

    ah_udp_in_reset(sock->_in);

    err = s_sock_recv_prep(sock);
    if (err != AH_ENONE) {
        goto report_err;
    }

    return;

report_err:
    sock->_cbs->on_recv(sock, NULL, err);
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
        ah_udp_in_free(sock->_in);
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

    ah_err_t err = ah_i_loop_evt_alloc(sock->_loop, &evt);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_sock_send;
    evt->_subject = out;

    out->_wsamsg.name = (void*) ah_i_sockaddr_const_into_bsd(out->raddr);
    out->_wsamsg.namelen = ah_i_sockaddr_get_size(out->raddr);
    out->_wsamsg.lpBuffers = ah_i_buf_into_wsabuf(&out->buf);
    out->_wsamsg.dwBufferCount = 1u;
    out->_sock = sock;

    int res = WSASendMsg(sock->_fd, &out->_wsamsg, 0u, NULL, &evt->_overlapped, NULL);
    if (res == SOCKET_ERROR) {
        err = WSAGetLastError();
        if (err == WSA_IO_PENDING) {
            err = AH_ENONE;
        }
        else if (err == WSA_OPERATION_ABORTED) {
            err = AH_EEOF;
        }
    }

    return err;
}

static void s_on_sock_send(ah_i_loop_evt_t* evt)
{
    ah_assert_if_debug(evt != NULL);

    ah_udp_out_t* out = evt->_subject;
    ah_assert_if_debug(out != NULL);

    ah_udp_sock_t* sock = out->_sock;
    ah_assert_if_debug(sock != NULL);

    ah_err_t err;

    DWORD nsent;
    err = ah_i_loop_evt_get_wsa_result(evt, sock->_fd, &nsent);
    if (err != AH_ENONE) {
        nsent = 0u;
    }

    out->nsent = nsent;

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

    ah_err_t err = ah_i_sock_close(sock->_fd);
    if (err == AH_EINTR) {
        if (ah_i_loop_try_set_pending_err(sock->_loop, AH_EINTR)) {
            err = AH_ENONE;
        }
    }

#ifndef NDEBUG
    sock->_fd = 0;
#endif

    s_sock_recv_stop(sock);

    sock->_cbs->on_close(sock, err);

    return err;
}
