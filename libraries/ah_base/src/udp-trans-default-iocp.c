// SPDX-License-Identifier: EPL-2.0

#include "ah/udp.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"
#include "winapi.h"

#include <ws2ipdef.h>

static void s_sock_on_recv(ah_i_loop_evt_t* evt);
static void s_sock_on_send(ah_i_loop_evt_t* evt);

static ah_err_t s_sock_recv_prep(ah_udp_sock_t* sock);
static void s_sock_recv_stop(ah_udp_sock_t* sock);
static ah_err_t s_sock_ref(ah_udp_sock_t* sock);
static void s_sock_unref(ah_udp_sock_t* sock);

ah_err_t ah_i_udp_trans_default_sock_recv_start(void* ctx, ah_udp_sock_t* sock)
{
    (void) ctx;

    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state != AH_I_UDP_SOCK_STATE_OPEN) {
        return AH_ESTATE;
    }

    ah_err_t err;

    err = ah_udp_in_alloc_for(&sock->_in);
    if (err != AH_ENONE) {
        return err;
    }

    sock->_state = AH_I_UDP_SOCK_STATE_RECEIVING;

    err = s_sock_recv_prep(sock);
    if (err != AH_ENONE) {
        ah_udp_in_free(sock->_in);
        return err;
    }

    return AH_ENONE;
}

static ah_err_t s_sock_recv_prep(ah_udp_sock_t* sock)
{
    ah_assert_if_debug(sock != NULL);
    ah_assert_if_debug(sock->_state == AH_I_UDP_SOCK_STATE_RECEIVING);

    ah_i_loop_evt_t* evt;

    ah_err_t err = ah_i_loop_evt_alloc(sock->_loop, &evt);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_sock_on_recv;
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

static void s_sock_on_recv(ah_i_loop_evt_t* evt)
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

    if (ah_unlikely(nrecv > AH_PSIZE)) {
        err = AH_EDOM;
        goto report_err;
    }

    sock->_in->nrecv = nrecv;

    err = s_sock_ref(sock);
    if (err != AH_ENONE) {
        goto report_err;
    }

    sock->_obs.cbs->on_recv(sock->_obs.ctx, sock, sock->_in, AH_ENONE);

    uint8_t state = sock->_state;

    s_sock_unref(sock);

    if (state != AH_I_UDP_SOCK_STATE_RECEIVING) {
        return;
    }

    ah_udp_in_reset(sock->_in);

    err = s_sock_recv_prep(sock);
    if (err != AH_ENONE) {
        sock->_state = AH_I_UDP_SOCK_STATE_OPEN;
        goto report_err;
    }

    return;

report_err:
    sock->_obs.cbs->on_recv(sock->_obs.ctx, sock, NULL, err);
}

static ah_err_t s_sock_ref(ah_udp_sock_t* sock)
{
    if (sock == NULL) {
        return AH_EINTERN;
    }
    return ah_add_uint32(sock->_ref_count, 1u, &sock->_ref_count);
}

static void s_sock_unref(ah_udp_sock_t* sock)
{
    if (sock->_ref_count != 0u) {
        sock->_ref_count -= 1u;
        return;
    }

    ah_assert_if_debug(sock->_state == AH_I_UDP_SOCK_STATE_CLOSING);

    ah_err_t err = ah_i_sock_close(sock->_fd);
    if (err == AH_EINTR) {
        if (ah_i_loop_try_set_pending_err(sock->_loop, AH_EINTR)) {
            err = AH_ENONE;
        }
    }

    sock->_fd = INVALID_SOCKET;

    s_sock_recv_stop(sock);

    sock->_state = AH_I_UDP_SOCK_STATE_CLOSED;

    sock->_obs.cbs->on_close(sock->_obs.ctx, sock, err);
}

static void s_sock_recv_stop(ah_udp_sock_t* sock)
{
    ah_assert_if_debug(sock != NULL);

    if (sock->_in != NULL) {
        ah_udp_in_free(sock->_in);
        sock->_in = NULL;
    }
}

ah_err_t ah_i_udp_trans_default_sock_recv_stop(void* ctx, ah_udp_sock_t* sock)
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

ah_err_t ah_i_udp_trans_default_sock_send(void* ctx, ah_udp_sock_t* sock, ah_udp_out_t* out)
{
    (void) ctx;

    if (sock == NULL || out == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state < AH_I_UDP_SOCK_STATE_OPEN) {
        return AH_ESTATE;
    }

    ah_i_loop_evt_t* evt;

    ah_err_t err = ah_i_loop_evt_alloc(sock->_loop, &evt);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_sock_on_send;
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

static void s_sock_on_send(ah_i_loop_evt_t* evt)
{
    ah_assert_if_debug(evt != NULL);

    ah_udp_out_t* out = evt->_subject;
    ah_assert_if_debug(out != NULL);

    ah_udp_sock_t* sock = out->_sock;
    ah_assert_if_debug(sock != NULL);

    if (sock->_state < AH_I_UDP_SOCK_STATE_OPEN) {
        return;
    }

    ah_err_t err;

    DWORD nsent;
    err = ah_i_loop_evt_get_wsa_result(evt, sock->_fd, &nsent);
    if (err != AH_ENONE) {
        nsent = 0u;
    }

    out->nsent = nsent;

    sock->_obs.cbs->on_send(sock->_obs.ctx, sock, out, err);
}

ah_err_t ah_i_udp_trans_default_sock_close(void* ctx, ah_udp_sock_t* sock)
{
    (void) ctx;

    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state <= AH_I_UDP_SOCK_STATE_CLOSING) {
        return AH_ESTATE;
    }
    if (sock->_fd == INVALID_SOCKET) {
        return AH_EINTERN;
    }
    sock->_state = AH_I_UDP_SOCK_STATE_CLOSING;

    s_sock_unref(sock);

    return AH_ENONE;
}
