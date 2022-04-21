// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/udp.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"

#include "../win32/winapi.h"

#include <ws2ipdef.h>
#include <mswsock.h>

static void s_on_recv(ah_i_loop_evt_t* evt, OVERLAPPED_ENTRY* ove);
static void s_on_send(ah_i_loop_evt_t* evt, OVERLAPPED_ENTRY* ove);

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

    ah_err_t err = ah_i_loop_evt_alloc(sock->_loop, &evt);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_recv;
    evt->_body._udp_recv._sock = sock;
    evt->_body._udp_recv._ctx = ctx;

    struct ah_bufvec bufvec = { .items = NULL, .length = 0u };
    ctx->alloc_cb(sock, &bufvec, 0u);
    if (bufvec.items == NULL) {
        return AH_ENOMEM;
    }

    WSABUF* buffers;
    ULONG buffer_count;
    err = ah_i_bufvec_into_wsabufs(&bufvec, &buffers, &buffer_count);
    if (ah_unlikely(err != AH_ENONE)) {
        return err;
    }

    ctx->_wsa_msg = (WSAMSG) {
        .name = ah_i_sockaddr_cast(&ctx->_remote_addr),
        .namelen = sizeof(ah_sockaddr_t),
        .lpBuffers = buffers,
        .dwBufferCount = buffer_count,
    };

    int res = win_WSARecvMsg(sock->_fd, &ctx->_wsa_msg, NULL, &evt->_overlapped, NULL);
    if (res == SOCKET_ERROR) {
        err = WSAGetLastError();
        if (err != WSA_IO_PENDING) {
            return err;
        }
    }

    return AH_ENONE;
}

static void s_on_recv(ah_i_loop_evt_t* evt, OVERLAPPED_ENTRY* ove)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(ove != NULL);

    ah_udp_sock_t* sock = evt->_body._udp_recv._sock;
    ah_assert_if_debug(sock != NULL);

    ah_udp_recv_ctx_t* ctx = evt->_body._udp_recv._ctx;
    ah_assert_if_debug(ctx != NULL);
    ah_assert_if_debug(ctx->recv_cb != NULL);
    ah_assert_if_debug(ctx->alloc_cb != NULL);

    if (!sock->_is_open || !sock->_is_receiving) {
        return;
    }

    (void) ove;

    ah_err_t err;

    DWORD n_bytes_transferred;
    DWORD flags;
    if (!WSAGetOverlappedResult(sock->_fd, &evt->_overlapped, &n_bytes_transferred, false, &flags)) {
        err = WSAGetLastError();
        goto call_recv_cb_with_err_and_return;
    }

    struct ah_bufvec bufvec;
    err = ah_i_bufvec_from_wsabufs(&bufvec, ctx->_wsa_msg.lpBuffers, ctx->_wsa_msg.dwBufferCount);
    if (err != AH_ENONE) {
        goto call_recv_cb_with_err_and_return;
    }

    ctx->recv_cb(sock, &ctx->_remote_addr, &bufvec, n_bytes_transferred, AH_ENONE);

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

    ah_err_t err = ah_i_loop_evt_alloc(sock->_loop, &evt);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_send;
    evt->_body._udp_send._sock = sock;
    evt->_body._udp_send._ctx = ctx;

    WSABUF* buffers;
    ULONG buffer_count;
    err = ah_i_bufvec_into_wsabufs(&ctx->bufvec, &buffers, &buffer_count);
    if (ah_unlikely(err != AH_ENONE)) {
        return err;
    }

    ctx->_wsa_msg = (WSAMSG) {
        .name = ah_i_sockaddr_cast(&ctx->remote_addr),
        .namelen = ah_i_sockaddr_get_size(&ctx->remote_addr),
        .lpBuffers = buffers,
        .dwBufferCount = buffer_count,
    };

    int res = WSASendMsg(sock->_fd, &ctx->_wsa_msg, 0u, NULL, &evt->_overlapped, NULL);
    if (res == SOCKET_ERROR) {
        err = WSAGetLastError();
        if (err != WSA_IO_PENDING) {
            return err;
        }
    }

    return AH_ENONE;
}

static void s_on_send(ah_i_loop_evt_t* evt, OVERLAPPED_ENTRY* ove)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(ove != NULL);

    ah_udp_sock_t* sock = evt->_body._udp_send._sock;
    ah_assert_if_debug(sock != NULL);

    ah_udp_send_ctx_t* ctx = evt->_body._udp_send._ctx;
    ah_assert_if_debug(ctx != NULL);
    ah_assert_if_debug(ctx->send_cb != NULL);
    ah_assert_if_debug(ctx->bufvec.items != NULL || ctx->bufvec.length == 0u);

    (void) ove;

    ah_err_t err;

    DWORD n_bytes_transferred;
    DWORD flags;
    if (!WSAGetOverlappedResult(sock->_fd, &evt->_overlapped, &n_bytes_transferred, false, &flags)) {
        err = WSAGetLastError();
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

    ah_err_t err = ah_i_sock_close(sock->_loop, sock->_fd);

#ifndef NDEBUG
    sock->_fd = 0;
#endif

    if (cb != NULL) {
        cb(sock, err);
    }

    return err;
}
