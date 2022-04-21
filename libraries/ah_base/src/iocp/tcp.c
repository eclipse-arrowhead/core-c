// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/tcp.h"

#include "../win32/winapi.h"
#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"

#include <stddef.h>

static void s_on_accept(ah_i_loop_evt_t* evt, OVERLAPPED_ENTRY* ove);
static void s_on_connect(ah_i_loop_evt_t* evt, OVERLAPPED_ENTRY* ove);
static void s_on_read(ah_i_loop_evt_t* evt, OVERLAPPED_ENTRY* ove);
static void s_on_write(ah_i_loop_evt_t* evt, OVERLAPPED_ENTRY* ove);

static ah_err_t s_prep_accept(ah_tcp_sock_t* sock, ah_tcp_listen_ctx_t* ctx);
static ah_err_t s_prep_read(ah_tcp_sock_t* sock, ah_tcp_read_ctx_t* ctx);

ah_extern ah_err_t ah_tcp_connect(ah_tcp_sock_t* sock, const ah_sockaddr_t* remote_addr, ah_tcp_connect_cb cb)
{
    if (sock == NULL || !ah_sockaddr_is_ip(remote_addr) || cb == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state != AH_I_TCP_STATE_OPEN) {
        return AH_ESTATE;
    }

    ah_i_loop_evt_t* evt;

    ah_err_t err = ah_i_loop_evt_alloc(sock->_loop, &evt);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_connect;
    evt->_body._tcp_connect._sock = sock;
    evt->_body._tcp_connect._cb = cb;

    const struct sockaddr* name = ah_i_sockaddr_cast_const(remote_addr);
    const int namelen = ah_i_sockaddr_get_size(remote_addr);

    DWORD bytes;
    if (!win_ConnectEx(sock->_fd, name, namelen, NULL, 0u, &bytes, &evt->_overlapped)) {
        err = WSAGetLastError();
        if (err != WSA_IO_PENDING) {
            return err;
        }
    }

    sock->_state = AH_I_TCP_STATE_CONNECTING;

    return AH_ENONE;
}

static void s_on_connect(ah_i_loop_evt_t* evt, OVERLAPPED_ENTRY* ove)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(ove != NULL);

    ah_tcp_sock_t* sock = evt->_body._tcp_connect._sock;
    ah_assert_if_debug(sock != NULL);

    ah_tcp_connect_cb cb = evt->_body._tcp_connect._cb;

    (void) ove;

    DWORD n_bytes_transferred;
    DWORD flags;
    if (!WSAGetOverlappedResult(sock->_fd, &evt->_overlapped, &n_bytes_transferred, false, &flags)) {
        cb(sock, WSAGetLastError());
        return;
    }

    sock->_state = AH_I_TCP_STATE_CONNECTED;
    sock->_state_read = AH_I_TCP_STATE_READ_STOPPED;
    sock->_state_write = AH_I_TCP_STATE_WRITE_STOPPED;

    cb(sock, AH_ENONE);
}

ah_extern ah_err_t ah_tcp_listen(ah_tcp_sock_t* sock, unsigned backlog, ah_tcp_listen_ctx_t* ctx)
{
    if (sock == NULL || ctx == NULL || ctx->listen_cb == NULL || ctx->accept_cb == NULL || ctx->alloc_cb == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state != AH_I_TCP_STATE_OPEN) {
        return AH_ESTATE;
    }

    ah_err_t err;

    if (!sock->_is_listening) {
        int backlog_int = (backlog == 0u) ? 128 : (backlog > SOMAXCONN) ? SOMAXCONN : (int) backlog;
        if (listen(sock->_fd, backlog_int) != 0) {
            err = WSAGetLastError();
            goto handle_err;
        }
        sock->_is_listening = true;
    }

    sock->_state = AH_I_TCP_STATE_LISTENING;

#ifndef NDEBUG
    ctx->_accept_fd = INVALID_SOCKET;
#endif

    err = s_prep_accept(sock, ctx);

    if (err != AH_ENONE) {
        sock->_state = AH_I_TCP_STATE_OPEN;
    }

handle_err:
    ctx->listen_cb(sock, err);

    return AH_ENONE;
}

static ah_err_t s_prep_accept(ah_tcp_sock_t* listener, ah_tcp_listen_ctx_t* ctx)
{
    ah_assert_if_debug(listener != NULL);
    ah_assert_if_debug(listener->_state == AH_I_TCP_STATE_LISTENING);
    ah_assert_if_debug(listener->_is_listening);
    ah_assert_if_debug(ctx != NULL);
    ah_assert_if_debug(ctx->_accept_fd == INVALID_SOCKET);

    ah_err_t err;

    ah_i_loop_evt_t* evt;
    err = ah_i_loop_evt_alloc(listener->_loop, &evt);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_accept;
    evt->_body._tcp_listen._sock = listener;
    evt->_body._tcp_listen._ctx = ctx;

    ah_i_sockfd_t accept_fd;
    err = ah_i_sock_open(listener->_loop, listener->_sockfamily, AH_I_SOCK_STREAM, &accept_fd);
    if (err != AH_ENONE) {
        goto dealloc_evt_and_report_err;
    }

    const DWORD addr_size = sizeof(struct sockaddr_storage);
    DWORD b; // Unused but required.

    if (!win_AcceptEx(listener->_fd, accept_fd, ctx->_accept_buffer, 0u, addr_size, addr_size, &b, &evt->_overlapped)) {
        err = WSAGetLastError();
        if (err != WSA_IO_PENDING) {
            goto close_accept_fd_dealloc_evt_and_report_err;
        }
    }

    ctx->_accept_fd = accept_fd;

    return AH_ENONE;

close_accept_fd_dealloc_evt_and_report_err:
    (void) closesocket(accept_fd);

dealloc_evt_and_report_err:
    ah_i_loop_evt_dealloc(listener->_loop, evt);

    ctx->listen_cb(listener, err);

    return AH_ENONE;
}

static void s_on_accept(ah_i_loop_evt_t* evt, OVERLAPPED_ENTRY* ove)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(ove != NULL);

    ah_tcp_sock_t* listener = evt->_body._tcp_listen._sock;
    ah_assert_if_debug(listener != NULL);

    ah_tcp_listen_ctx_t* ctx = evt->_body._tcp_listen._ctx;
    ah_assert_if_debug(ctx != NULL);
    ah_assert_if_debug(ctx->listen_cb != NULL);
    ah_assert_if_debug(ctx->accept_cb != NULL);
    ah_assert_if_debug(ctx->alloc_cb != NULL);

    (void) ove;

    ah_err_t err;

    DWORD n_bytes_transferred;
    DWORD flags;
    if (!WSAGetOverlappedResult(listener->_fd, &evt->_overlapped, &n_bytes_transferred, false, &flags)) {
        err = WSAGetLastError();
        goto handle_err;
    }

    ah_tcp_sock_t* conn = NULL;
    ctx->alloc_cb(listener, &conn);
    if (conn == NULL) {
        err = AH_ENOMEM;
        goto handle_err;
    }
    *conn = (ah_tcp_sock_t) {
        ._loop = listener->_loop,
        ._fd = ctx->_accept_fd,
        ._state = AH_I_TCP_STATE_CONNECTED,
        ._state_read = AH_I_TCP_STATE_READ_STOPPED,
        ._state_write = AH_I_TCP_STATE_WRITE_STOPPED,
    };

#ifndef NDEBUG
    ctx->_accept_fd = INVALID_SOCKET;
#endif

    const DWORD addr_size = sizeof(struct sockaddr_storage);

    struct sockaddr* local_addr;
    INT local_addr_size;

    ah_sockaddr_t* remote_addr;
    INT remote_addr_size;

    win_GetAcceptExSockaddrs(ctx->_accept_buffer, 0u, addr_size, addr_size, &local_addr, &local_addr_size,
        (struct sockaddr**) &remote_addr, &remote_addr_size);

    ctx->accept_cb(listener, conn, remote_addr, AH_ENONE);

prep_another_accept:

    s_prep_accept(listener, ctx);

    return;

handle_err:
    (void) closesocket(ctx->_accept_fd);

#ifndef NDEBUG
    ctx->_accept_fd = INVALID_SOCKET;
#endif

    ctx->accept_cb(listener, NULL, NULL, err);
    goto prep_another_accept;
}

ah_extern ah_err_t ah_tcp_read_start(ah_tcp_sock_t* sock, ah_tcp_read_ctx_t* ctx)
{
    if (sock == NULL || ctx == NULL || ctx->alloc_cb == NULL || ctx->read_cb == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state != AH_I_TCP_STATE_CONNECTED || sock->_state_read != AH_I_TCP_STATE_READ_STOPPED) {
        return AH_ESTATE;
    }

    ah_err_t err = s_prep_read(sock, ctx);
    if (err != AH_ENONE) {
        return err;
    }

    sock->_state_read = AH_I_TCP_STATE_READ_STARTED;

    return AH_ENONE;
}

static ah_err_t s_prep_read(ah_tcp_sock_t* sock, ah_tcp_read_ctx_t* ctx)
{
    ah_assert_if_debug(sock != NULL);
    ah_assert_if_debug(ctx != NULL);

    ah_i_loop_evt_t* evt;

    ah_err_t err = ah_i_loop_evt_alloc(sock->_loop, &evt);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_read;
    evt->_body._tcp_read._sock = sock;
    evt->_body._tcp_read._ctx = ctx;

    ctx->alloc_cb(sock, &ctx->_bufvec, 0u);
    if (ctx->_bufvec.items == NULL) {
        return AH_ENOMEM;
    }

    WSABUF* buffers;
    ULONG buffer_count;
    err = ah_i_bufvec_into_wsabufs(&ctx->_bufvec, &buffers, &buffer_count);
    if (ah_unlikely(err != AH_ENONE)) {
        return err;
    }

    int res = WSARecv(sock->_fd, buffers, (DWORD) buffer_count, NULL, &ctx->_recv_flags, &evt->_overlapped, NULL);
    if (res == SOCKET_ERROR) {
        err = WSAGetLastError();
        if (err != WSA_IO_PENDING) {
            return err;
        }
    }

    return AH_ENONE;
}

static void s_on_read(ah_i_loop_evt_t* evt, OVERLAPPED_ENTRY* ove)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(ove != NULL);

    ah_tcp_sock_t* sock = evt->_body._tcp_read._sock;
    ah_assert_if_debug(sock != NULL);

    ah_tcp_read_ctx_t* ctx = evt->_body._tcp_read._ctx;
    ah_assert_if_debug(ctx != NULL);
    ah_assert_if_debug(ctx->read_cb != NULL);
    ah_assert_if_debug(ctx->alloc_cb != NULL);

    if (sock->_state != AH_I_TCP_STATE_CONNECTED || sock->_state_read != AH_I_TCP_STATE_READ_STARTED) {
        return;
    }

    (void) ove;

    ah_err_t err;

    DWORD n_bytes_transferred;
    DWORD flags;
    if (!WSAGetOverlappedResult(sock->_fd, &evt->_overlapped, &n_bytes_transferred, false, &flags)) {
        err = WSAGetLastError();
        goto handle_err;
    }

    ctx->read_cb(sock, &ctx->_bufvec, n_bytes_transferred, AH_ENONE);

    if (sock->_state_read != AH_I_TCP_STATE_READ_STARTED) {
        return;
    }

    err = s_prep_read(sock, ctx);
    if (err != AH_ENONE) {
        goto handle_err;
    }

    return;

handle_err:
    ctx->read_cb(sock, NULL, 0u, err);
}

ah_extern ah_err_t ah_tcp_read_stop(ah_tcp_sock_t* sock)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state_read != AH_I_TCP_STATE_READ_STARTED) {
        return AH_ESTATE;
    }
    sock->_state_read = AH_I_TCP_STATE_READ_STOPPED;

    return AH_ENONE;
}

ah_extern ah_err_t ah_tcp_write(ah_tcp_sock_t* sock, ah_tcp_write_ctx_t* ctx)
{
    if (sock == NULL || ctx == NULL || ctx->write_cb == NULL) {
        return AH_EINVAL;
    }
    if (ctx->bufvec.items == NULL && ctx->bufvec.length != 0u) {
        return AH_EINVAL;
    }
    if (sock->_state != AH_I_TCP_STATE_CONNECTED || sock->_state_write != AH_I_TCP_STATE_WRITE_STOPPED) {
        return AH_ESTATE;
    }

    ah_i_loop_evt_t* evt;

    ah_err_t err = ah_i_loop_evt_alloc(sock->_loop, &evt);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_write;
    evt->_body._tcp_write._sock = sock;
    evt->_body._tcp_write._ctx = ctx;

    WSABUF* buffers;
    ULONG buffer_count;
    err = ah_i_bufvec_into_wsabufs(&ctx->bufvec, &buffers, &buffer_count);
    if (ah_unlikely(err != AH_ENONE)) {
        return err;
    }

    int res = WSASend(sock->_fd, buffers, buffer_count, NULL, 0u, &evt->_overlapped, NULL);
    if (res == SOCKET_ERROR) {
        err = WSAGetLastError();
        if (err != WSA_IO_PENDING) {
            return err;
        }
    }

    sock->_state_write = AH_I_TCP_STATE_WRITE_STARTED;

    return AH_ENONE;
}

static void s_on_write(ah_i_loop_evt_t* evt, OVERLAPPED_ENTRY* ove)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(ove != NULL);

    ah_tcp_sock_t* sock = evt->_body._tcp_write._sock;
    ah_assert_if_debug(sock != NULL);

    ah_tcp_write_ctx_t* ctx = evt->_body._tcp_write._ctx;
    ah_assert_if_debug(ctx != NULL);
    ah_assert_if_debug(ctx->write_cb != NULL);
    ah_assert_if_debug(ctx->bufvec.items != NULL || ctx->bufvec.length == 0u);

    if (sock->_state != AH_I_TCP_STATE_CONNECTED || sock->_state_write != AH_I_TCP_STATE_WRITE_STARTED) {
        return;
    }

    (void) ove;

    ah_err_t err;

    DWORD n_bytes_transferred;
    DWORD flags;
    if (!WSAGetOverlappedResult(sock->_fd, &evt->_overlapped, &n_bytes_transferred, false, &flags)) {
        err = WSAGetLastError();
        goto handle_err;
    }

    err = AH_ENONE;

handle_err:
    sock->_state_write = AH_I_TCP_STATE_WRITE_STOPPED;
    ctx->write_cb(sock, err);
}

ah_extern ah_err_t ah_tcp_close(ah_tcp_sock_t* sock, ah_tcp_close_cb cb)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if ((sock->_state & (AH_I_TCP_STATE_OPEN | AH_I_TCP_STATE_CONNECTED | AH_I_TCP_STATE_LISTENING)) == 0u) {
        return AH_ESTATE;
    }
#ifndef NDEBUG
    if (sock->_fd == INVALID_SOCKET) {
        return AH_ESTATE;
    }
#endif
    sock->_state = AH_I_TCP_STATE_CLOSED;
    sock->_state_read = AH_I_TCP_STATE_READ_OFF;
    sock->_state_write = AH_I_TCP_STATE_WRITE_OFF;

    ah_err_t err = ah_i_sock_close(sock->_loop, sock->_fd);

#ifndef NDEBUG
    sock->_fd = INVALID_SOCKET;
#endif

    if (cb != NULL) {
        cb(sock, err);
    }

    return err;
}
