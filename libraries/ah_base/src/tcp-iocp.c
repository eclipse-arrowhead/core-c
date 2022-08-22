// SPDX-License-Identifier: EPL-2.0

#include "ah/tcp.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"
#include "ah/sock.h"
#include "winapi.h"

#include <stddef.h>

static void s_on_conn_connect(ah_i_loop_evt_t* evt);
static void s_on_conn_read(ah_i_loop_evt_t* evt);
static void s_on_conn_write(ah_i_loop_evt_t* evt);

static void s_on_listener_accept(ah_i_loop_evt_t* evt);

static ah_err_t s_conn_read_prep(ah_tcp_conn_t* conn);
static void s_conn_read_stop(ah_tcp_conn_t* conn);

static ah_err_t s_listener_accept_prep(ah_tcp_listener_t* ln);

#pragma warning(disable : 6011)
ah_err_t ah_i_tcp_conn_connect(void* ctx, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr)
{
    (void) ctx;

    if (conn == NULL || raddr == NULL) {
        return AH_EINVAL;
    }
    if (!ah_sockaddr_is_ip(raddr)) {
        return AH_EAFNOSUPPORT;
    }
    if (conn->_state != AH_I_TCP_CONN_STATE_OPEN) {
        return AH_ESTATE;
    }

    ah_err_t err;

    if (conn->_ConnectEx == NULL) {
        err = ah_i_winapi_get_wsa_fn(conn->_fd, &(GUID) WSAID_CONNECTEX, (void**) &conn->_ConnectEx);
        if (err != AH_ENONE) {
            return err;
        }
    }

    ah_i_loop_evt_t* evt;
    err = ah_i_loop_evt_alloc(conn->_loop, &evt);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_conn_connect;
    evt->_subject = conn;

    const struct sockaddr* name = ah_i_sockaddr_const_into_bsd(raddr);
    const int namelen = ah_i_sockaddr_get_size(raddr);

    DWORD bytes;
    if (!conn->_ConnectEx(conn->_fd, name, namelen, NULL, 0u, &bytes, &evt->_overlapped)) {
        err = WSAGetLastError();
        if (err != WSA_IO_PENDING) {
            return err;
        }
    }

    conn->_state = AH_I_TCP_CONN_STATE_CONNECTING;

    return AH_ENONE;
}
#pragma warning(default : 6011)

static void s_on_conn_connect(ah_i_loop_evt_t* evt)
{
    ah_assert_if_debug(evt != NULL);

    ah_tcp_conn_t* conn = evt->_subject;
    ah_assert_if_debug(conn != NULL);

    if (conn->_state != AH_I_TCP_CONN_STATE_CONNECTING) {
        return;
    }

    ah_err_t err;

    DWORD n_bytes_transferred;
    err = ah_i_loop_evt_get_wsa_result(evt, conn->_fd, &n_bytes_transferred);
    if (err != AH_ENONE) {
        conn->_state = AH_I_TCP_CONN_STATE_OPEN;
        goto handle_err;
    }

    conn->_state = AH_I_TCP_CONN_STATE_CONNECTED;

    err = ah_i_sock_setsockopt(conn->_fd, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);

handle_err:
    conn->_cbs->on_connect(conn, err);
}

ah_err_t ah_i_tcp_conn_read_start(void* ctx, ah_tcp_conn_t* conn)
{
    (void) ctx;

    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state != AH_I_TCP_CONN_STATE_CONNECTED || (conn->_shutdown_flags & AH_TCP_SHUTDOWN_RD) != 0) {
        return AH_ESTATE;
    }

    ah_err_t err;

    err = ah_tcp_in_alloc_for(&conn->_in);
    if (err != AH_ENONE) {
        return err;
    }

    conn->_state = AH_I_TCP_CONN_STATE_READING;

    err = s_conn_read_prep(conn);
    if (err != AH_ENONE) {
        conn->_state = AH_I_TCP_CONN_STATE_CONNECTED;
        return err;
    }

    return AH_ENONE;
}

static ah_err_t s_conn_read_prep(ah_tcp_conn_t* conn)
{
    ah_assert_if_debug(conn != NULL);
    ah_assert_if_debug(conn->_state == AH_I_TCP_CONN_STATE_READING);

    ah_err_t err;

    conn->_recv_buf = ah_rw_get_writable_as_buf(&conn->_in->rw);
    if (ah_buf_is_empty(&conn->_recv_buf)) {
        return AH_EOVERFLOW;
    }

    ah_i_loop_evt_t* evt;

    err = ah_i_loop_evt_alloc(conn->_loop, &evt);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_conn_read;
    evt->_subject = conn;

    WSABUF* buffer = ah_i_buf_into_wsabuf(&conn->_recv_buf);

    int res = WSARecv(conn->_fd, buffer, 1u, NULL, &conn->_recv_flags, &evt->_overlapped, NULL);
    if (res == SOCKET_ERROR) {
        err = WSAGetLastError();
        if (err != WSA_IO_PENDING) {
            return err;
        }
    }

    return AH_ENONE;
}

static void s_on_conn_read(ah_i_loop_evt_t* evt)
{
    ah_assert_if_debug(evt != NULL);

    ah_tcp_conn_t* conn = evt->_subject;
    ah_assert_if_debug(conn != NULL);

    if (conn->_state != AH_I_TCP_CONN_STATE_READING) {
        return;
    }

    ah_err_t err;

    DWORD nread;
    err = ah_i_loop_evt_get_wsa_result(evt, conn->_fd, &nread);
    if (err != AH_ENONE) {
        nread = 0u;
        goto report_err;
    }

    if (ah_unlikely(conn->_recv_buf.size != 0 && nread == 0)) {
        conn->_shutdown_flags |= AH_TCP_SHUTDOWN_RD;
        err = AH_EEOF;
        goto report_err;
    }

    if (ah_unlikely(conn->_recv_buf.size < (size_t) nread)) {
        err = AH_EDOM;
        goto report_err;
    }

    conn->_in->rw.w = &conn->_in->rw.w[(size_t) nread];
    ah_assert_if_debug(conn->_in->rw.w <= conn->_in->rw.e);

    conn->_cbs->on_read(conn, conn->_in, AH_ENONE);

#ifndef NDEBUG
    conn->_recv_buf = (ah_buf_t) { 0u };
#endif

    if (conn->_state != AH_I_TCP_CONN_STATE_READING) {
        return;
    }

    if (!ah_rw_is_readable(&conn->_in->rw)) {
        ah_tcp_in_reset(conn->_in);
    }

    err = s_conn_read_prep(conn);
    if (err != AH_ENONE) {
        conn->_state = AH_I_TCP_CONN_STATE_CONNECTED;
        goto report_err;
    }

    return;

report_err:
    conn->_cbs->on_read(conn, NULL, err);
}

ah_err_t ah_i_tcp_conn_read_stop(void* ctx, ah_tcp_conn_t* conn)
{
    (void) ctx;

    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state != AH_I_TCP_CONN_STATE_READING) {
        return AH_ESTATE;
    }

    conn->_state = AH_I_TCP_CONN_STATE_CONNECTED;

    s_conn_read_stop(conn);

    return AH_ENONE;
}

static void s_conn_read_stop(ah_tcp_conn_t* conn)
{
    ah_assert_if_debug(conn != NULL);

    if (conn->_in != NULL) {
        ah_tcp_in_free(conn->_in);
    }
}

ah_err_t ah_i_tcp_conn_write(void* ctx, ah_tcp_conn_t* conn, ah_tcp_out_t* out)
{
    (void) ctx;

    if (conn == NULL || out == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state < AH_I_TCP_CONN_STATE_CONNECTED || (conn->_shutdown_flags & AH_TCP_SHUTDOWN_WR) != 0) {
        return AH_ESTATE;
    }

    ah_i_loop_evt_t* evt;

    ah_err_t err = ah_i_loop_evt_alloc(conn->_loop, &evt);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_conn_write;
    evt->_subject = out;

    out->_conn = conn;

    int res = WSASend(conn->_fd, ah_i_buf_into_wsabuf(&out->buf), 1u, NULL, 0u, &evt->_overlapped, NULL);
    if (res == SOCKET_ERROR) {
        err = WSAGetLastError();
        if (err == WSA_IO_PENDING) {
            err = AH_ENONE;
        }
    }

    return err;
}

static void s_on_conn_write(ah_i_loop_evt_t* evt)
{
    ah_assert_if_debug(evt != NULL);

    ah_tcp_out_t* out = evt->_subject;
    ah_assert_if_debug(out != NULL);

    ah_tcp_conn_t* conn = out->_conn;
    ah_assert_if_debug(conn != NULL);

    if (conn->_state < AH_I_TCP_CONN_STATE_CONNECTED) {
        return;
    }

    DWORD nsent;
    ah_err_t err = ah_i_loop_evt_get_wsa_result(evt, conn->_fd, &nsent);

    conn->_cbs->on_write(conn, out, err);
}

ah_err_t ah_i_tcp_conn_close(void* ctx, ah_tcp_conn_t* conn)
{
    (void) ctx;

    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state == AH_I_TCP_CONN_STATE_CLOSED) {
        return AH_ESTATE;
    }
#ifndef NDEBUG
    if (conn->_fd == 0) {
        return AH_ESTATE;
    }
#endif
    conn->_state = AH_I_TCP_CONN_STATE_CLOSED;

    ah_err_t err = ah_i_sock_close(conn->_fd);
    if (err == AH_EINTR) {
        if (ah_i_loop_try_set_pending_err(conn->_loop, AH_EINTR)) {
            err = AH_ENONE;
        }
    }

#ifndef NDEBUG
    conn->_fd = 0;
#endif
    conn->_shutdown_flags = AH_TCP_SHUTDOWN_RDWR;

    s_conn_read_stop(conn);

    conn->_cbs->on_close(conn, err);

    if (conn->_owning_slab != NULL) {
        ah_i_slab_free(conn->_owning_slab, conn);
    }

    return AH_ENONE;
}

ah_err_t ah_i_tcp_listener_listen(void* ctx, ah_tcp_listener_t* ln, unsigned backlog, const ah_tcp_conn_cbs_t* conn_cbs)
{
    (void) ctx;

    if (ln == NULL || conn_cbs == NULL) {
        return AH_EINVAL;
    }
    if (conn_cbs->on_read == NULL || conn_cbs->on_write == NULL || conn_cbs->on_close == NULL) {
        return AH_EINVAL;
    }
    if (ln->_state != AH_I_TCP_LISTENER_STATE_OPEN) {
        return AH_ESTATE;
    }

    ah_err_t err;

    if (ln->_AcceptEx == NULL) {
        err = ah_i_winapi_get_wsa_fn(ln->_fd, &(GUID) WSAID_ACCEPTEX, (void**) &ln->_AcceptEx);
        if (err != AH_ENONE) {
            return err;
        }
    }

    if (ln->_GetAcceptExSockaddrs == NULL) {
        err = ah_i_winapi_get_wsa_fn(ln->_fd, &(GUID) WSAID_GETACCEPTEXSOCKADDRS, (void**) &ln->_GetAcceptExSockaddrs);
        if (err != AH_ENONE) {
            return err;
        }
    }

    if (!ln->_is_listening) {
        int backlog_int = (backlog == 0u ? 16 : backlog <= SOMAXCONN ? (int) backlog
                                                                     : SOMAXCONN);
        if (listen(ln->_fd, backlog_int) != 0) {
            err = WSAGetLastError();
            goto report_err;
        }

        ln->_is_listening = true;
    }

#ifndef NDEBUG
    ln->_accept_fd = INVALID_SOCKET;
#endif
    ln->_conn_cbs = conn_cbs;
    ln->_state = AH_I_TCP_LISTENER_STATE_LISTENING;

    err = s_listener_accept_prep(ln);

    if (err != AH_ENONE) {
        ln->_state = AH_I_TCP_LISTENER_STATE_OPEN;
    }

report_err:
    ln->_cbs->on_listen(ln, err);

    return AH_ENONE;
}

static ah_err_t s_listener_accept_prep(ah_tcp_listener_t* ln)
{
    ah_assert_if_debug(ln != NULL);
    ah_assert_if_debug(ln->_state == AH_I_TCP_LISTENER_STATE_LISTENING);
    ah_assert_if_debug(ln->_is_listening);
    ah_assert_if_debug(ln->_accept_fd == INVALID_SOCKET);

    ah_err_t err;

    ah_i_loop_evt_t* evt;
    err = ah_i_loop_evt_alloc(ln->_loop, &evt);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_listener_accept;
    evt->_subject = ln;

    ah_i_sockfd_t accept_fd;
    err = ah_i_sock_open(ln->_loop, ln->_sockfamily, SOCK_STREAM, &accept_fd);
    if (err != AH_ENONE) {
        goto handle_err0;
    }

    const SOCKET fd = ln->_fd;
    const DWORD addr_size = AH_I_TCP_LISTENER_ACCEPT_BUFFER_ADDR_SIZE;
    DWORD b; // Unused but required.

    if (!ln->_AcceptEx(fd, accept_fd, ln->_accept_buffer, 0u, addr_size, addr_size, &b, &evt->_overlapped)) {
        err = WSAGetLastError();
        if (err != WSA_IO_PENDING) {
            goto handle_err1;
        }
    }

    ln->_accept_fd = accept_fd;

    return AH_ENONE;

handle_err1:
    (void) closesocket(accept_fd);

handle_err0:
    ah_i_loop_evt_dealloc(ln->_loop, evt);

    return err;
}

static void s_on_listener_accept(ah_i_loop_evt_t* evt)
{
    ah_assert_if_debug(evt != NULL);

    ah_tcp_listener_t* ln = evt->_subject;
    ah_assert_if_debug(ln != NULL);

    if (ln->_state != AH_I_TCP_LISTENER_STATE_LISTENING) {
        return;
    }

    ah_err_t err;

    ah_tcp_conn_t* conn = NULL;
    ah_sockaddr_t* raddr = NULL;

    DWORD n_bytes_transferred;
    err = ah_i_loop_evt_get_wsa_result(evt, ln->_fd, &n_bytes_transferred);
    if (err != AH_ENONE) {
        goto handle_err;
    }

    err = ah_i_sock_setsockopt(ln->_accept_fd, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, &ln->_fd, sizeof(ln->_fd));
    if (err != AH_ENONE) {
        goto handle_err;
    }

    conn = ah_i_slab_alloc(&ln->_conn_slab);
    if (conn == NULL) {
        err = AH_ENOMEM;
        goto handle_err;
    }

    *conn = (ah_tcp_conn_t) {
        ._loop = ln->_loop,
        ._trans = ln->_trans,
        ._owning_slab = &ln->_conn_slab,
        ._cbs = ln->_conn_cbs,
        ._state = AH_I_TCP_CONN_STATE_CONNECTED,
        ._fd = ln->_accept_fd,
    };

#ifndef NDEBUG
    ln->_accept_fd = INVALID_SOCKET;
#endif

    const DWORD addr_size = AH_I_TCP_LISTENER_ACCEPT_BUFFER_ADDR_SIZE;
    struct sockaddr *laddr_bsd, *raddr_bsd;
    INT laddr_size, raddr_size;
    ln->_GetAcceptExSockaddrs(ln->_accept_buffer, 0u, addr_size, addr_size, &laddr_bsd, &laddr_size, &raddr_bsd, &raddr_size);

    raddr = ah_i_sockaddr_from_bsd(raddr_bsd);

prep_another_accept:
    ln->_cbs->on_accept(ln, conn, raddr, err);

    if (ah_tcp_listener_is_closed(ln)) {
        return;
    }

    err = s_listener_accept_prep(ln);
    if (err != AH_ENONE && err != AH_ECANCELED) {
        ln->_cbs->on_listen(ln, err);
    }

    return;

handle_err:
    (void) closesocket(ln->_accept_fd);

#ifndef NDEBUG
    ln->_accept_fd = INVALID_SOCKET;
#endif

    goto prep_another_accept;
}

ah_err_t ah_i_tcp_listener_close(void* ctx, ah_tcp_listener_t* ln)
{
    (void) ctx;

    if (ln == NULL) {
        return AH_EINVAL;
    }
    if (ln->_state == AH_I_TCP_LISTENER_STATE_CLOSED) {
        return AH_ESTATE;
    }
#ifndef NDEBUG
    if (ln->_fd == 0) {
        return AH_ESTATE;
    }
#endif
    ln->_state = AH_I_TCP_LISTENER_STATE_CLOSED;

    ah_err_t err = ah_i_sock_close(ln->_fd);
    if (err == AH_EINTR) {
        if (ah_i_loop_try_set_pending_err(ln->_loop, AH_EINTR)) {
            err = AH_ENONE;
        }
    }

#ifndef NDEBUG
    ln->_fd = 0;
#endif

    ln->_cbs->on_close(ln, err);

    return AH_ENONE;
}
