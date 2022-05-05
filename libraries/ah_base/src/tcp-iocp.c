// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/tcp.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"
#include "winapi.h"

#include <stddef.h>

static void s_on_conn_connect(ah_i_loop_evt_t* evt);
static void s_on_conn_read(ah_i_loop_evt_t* evt);
static void s_on_conn_write(ah_i_loop_evt_t* evt);

static void s_on_listener_accept(ah_i_loop_evt_t* evt);

static ah_err_t s_prep_listener_accept(ah_tcp_listener_t* ln);
static ah_err_t s_prep_conn_read(ah_tcp_conn_t* conn);
static ah_err_t s_prep_conn_write(ah_tcp_conn_t* conn);

ah_extern ah_err_t ah_tcp_omsg_init(ah_tcp_omsg_t* omsg, ah_bufs_t bufs)
{
    if (omsg == NULL || (bufs.items == NULL && bufs.length != 0u)) {
        return AH_EINVAL;
    }

    WSABUF* buffers;
    ULONG buffer_count;

    ah_err_t err = ah_i_bufs_into_wsabufs(&bufs, &buffers, &buffer_count);
    if (err != AH_ENONE) {
        return err;
    }

    *omsg = (ah_tcp_omsg_t) {
        ._next = NULL,
        ._buffers = buffers,
        ._buffer_count = buffer_count,
    };

    return AH_ENONE;
}

ah_extern ah_bufs_t ah_tcp_omsg_get_bufs(ah_tcp_omsg_t* omsg)
{
    ah_assert_if_debug(omsg != NULL);

    ah_bufs_t bufs;
    ah_i_bufs_from_wsabufs(&bufs, omsg->_buffers, omsg->_buffer_count);

    return bufs;
}

ah_extern ah_err_t ah_tcp_conn_connect(ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr)
{
    if (conn == NULL || raddr == NULL || !ah_sockaddr_is_ip(raddr)) {
        return AH_EINVAL;
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
    DWORD flags;
    if (!WSAGetOverlappedResult(conn->_fd, &evt->_overlapped, &n_bytes_transferred, false, &flags)) {
        conn->_state = AH_I_TCP_CONN_STATE_OPEN;
        err = WSAGetLastError();
    }
    else {
        conn->_state = AH_I_TCP_CONN_STATE_CONNECTED;

        ah_tcp_shutdown_t shutdown_flags = 0u;

        if (conn->_vtab->on_read_data == NULL) {
            shutdown_flags |= AH_TCP_SHUTDOWN_RD;
        }
        if (conn->_vtab->on_write_done == NULL) {
            shutdown_flags |= AH_TCP_SHUTDOWN_WR;
        }
        err = ah_tcp_conn_shutdown(conn, shutdown_flags);
    }

    conn->_vtab->on_connect(conn, err);
}

ah_extern ah_err_t ah_tcp_conn_read_start(ah_tcp_conn_t* conn)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state != AH_I_TCP_CONN_STATE_CONNECTED || (conn->_shutdown_flags & AH_TCP_SHUTDOWN_RD) != 0) {
        return AH_ESTATE;
    }

    ah_err_t err = s_prep_conn_read(conn);
    if (err != AH_ENONE) {
        return err;
    }

    conn->_state = AH_I_TCP_CONN_STATE_READING;

    return AH_ENONE;
}

static ah_err_t s_prep_conn_read(ah_tcp_conn_t* conn)
{
    ah_assert_if_debug(conn != NULL);

    ah_i_loop_evt_t* evt;

    ah_err_t err = ah_i_loop_evt_alloc(conn->_loop, &evt);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_conn_read;
    evt->_subject = conn;

    conn->_recv_buf = (ah_buf_t) { 0u };
    conn->_vtab->on_read_alloc(conn, &conn->_recv_buf);

    if (conn->_state != AH_I_TCP_CONN_STATE_READING) {
        return AH_ENONE;
    }

    if (ah_buf_is_empty(&conn->_recv_buf)) {
        return AH_ENOBUFS;
    }

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
    DWORD flags;
    if (!WSAGetOverlappedResult(conn->_fd, &evt->_overlapped, &nread, false, &flags)) {
        err = WSAGetLastError();
        goto handle_err;
    }

    conn->_vtab->on_read_data(conn, &conn->_recv_buf, (size_t) nread);
#ifndef NDEBUG
    conn->_recv_buf = (ah_buf_t) { 0u };
#endif

    if (conn->_state != AH_I_TCP_CONN_STATE_READING) {
        return;
    }

    err = s_prep_conn_read(conn);
    if (err != AH_ENONE) {
        goto handle_err;
    }

    return;

handle_err:
    conn->_vtab->on_read_err(conn, err);
}

ah_extern ah_err_t ah_tcp_conn_read_stop(ah_tcp_conn_t* conn)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state != AH_I_TCP_CONN_STATE_READING) {
        return conn->_state == AH_I_TCP_CONN_STATE_CONNECTED ? AH_ESTATE : AH_ENONE;
    }

    conn->_state = AH_I_TCP_CONN_STATE_CONNECTED;

    return AH_ENONE;
}

ah_extern ah_err_t ah_tcp_conn_write(ah_tcp_conn_t* conn, ah_tcp_omsg_t* omsg)
{
    if (conn == NULL || omsg == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state < AH_I_TCP_CONN_STATE_CONNECTED || (conn->_shutdown_flags & AH_TCP_SHUTDOWN_WR) != 0) {
        return AH_ESTATE;
    }

    if (conn->_write_queue_head != NULL) {
        conn->_write_queue_end->_next = omsg;
        conn->_write_queue_end = omsg;
        return AH_ENONE;
    }

    conn->_write_queue_head = omsg;
    conn->_write_queue_end = omsg;

    return s_prep_conn_write(conn);
}

static ah_err_t s_prep_conn_write(ah_tcp_conn_t* conn)
{
    ah_i_loop_evt_t* evt;

    ah_err_t err = ah_i_loop_evt_alloc(conn->_loop, &evt);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_conn_write;
    evt->_subject = conn;

    ah_tcp_omsg_t* omsg = conn->_write_queue_head;
    ah_assert_if_debug(omsg != NULL);

    int res = WSASend(conn->_fd, omsg->_buffers, omsg->_buffer_count, NULL, 0u, &evt->_overlapped, NULL);
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

    ah_tcp_conn_t* conn = evt->_subject;
    ah_assert_if_debug(conn != NULL);
    ah_assert_if_debug(conn->_write_queue_head != NULL);

    if (conn->_state < AH_I_TCP_CONN_STATE_CONNECTED) {
        return;
    }

    ah_err_t err;

    DWORD n_bytes_transferred;
    DWORD flags;
    if (!WSAGetOverlappedResult(conn->_fd, &evt->_overlapped, &n_bytes_transferred, false, &flags)) {
        err = WSAGetLastError();
    }
    else {
        err = AH_ENONE;
    }

report_err_and_prep_next:
    conn->_write_queue_head = conn->_write_queue_head->_next;
    conn->_vtab->on_write_done(conn, err);

    if (conn->_state < AH_I_TCP_CONN_STATE_CONNECTED) {
        return;
    }
    if (conn->_write_queue_head == NULL) {
        return;
    }

    err = s_prep_conn_write(conn);
    if (err != AH_ENONE) {
        goto report_err_and_prep_next;
    }
}

ah_extern ah_err_t ah_tcp_conn_close(ah_tcp_conn_t* conn)
{
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

    conn->_vtab->on_close(conn, err);

    return AH_ENONE;
}

ah_extern ah_err_t ah_tcp_listener_listen(ah_tcp_listener_t* ln, unsigned backlog, const ah_tcp_conn_vtab_t* conn_vtab)
{
    if (ln == NULL || conn_vtab == NULL) {
        return AH_EINVAL;
    }
    if (conn_vtab->on_close == NULL) {
        return AH_EINVAL;
    }
    if (conn_vtab->on_read_alloc == NULL || conn_vtab->on_read_data == NULL || conn_vtab->on_read_err == NULL) {
        return AH_EINVAL;
    }
    if (conn_vtab->on_write_done == NULL) {
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
        int backlog_int = (backlog == 0u ? 16 : backlog <= SOMAXCONN ? (int) backlog : SOMAXCONN);
        if (listen(ln->_fd, backlog_int) != 0) {
            err = WSAGetLastError();
            goto handle_err;
        }
        ln->_is_listening = true;
    }

    ln->_conn_vtab = conn_vtab;
    ln->_state = AH_I_TCP_LISTENER_STATE_LISTENING;

#ifndef NDEBUG
    ln->_accept_fd = INVALID_SOCKET;
#endif

    err = s_prep_listener_accept(ln);

    if (err != AH_ENONE) {
        ln->_state = AH_I_TCP_LISTENER_STATE_OPEN;
    }

handle_err:
    ln->_vtab->on_listen(ln, err);

    return AH_ENONE;
}

static ah_err_t s_prep_listener_accept(ah_tcp_listener_t* ln)
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
        goto dealloc_evt_and_report_err;
    }

    const SOCKET fd = ln->_fd;
    const DWORD addr_size = AH_I_TCP_LISTENER_ACCEPT_BUFFER_ADDR_SIZE;
    DWORD b; // Unused but required.

    if (!ln->_AcceptEx(fd, accept_fd, ln->_accept_buffer, 0u, addr_size, addr_size, &b, &evt->_overlapped)) {
        err = WSAGetLastError();
        if (err != WSA_IO_PENDING) {
            goto close_accept_fd_dealloc_evt_and_report_err;
        }
    }

    ln->_accept_fd = accept_fd;

    return AH_ENONE;

close_accept_fd_dealloc_evt_and_report_err:
    (void) closesocket(accept_fd);

dealloc_evt_and_report_err:
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

    DWORD n_bytes_transferred;
    DWORD flags;
    if (!WSAGetOverlappedResult(ln->_fd, &evt->_overlapped, &n_bytes_transferred, false, &flags)) {
        err = WSAGetLastError();
        goto handle_err;
    }

    ah_tcp_conn_t* conn = NULL;
    ln->_vtab->on_conn_alloc(ln, &conn);
    if (conn == NULL) {
        err = AH_ENOBUFS;
        goto handle_err;
    }

    *conn = (ah_tcp_conn_t) {
        ._loop = ln->_loop,
        ._vtab = ln->_conn_vtab,
        ._state = AH_I_TCP_CONN_STATE_CONNECTED,
        ._fd = ln->_accept_fd,
    };

#ifndef NDEBUG
    ln->_accept_fd = INVALID_SOCKET;
#endif

    const DWORD addr_size = AH_I_TCP_LISTENER_ACCEPT_BUFFER_ADDR_SIZE;

    struct sockaddr* laddr;
    INT laddr_size;

    struct sockaddr* raddr = NULL;
    INT raddr_size;

    ln->_GetAcceptExSockaddrs(ln->_accept_buffer, 0u, addr_size, addr_size, &laddr, &laddr_size, &raddr, &raddr_size);
    ln->_vtab->on_conn_accept(ln, conn, ah_i_sockaddr_from_bsd(raddr));

    if (ln->_state != AH_I_TCP_LISTENER_STATE_LISTENING) {
        return;
    }

prep_another_accept:

    err = s_prep_listener_accept(ln);
    if (err != AH_ENONE) {
        ah_i_tcp_listener_force_close_with_err(ln, err);
    }

    return;

handle_err:
    (void) closesocket(ln->_accept_fd);

#ifndef NDEBUG
    ln->_accept_fd = INVALID_SOCKET;
#endif

    ln->_vtab->on_conn_err(ln, err);
    goto prep_another_accept;
}

ah_extern ah_err_t ah_tcp_listener_close(ah_tcp_listener_t* ln)
{
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

    ln->_vtab->on_close(ln, err);

    return AH_ENONE;
}
