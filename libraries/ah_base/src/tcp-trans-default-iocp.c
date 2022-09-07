// SPDX-License-Identifier: EPL-2.0

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"
#include "ah/sock.h"
#include "ah/tcp.h"
#include "winapi.h"

#include <stddef.h>

static void s_conn_on_connect(ah_i_loop_evt_t* evt);
static void s_conn_on_read(ah_i_loop_evt_t* evt);
static void s_conn_on_write(ah_i_loop_evt_t* evt);

static void s_listener_on_accept(ah_i_loop_evt_t* evt);

static ah_err_t s_conn_read_prep(ah_tcp_conn_t* conn);
static void s_conn_read_stop(ah_tcp_conn_t* conn);
static ah_err_t s_conn_ref(ah_tcp_conn_t* conn);
static void s_conn_unref(ah_tcp_conn_t* conn);

static ah_err_t s_listener_accept_prep(ah_tcp_listener_t* ln);
static ah_err_t s_listener_ref(ah_tcp_listener_t* ln);
static void s_listener_unref(ah_tcp_listener_t* ln);

#pragma warning(disable : 6011)
ah_err_t ah_i_tcp_trans_default_conn_connect(void* ctx, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr)
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

    evt->_cb = s_conn_on_connect;
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

static void s_conn_on_connect(ah_i_loop_evt_t* evt)
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
    conn->_obs.cbs->on_connect(conn->_obs.ctx, conn, err);
}

ah_err_t ah_i_tcp_trans_default_conn_read_start(void* ctx, ah_tcp_conn_t* conn)
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

    evt->_cb = s_conn_on_read;
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

static void s_conn_on_read(ah_i_loop_evt_t* evt)
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

    err = s_conn_ref(conn);
    if (err != AH_ENONE) {
        goto report_err;
    }

    conn->_obs.cbs->on_read(conn->_obs.ctx, conn, conn->_in, AH_ENONE);
    conn->_recv_buf = (ah_buf_t) { 0u };

    uint8_t state = conn->_state;

    s_conn_unref(conn);

    if (state != AH_I_TCP_CONN_STATE_READING) {
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
    conn->_obs.cbs->on_read(conn->_obs.ctx, conn, NULL, err);
}

static ah_err_t s_conn_ref(ah_tcp_conn_t* conn)
{
    if (conn == NULL) {
        return AH_EINTERN;
    }
    return ah_add_uint32(conn->_ref_count, 1u, &conn->_ref_count);
}

static void s_conn_unref(ah_tcp_conn_t* conn)
{
    if (conn->_ref_count != 0u) {
        conn->_ref_count -= 1u;
        return;
    }

    ah_assert_if_debug(conn->_state == AH_I_TCP_CONN_STATE_CLOSING);

    ah_err_t err = ah_i_sock_close(conn->_fd);
    if (err == AH_EINTR) {
        if (ah_i_loop_try_set_pending_err(conn->_loop, AH_EINTR)) {
            err = AH_ENONE;
        }
    }

    conn->_shutdown_flags = AH_TCP_SHUTDOWN_RDWR;
    conn->_state = AH_I_TCP_CONN_STATE_CLOSED;
    conn->_fd = INVALID_SOCKET;

    s_conn_read_stop(conn);

    conn->_obs.cbs->on_close(conn->_obs.ctx, conn, err);
}

static void s_conn_read_stop(ah_tcp_conn_t* conn)
{
    ah_assert_if_debug(conn != NULL);

    if (conn->_in != NULL) {
        ah_tcp_in_free(conn->_in);
        conn->_in = NULL;
    }
}

ah_err_t ah_i_tcp_trans_default_conn_read_stop(void* ctx, ah_tcp_conn_t* conn)
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

ah_err_t ah_i_tcp_trans_default_conn_write(void* ctx, ah_tcp_conn_t* conn, ah_tcp_out_t* out)
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

    evt->_cb = s_conn_on_write;
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

static void s_conn_on_write(ah_i_loop_evt_t* evt)
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

    conn->_obs.cbs->on_write(conn->_obs.ctx, conn, out, err);
}

ah_err_t ah_i_tcp_trans_default_conn_close(void* ctx, ah_tcp_conn_t* conn)
{
    (void) ctx;

    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_state == AH_I_TCP_CONN_STATE_CLOSED) {
        return AH_ESTATE;
    }
    if (conn->_fd == INVALID_SOCKET) {
        return AH_EINTERN;
    }
    conn->_state = AH_I_TCP_CONN_STATE_CLOSING;

    s_conn_unref(conn);

    return AH_ENONE;
}

ah_err_t ah_i_tcp_trans_default_listener_listen(void* ctx, ah_tcp_listener_t* ln, unsigned backlog)
{
    (void) ctx;

    if (ln == NULL) {
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

    ln->_state = AH_I_TCP_LISTENER_STATE_LISTENING;
    ln->_accept_fd = INVALID_SOCKET;

    err = s_listener_accept_prep(ln);

    if (err != AH_ENONE) {
        ln->_state = AH_I_TCP_LISTENER_STATE_OPEN;
    }

report_err:
    ln->_obs.cbs->on_listen(ln->_obs.ctx, ln, err);

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

    evt->_cb = s_listener_on_accept;
    evt->_subject = ln;

    ah_i_sockfd_t accept_fd;
    err = ah_i_sock_open(ln->_loop, ln->_sock_family, SOCK_STREAM, &accept_fd);
    if (err != AH_ENONE) {
        goto dealloc_evt_and_return_err;
    }

    const SOCKET fd = ln->_fd;
    const DWORD addr_size = AH_I_TCP_LISTENER_ACCEPT_BUFFER_ADDR_SIZE;
    DWORD b; // Unused but required.

    if (!ln->_AcceptEx(fd, accept_fd, ln->_accept_buffer, 0u, addr_size, addr_size, &b, &evt->_overlapped)) {
        err = WSAGetLastError();
        if (err != WSA_IO_PENDING) {
            goto close_socket_dealloc_evt_and_return_err;
        }
    }

    ln->_accept_fd = accept_fd;

    return AH_ENONE;

close_socket_dealloc_evt_and_return_err:
    (void) closesocket(accept_fd);

dealloc_evt_and_return_err:
    ah_i_loop_evt_dealloc(ln->_loop, evt);

    return err;
}

static void s_listener_on_accept(ah_i_loop_evt_t* evt)
{
    ah_assert_if_debug(evt != NULL);

    ah_tcp_listener_t* ln = evt->_subject;
    ah_assert_if_debug(ln != NULL);

    if (ln->_state != AH_I_TCP_LISTENER_STATE_LISTENING) {
        return;
    }

    ah_err_t err;
    ah_err_t err_major = AH_ENONE;

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

    (void) memset(conn, 0, sizeof(*conn));

    err = ln->_trans.vtab->listener_prepare(ln->_trans.ctx, ln, &conn->_trans);
    if (err != AH_ENONE) {
        ah_i_slab_free(&ln->_conn_slab, conn);
        goto handle_err;
    }

    if (!ah_tcp_trans_vtab_is_valid(conn->_trans.vtab)) {
        err = AH_ESTATE;
        goto handle_err;
    }

    const DWORD addr_size = AH_I_TCP_LISTENER_ACCEPT_BUFFER_ADDR_SIZE;
    struct sockaddr *laddr_bsd, *raddr_bsd;
    INT laddr_size, raddr_size;
    ln->_GetAcceptExSockaddrs(ln->_accept_buffer, 0u, addr_size, addr_size, &laddr_bsd, &laddr_size, &raddr_bsd, &raddr_size);

    raddr = ah_i_sockaddr_from_bsd(raddr_bsd);

    conn->_loop = ln->_loop;
    conn->_owning_slab = &ln->_conn_slab;
    conn->_sock_family = ln->_sock_family;
    conn->_state = AH_I_TCP_CONN_STATE_CONNECTED;
    conn->_fd = ln->_accept_fd;

    ln->_accept_fd = INVALID_SOCKET;

    ah_tcp_accept_t accept = {
        .ctx = conn->_trans.ctx,
        .conn = conn,
        .obs = &conn->_obs,
        .raddr = raddr,
    };
    ah_tcp_accept_t* accept_ptr = &accept;

report_err_and_prep_new_accept:
    err_major = s_listener_ref(ln);
    if (err_major != AH_ENONE) {
        goto handle_err;
    }

    ln->_obs.cbs->on_accept(ln->_obs.ctx, ln, accept_ptr, err);

    uint8_t state = ln->_state;

    s_listener_unref(ln);

    if (state != AH_I_TCP_LISTENER_STATE_LISTENING) {
        return;
    }

    err = s_listener_accept_prep(ln);
    if (err != AH_ENONE && err != AH_ECANCELED) {
        err_major = err;
        goto handle_err;
    }

    return;

handle_err:
    (void) closesocket(ln->_accept_fd);
    ln->_accept_fd = INVALID_SOCKET;

    if (err_major != AH_ENONE) {
        ln->_obs.cbs->on_accept(ln->_obs.ctx, ln, NULL, err_major);
        return;
    }

    accept_ptr = NULL;

    goto report_err_and_prep_new_accept;
}

static ah_err_t s_listener_ref(ah_tcp_listener_t* ln)
{
    if (ln == NULL) {
        return AH_EINTERN;
    }
    return ah_add_uint32(ln->_ref_count, 1u, &ln->_ref_count);
}

static void s_listener_unref(ah_tcp_listener_t* ln)
{
    if (ln->_ref_count != 0u) {
        ln->_ref_count -= 1u;
        return;
    }

    ah_assert_if_debug(ln->_state == AH_I_TCP_LISTENER_STATE_CLOSING);

    ah_err_t err = ah_i_sock_close(ln->_fd);
    if (err == AH_EINTR) {
        if (ah_i_loop_try_set_pending_err(ln->_loop, AH_EINTR)) {
            err = AH_ENONE;
        }
    }

    ln->_state = AH_I_TCP_LISTENER_STATE_CLOSED;
    ln->_fd = INVALID_SOCKET;

    ln->_obs.cbs->on_close(ln->_obs.ctx, ln, err);
}

ah_err_t ah_i_tcp_trans_default_listener_close(void* ctx, ah_tcp_listener_t* ln)
{
    (void) ctx;

    if (ln == NULL) {
        return AH_EINVAL;
    }
    if (ln->_state == AH_I_TCP_LISTENER_STATE_CLOSED) {
        return AH_ESTATE;
    }
    if (ln->_fd == INVALID_SOCKET) {
        return AH_EINTERN;
    }
    ln->_state = AH_I_TCP_LISTENER_STATE_CLOSING;

    s_listener_unref(ln);

    return AH_ENONE;
}
