// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/tcp.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/internal/collections/list.h"
#include "ah/loop.h"
#include "ah/sock.h"
#include "tcp-in.h"

#include <sys/uio.h>

static void s_on_conn_connect(ah_i_loop_evt_t* evt, struct kevent* kev);
static void s_on_conn_read(ah_i_loop_evt_t* evt, struct kevent* kev);
static void s_on_conn_write(ah_i_loop_evt_t* evt, struct kevent* kev);

static void s_on_listener_accept(ah_i_loop_evt_t* evt, struct kevent* kev);

static ah_err_t s_conn_write_prep(ah_tcp_conn_t* conn);

ah_err_t ah_i_tcp_conn_connect(void* ctx, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr)
{
    (void) ctx;

    if (conn == NULL || raddr == NULL || !ah_sockaddr_is_ip(raddr)) {
        return AH_EINVAL;
    }
    if (conn->_state != AH_I_TCP_CONN_STATE_OPEN) {
        return AH_ESTATE;
    }

    ah_i_loop_evt_t* evt;
    struct kevent* kev;

    ah_err_t err = ah_i_loop_evt_alloc_with_kev(conn->_loop, &evt, &kev);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_conn_connect;
    evt->_subject = conn;

    conn->_state = AH_I_TCP_CONN_STATE_CONNECTING;

    EV_SET(kev, conn->_fd, EVFILT_WRITE, EV_ADD | EV_ONESHOT, 0u, 0u, evt);

    if (connect(conn->_fd, ah_i_sockaddr_const_into_bsd(raddr), ah_i_sockaddr_get_size(raddr)) != 0) {
        if (errno == EINPROGRESS) {
            return AH_ENONE;
        }
        kev->flags |= EV_ERROR;
        kev->data = errno;
    }

    s_on_conn_connect(evt, kev);

    return AH_ENONE;
}

static void s_on_conn_connect(ah_i_loop_evt_t* evt, struct kevent* kev)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(kev != NULL);

    ah_tcp_conn_t* conn = evt->_subject;
    ah_assert_if_debug(conn != NULL);

    ah_err_t err;

    if (ah_unlikely((kev->flags & EV_ERROR) != 0)) {
        err = (ah_err_t) kev->data;
        conn->_state = AH_I_TCP_CONN_STATE_OPEN;
    }
    else if (ah_unlikely((kev->flags & EV_EOF) != 0)) {
        conn->_state = AH_I_TCP_CONN_STATE_OPEN;
        err = kev->fflags != 0 ? (ah_err_t) kev->fflags : AH_EEOF;
    }
    else {
        conn->_state = AH_I_TCP_CONN_STATE_CONNECTED;

        ah_tcp_shutdown_t shutdown_flags = 0u;

        if (conn->_cbs->on_read == NULL) {
            shutdown_flags |= AH_TCP_SHUTDOWN_RD;
        }
        if (conn->_cbs->on_write == NULL) {
            shutdown_flags |= AH_TCP_SHUTDOWN_WR;
        }
        if (shutdown_flags != 0) {
            err = ah_tcp_conn_shutdown(conn, shutdown_flags);
        }
        else {
            err = AH_ENONE;
        }
    }

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

    err = ah_i_tcp_in_alloc_for(&conn->_in);
    if (err != AH_ENONE) {
        return err;
    }

    ah_i_loop_evt_t* evt;
    struct kevent* kev;

    err = ah_i_loop_evt_alloc_with_kev(conn->_loop, &evt, &kev);
    if (err != AH_ENONE) {
        ah_i_tcp_in_free(conn->_in);
        return err;
    }

    evt->_cb = s_on_conn_read;
    evt->_subject = conn;

    EV_SET(kev, conn->_fd, EVFILT_READ, EV_ADD, 0u, 0, evt);
    conn->_read_evt = evt;

    conn->_state = AH_I_TCP_CONN_STATE_READING;

    return AH_ENONE;
}

static void s_on_conn_read(ah_i_loop_evt_t* evt, struct kevent* kev)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(kev != NULL);

    ah_tcp_conn_t* conn = evt->_subject;
    ah_assert_if_debug(conn != NULL);

    if (conn->_state != AH_I_TCP_CONN_STATE_READING) {
        return;
    }

    ah_err_t err;

    if (ah_unlikely((kev->flags & EV_ERROR) != 0)) {
        err = (ah_err_t) kev->data;
        goto report_err;
    }

    size_t n_bytes_left = kev->data;

    while (n_bytes_left != 0u) {
        ah_buf_t dst = ah_rw_get_writable_as_buf(&conn->_in->rw);
        if (ah_buf_is_empty(&dst)) {
            err = AH_EOVERFLOW;
            goto report_err;
        }

        ssize_t nread = recv(conn->_fd, ah_buf_get_base(&dst), ah_buf_get_size(&dst), 0u);
        if (nread < 0) {
            err = errno;
            goto report_err;
        }
        if (nread == 0) {
            break;
        }
        conn->_in->rw.w = &conn->_in->rw.w[(size_t) nread];
        ah_assert_if_debug(conn->_in->rw.w <= conn->_in->rw.e);

        if (ah_unlikely(ah_buf_get_size(&dst) < (size_t) nread)) {
            err = AH_EDOM;
            goto report_err;
        }

        conn->_cbs->on_read(conn, conn->_in, AH_ENONE);

        if (!ah_rw_is_readable(&conn->_in->rw)) {
            ah_i_tcp_in_reset(conn->_in);
        }

        if (conn->_state != AH_I_TCP_CONN_STATE_READING) {
            return;
        }

        n_bytes_left -= (size_t) nread;
    }

    if (ah_unlikely((kev->flags & EV_EOF) != 0)) {
        err = kev->fflags != 0u ? (ah_err_t) kev->fflags : AH_EEOF;
        conn->_shutdown_flags |= AH_TCP_SHUTDOWN_RD;
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
        return conn->_state == AH_I_TCP_CONN_STATE_CONNECTED ? AH_ESTATE : AH_ENONE;
    }
    conn->_state = AH_I_TCP_CONN_STATE_CONNECTED;

    if (conn->_in != NULL) {
        ah_i_tcp_in_free(conn->_in);
        conn->_in = NULL;
    }

    struct kevent* kev;
    if (ah_i_loop_alloc_kev(conn->_loop, &kev) == AH_ENONE) {
        EV_SET(kev, conn->_fd, EVFILT_READ, EV_DELETE, 0, 0u, NULL);
    }

    return AH_ENONE;
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

    out->_buf_offset = 0u;

    const bool is_preparing_another_write = ah_i_list_is_empty(&conn->_out_queue);

    ah_i_list_push(&conn->_out_queue, out, offsetof(ah_tcp_out_t, _list_entry));

    if (is_preparing_another_write) {
        return s_conn_write_prep(conn);
    }

    return AH_ENONE;
}

static ah_err_t s_conn_write_prep(ah_tcp_conn_t* conn)
{
    ah_assert_if_debug(conn != NULL);

    ah_i_loop_evt_t* evt;
    struct kevent* kev;

    ah_err_t err = ah_i_loop_evt_alloc_with_kev(conn->_loop, &evt, &kev);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_conn_write;
    evt->_subject = conn;

    EV_SET(kev, conn->_fd, EVFILT_WRITE, EV_ADD | EV_ONESHOT, 0u, 0, evt);

    return AH_ENONE;
}

static void s_on_conn_write(ah_i_loop_evt_t* evt, struct kevent* kev)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(kev != NULL);

    ah_tcp_conn_t* conn = evt->_subject;
    ah_assert_if_debug(conn != NULL);

    if (conn->_state < AH_I_TCP_CONN_STATE_CONNECTED) {
        return;
    }

    ah_err_t err;

    ah_tcp_out_t* out = ah_i_list_peek(&conn->_out_queue, offsetof(ah_tcp_out_t, _list_entry));

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
        conn->_shutdown_flags |= AH_TCP_SHUTDOWN_WR;
        goto report_err_and_prep_next;
    }

    if (out->_buf_offset > ah_buf_get_size(&out->buf)) {
        err = AH_EINTERN;
        goto report_err_and_prep_next;
    }

    void* buffer = &ah_buf_get_base(&out->buf)[out->_buf_offset];
    size_t length = ah_buf_get_size(&out->buf) - out->_buf_offset;

    ssize_t res = send(conn->_fd, buffer, length, 0);
    if (ah_unlikely(res < 0)) {
        err = errno;
        goto report_err_and_prep_next;
    }

    if (((size_t) res) < ah_buf_get_size(&out->buf)) {
        ((ah_tcp_out_t*) out)->_buf_offset = (size_t) res;
        goto prep_next;
    }

    err = AH_ENONE;

report_err_and_prep_next:
    ah_i_list_skip(&conn->_out_queue);
    conn->_cbs->on_write(conn, out, err);

    if (conn->_state < AH_I_TCP_CONN_STATE_CONNECTED) {
        return;
    }
    if (ah_i_list_is_empty(&conn->_out_queue)) {
        return;
    }

prep_next:
    err = s_conn_write_prep(conn);
    if (err != AH_ENONE) {
        goto report_err_and_prep_next;
    }
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

    if (conn->_read_evt != NULL) {
        ah_i_loop_evt_dealloc(conn->_loop, conn->_read_evt);
    }

#ifndef NDEBUG
    conn->_fd = 0;
#endif

    if (conn->_in != NULL) {
        ah_i_tcp_in_free(conn->_in);
    }

    conn->_cbs->on_close(conn, err);

    return AH_ENONE;
}

ah_err_t ah_i_tcp_listener_listen(void* ctx, ah_tcp_listener_t* ln, unsigned backlog, const ah_tcp_conn_cbs_t* conn_cbs)
{
    (void) ctx;

    if (ln == NULL || conn_cbs == NULL) {
        return AH_EINVAL;
    }
    if (conn_cbs->on_close == NULL || conn_cbs->on_read == NULL || conn_cbs->on_write == NULL) {
        return AH_EINVAL;
    }
    if (ln->_state != AH_I_TCP_LISTENER_STATE_OPEN) {
        return AH_ESTATE;
    }

    ah_err_t err;

    int backlog_int = (backlog == 0u ? 16 : backlog <= SOMAXCONN ? (int) backlog
                                                                 : SOMAXCONN);
    if (listen(ln->_fd, backlog_int) != 0) {
        err = errno;
        ln->_cbs->on_listen(ln, err);
        return AH_ENONE;
    }

    ah_i_loop_evt_t* evt;
    struct kevent* kev;

    err = ah_i_loop_evt_alloc_with_kev(ln->_loop, &evt, &kev);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_listener_accept;
    evt->_subject = ln;

    EV_SET(kev, ln->_fd, EVFILT_READ, EV_ADD, 0u, 0, evt);

    ln->_conn_cbs = conn_cbs;
    ln->_listen_evt = evt;
    ln->_state = AH_I_TCP_LISTENER_STATE_LISTENING;
    ln->_cbs->on_listen(ln, AH_ENONE);

    return AH_ENONE;
}

static void s_on_listener_accept(ah_i_loop_evt_t* evt, struct kevent* kev)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(kev != NULL);

    ah_tcp_listener_t* ln = evt->_subject;
    ah_assert_if_debug(ln != NULL);

    if (ah_unlikely((kev->flags & EV_ERROR) != 0)) {
        ln->_cbs->on_listen(ln, (ah_err_t) kev->data);
        return;
    }

    for (int64_t i = 0; i < kev->data; i += 1) {
        ah_tcp_conn_t* conn = ah_i_slab_alloc(&ln->_conn_slab);
        if (conn == NULL) {
            ln->_cbs->on_accept(ln, NULL, NULL, AH_ENOMEM);
            continue;
        }

        ah_sockaddr_t sockaddr;
        socklen_t socklen = sizeof(ah_sockaddr_t);

        const int fd = accept(ln->_fd, ah_i_sockaddr_into_bsd(&sockaddr), &socklen);
        if (fd == -1) {
            ln->_cbs->on_accept(ln, NULL, NULL, errno);
            continue;
        }

#if AH_I_SOCKADDR_HAS_SIZE
        ah_assert_if_debug(socklen <= UINT8_MAX);
        sockaddr.as_any.size = socklen;
#endif

        *conn = (ah_tcp_conn_t) {
            ._loop = ln->_loop,
            ._trans = ln->_trans,
            ._owning_slab = &ln->_conn_slab,
            ._cbs = ln->_conn_cbs,
            ._state = AH_I_TCP_CONN_STATE_CONNECTED,
            ._fd = fd,
        };

        ln->_cbs->on_accept(ln, conn, &sockaddr, AH_ENONE);
    }

    if (ah_unlikely((kev->flags & EV_EOF) != 0)) {
        ln->_cbs->on_listen(ln, (ah_err_t) kev->fflags != 0 ? (ah_err_t) kev->fflags : AH_EEOF);
    }
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

    if (ln->_listen_evt != NULL) {
        ah_i_loop_evt_dealloc(ln->_loop, ln->_listen_evt);
    }

#ifndef NDEBUG
    ln->_fd = 0;
#endif

    ln->_cbs->on_close(ln, err);

    return AH_ENONE;
}
