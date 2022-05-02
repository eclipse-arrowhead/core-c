// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/tcp.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"

#include <sys/uio.h>

static void s_on_conn_connect(ah_i_loop_evt_t* evt, struct kevent* kev);
static void s_on_conn_read(ah_i_loop_evt_t* evt, struct kevent* kev);
static void s_on_conn_write(ah_i_loop_evt_t* evt, struct kevent* kev);

static void s_on_listener_accept(ah_i_loop_evt_t* evt, struct kevent* kev);

static ah_err_t s_prep_conn_write(ah_tcp_conn_t* conn);

ah_extern ah_err_t ah_tcp_conn_connect(ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr)
{
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
        err = kev->fflags != 0 ? (ah_err_t) kev->fflags : AH_EEOF;
        conn->_state = AH_I_TCP_CONN_STATE_OPEN;
    }
    else {
        conn->_state = AH_I_TCP_CONN_STATE_CONNECTED;

        ah_tcp_shutdown_t shutdown_flags = 0u;

        if (conn->_vtab->on_read_done == NULL) {
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
    if (conn->_is_reading) {
        return AH_ESTATE;
    }

    ah_i_loop_evt_t* evt;
    struct kevent* kev;

    ah_err_t err = ah_i_loop_evt_alloc_with_kev(conn->_loop, &evt, &kev);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_conn_read;
    evt->_subject = conn;

    EV_SET(kev, conn->_fd, EVFILT_READ, EV_ADD, 0u, 0, evt);
    conn->_read_evt = evt;

    conn->_is_reading = true;

    return AH_ENONE;
}

static void s_on_conn_read(ah_i_loop_evt_t* evt, struct kevent* kev)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(kev != NULL);

    ah_tcp_conn_t* conn = evt->_subject;
    ah_assert_if_debug(conn != NULL);

    if (conn->_state != AH_I_TCP_CONN_STATE_CONNECTED || (conn->_shutdown_flags & AH_TCP_SHUTDOWN_RD) == 0u) {
        return;
    }
    ah_assert_if_debug(conn->_is_reading);

    ah_err_t err;

    if (ah_unlikely((kev->flags & EV_ERROR) != 0)) {
        err = (ah_err_t) kev->data;
        goto report_err;
    }

    size_t n_bytes_left = kev->data;

    ah_bufs_t bufs;

    while (n_bytes_left != 0u) {
        bufs = (ah_bufs_t) { .items = NULL, .length = 0u };
        conn->_vtab->on_read_alloc(conn, &bufs, n_bytes_left);
        if (bufs.items == NULL) {
            err = AH_ENOBUFS;
            goto report_err;
        }

        struct iovec* iov;
        int iovcnt;
        err = ah_i_bufs_into_iovec(&bufs, &iov, &iovcnt);
        if (err != AH_ENONE) {
            goto report_err;
        }

        ssize_t n_bytes_read = readv(conn->_fd, iov, iovcnt);
        if (n_bytes_read < 0) {
            err = errno;
            goto report_err;
        }

        conn->_vtab->on_read_done(conn, bufs, (size_t) n_bytes_read, AH_ENONE);

        if (!conn->_is_reading) {
            return;
        }

        n_bytes_left -= (size_t) n_bytes_read;
    }

    if (ah_unlikely((kev->flags & EV_EOF) != 0)) {
        err = kev->fflags != 0 ? (ah_err_t) kev->fflags : AH_EEOF;
        conn->_shutdown_flags |= AH_TCP_SHUTDOWN_RD;
        goto report_err;
    }

    return;

report_err:
    conn->_vtab->on_read_done(conn, (ah_bufs_t) { 0u }, 0u, err);
}

ah_extern ah_err_t ah_tcp_conn_read_stop(ah_tcp_conn_t* conn)
{
    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (!conn->_is_reading) {
        return AH_ESTATE;
    }

    struct kevent* kev;
    ah_err_t err = ah_i_loop_alloc_kev(conn->_loop, &kev);
    if (err != AH_ENONE) {
        return err;
    }

    EV_SET(kev, conn->_fd, EVFILT_READ, EV_DELETE, 0, 0u, NULL);

    conn->_is_reading = false;

    return AH_ENONE;
}

ah_extern ah_err_t ah_tcp_conn_write(ah_tcp_conn_t* conn, ah_bufs_t bufs)
{
    if (conn == NULL || (bufs.items == NULL && bufs.length != 0u)) {
        return AH_EINVAL;
    }
    if (conn->_state != AH_I_TCP_CONN_STATE_CONNECTED || (conn->_shutdown_flags & AH_TCP_SHUTDOWN_WR) != 0) {
        return AH_ESTATE;
    }
    if (conn->_is_writing) {
        return AH_EAGAIN;
    }

    conn->_write_bufs = bufs;

    ah_err_t err = s_prep_conn_write(conn);
    if (err != AH_ENONE) {
        return err;
    }

    conn->_is_writing = true;

    return AH_ENONE;
}

static ah_err_t s_prep_conn_write(ah_tcp_conn_t* conn)
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

    if (conn->_state != AH_I_TCP_CONN_STATE_CONNECTED || (conn->_shutdown_flags & AH_TCP_SHUTDOWN_WR) != 0) {
        return;
    }
    ah_assert_if_debug(conn->_is_writing);

    ah_err_t err;
    size_t n_bytes_written = 0u;

    if (ah_unlikely((kev->flags & EV_ERROR) != 0)) {
        err = (ah_err_t) kev->data;
        goto report_err;
    }

    if (ah_unlikely((kev->flags & EV_EOF) != 0)) {
        err = kev->fflags != 0 ? (ah_err_t) kev->fflags : AH_EEOF;
        conn->_shutdown_flags |= AH_TCP_SHUTDOWN_WR;
        goto report_err;
    }

    struct iovec* iov;
    int iovcnt;
    err = ah_i_bufs_into_iovec(&conn->_write_bufs, &iov, &iovcnt);
    if (ah_unlikely(err != AH_ENONE)) {
        err = AH_EDOM;
        goto report_err;
    }

    ssize_t res = writev(conn->_fd, iov, iovcnt);
    if (ah_unlikely(res < 0)) {
        err = errno;
        goto report_err;
    }

    n_bytes_written = (size_t) res;

    // If more remains to be written but no output buffer space is available,
    // adjust bufs and schedule another writing.
    for (size_t i = 0u; i < conn->_write_bufs.length; i += 1u) {
        ah_buf_t* buf = &conn->_write_bufs.items[0u];

        if (((size_t) res) >= buf->_size) {
            res -= (ssize_t) buf->_size;
            continue;
        }

        conn->_write_bufs.items = &conn->_write_bufs.items[i];
        conn->_write_bufs.length -= i;

        buf->_octets = &buf->_octets[(size_t) res];
        buf->_size -= (size_t) res;

        err = s_prep_conn_write(conn);
        if (err != AH_ENONE) {
            goto report_err;
        }
        return;
    }

    err = AH_ENONE;

report_err:
    conn->_vtab->on_write_done(conn, conn->_write_bufs, n_bytes_written, err);
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

    if (conn->_read_evt != NULL) {
        ah_i_loop_evt_dealloc(conn->_loop, conn->_read_evt);
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
    if (conn_vtab->on_read_alloc == NULL || conn_vtab->on_read_done == NULL || conn_vtab->on_write_done == NULL) {
        return AH_EINVAL;
    }
    if (ln->_state != AH_I_TCP_LISTENER_STATE_OPEN) {
        return AH_ESTATE;
    }

    ah_err_t err;

    int backlog_int = (backlog == 0u ? 16 : backlog <= SOMAXCONN ? (int) backlog : SOMAXCONN);
    if (listen(ln->_fd, backlog_int) != 0) {
        err = errno;
        ln->_vtab->on_listen(ln, err);
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

    ln->_conn_vtab = conn_vtab;
    ln->_listen_evt = evt;
    ln->_state = AH_I_TCP_LISTENER_STATE_LISTENING;
    ln->_vtab->on_listen(ln, AH_ENONE);

    return AH_ENONE;
}

static void s_on_listener_accept(ah_i_loop_evt_t* evt, struct kevent* kev)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(kev != NULL);

    ah_tcp_listener_t* ln = evt->_subject;
    ah_assert_if_debug(ln != NULL);

    if (ah_unlikely((kev->flags & EV_ERROR) != 0)) {
        ln->_vtab->on_listen(ln, (ah_err_t) kev->data);
        ln->_state = AH_I_TCP_LISTENER_STATE_OPEN;
        return;
    }

    for (int64_t i = 0; i < kev->data; i += 1) {
        ah_tcp_conn_t* conn = NULL;
        ln->_vtab->on_conn_alloc(ln, &conn);
        if (conn == NULL) {
            ln->_vtab->on_conn_accept(ln, NULL, NULL, AH_ENOBUFS);
            continue;
        }

        ah_sockaddr_t sockaddr;
        socklen_t socklen = sizeof(ah_sockaddr_t);

        const int fd = accept(ln->_fd, ah_i_sockaddr_into_bsd(&sockaddr), &socklen);
        if (fd == -1) {
            ln->_vtab->on_conn_accept(ln, NULL, NULL, errno);
            continue;
        }

#if AH_I_SOCKADDR_HAS_SIZE
        ah_assert_if_debug(socklen <= UINT8_MAX);
        sockaddr.as_any.size = socklen;
#endif

        *conn = (ah_tcp_conn_t) {
            ._loop = ln->_loop,
            ._vtab = ln->_conn_vtab,
            ._state = AH_I_TCP_CONN_STATE_CONNECTED,
            ._fd = fd,
        };

        ln->_vtab->on_conn_accept(ln, conn, &sockaddr, AH_ENONE);
    }

    if (ah_unlikely((kev->flags & EV_EOF) != 0)) {
        ln->_vtab->on_listen(ln, (ah_err_t) kev->fflags != 0 ? (ah_err_t) kev->fflags : AH_EEOF);
        ln->_state = AH_I_TCP_LISTENER_STATE_OPEN;
    }
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

    if (ln->_listen_evt != NULL) {
        ah_i_loop_evt_dealloc(ln->_loop, ln->_listen_evt);
    }

#ifndef NDEBUG
    ln->_fd = 0;
#endif

    ln->_vtab->on_close(ln, err);

    return AH_ENONE;
}
