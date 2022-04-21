// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/tcp.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"

#include <stddef.h>
#include <sys/socket.h>
#include <sys/uio.h>

static void s_on_accept(ah_i_loop_evt_t* evt, struct kevent* kev);
static void s_on_connect(ah_i_loop_evt_t* evt, struct kevent* kev);
static void s_on_read(ah_i_loop_evt_t* evt, struct kevent* kev);
static void s_on_write(ah_i_loop_evt_t* evt, struct kevent* kev);

static ah_err_t s_prep_write(ah_tcp_sock_t* sock, ah_tcp_write_ctx_t* ctx);

ah_extern ah_err_t ah_tcp_connect(ah_tcp_sock_t* sock, const ah_sockaddr_t* remote_addr, ah_tcp_connect_cb cb)
{
    if (sock == NULL || !ah_sockaddr_is_ip(remote_addr) || cb == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state != AH_I_TCP_STATE_OPEN) {
        return AH_ESTATE;
    }

    ah_err_t err;

    if (connect(sock->_fd, ah_i_sockaddr_const_into_bsd(remote_addr), ah_i_sockaddr_get_size(remote_addr)) != 0) {
        if (errno == EINPROGRESS) {
            ah_i_loop_evt_t* evt;
            struct kevent* kev;

            err = ah_i_loop_evt_alloc_with_kev(sock->_loop, &evt, &kev);
            if (err != AH_ENONE) {
                return err;
            }

            evt->_cb = s_on_connect;
            evt->_body._tcp_connect._sock = sock;
            evt->_body._tcp_connect._cb = cb;

            EV_SET(kev, sock->_fd, EVFILT_WRITE, EV_ADD | EV_ONESHOT, 0u, 0u, evt);

            sock->_state = AH_I_TCP_STATE_CONNECTING;

            return AH_ENONE;
        }
        err = errno;
    }
    else {
        err = AH_ENONE;
    }

    if (err != AH_ENONE) {
        cb(sock, err);
        return AH_ENONE;
    }

    sock->_state = AH_I_TCP_STATE_CONNECTED;
    sock->_state_read = AH_I_TCP_STATE_READ_STOPPED;
    sock->_state_write = AH_I_TCP_STATE_WRITE_STOPPED;

    cb(sock, AH_ENONE);

    return AH_ENONE;
}

static void s_on_connect(ah_i_loop_evt_t* evt, struct kevent* kev)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(kev != NULL);

    ah_tcp_sock_t* sock = evt->_body._tcp_connect._sock;
    ah_assert_if_debug(sock != NULL);

    ah_tcp_connect_cb cb = evt->_body._tcp_connect._cb;

    ah_err_t err;

    if (ah_unlikely((kev->flags & EV_ERROR) != 0)) {
        err = (ah_err_t) kev->data;
    }
    else if (ah_unlikely((kev->flags & EV_EOF) != 0)) {
        err = kev->fflags != 0 ? (ah_err_t) kev->fflags : AH_EEOF;
    }
    else {
        err = AH_ENONE;
    }

    if (ah_likely(err == AH_ENONE)) {
        sock->_state = AH_I_TCP_STATE_CONNECTED;
        sock->_state_read = AH_I_TCP_STATE_READ_STOPPED;
        sock->_state_write = AH_I_TCP_STATE_WRITE_STOPPED;
    }

    cb(sock, err);
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

    int backlog_int = (backlog == 0u || backlog > SOMAXCONN) ? SOMAXCONN : (int) backlog;
    if (listen(sock->_fd, backlog_int) != 0) {
        err = errno;
        ctx->listen_cb(sock, err);
        return AH_ENONE;
    }

    ah_i_loop_evt_t* evt;
    struct kevent* kev;

    err = ah_i_loop_evt_alloc_with_kev(sock->_loop, &evt, &kev);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_accept;
    evt->_body._tcp_listen._sock = sock;
    evt->_body._tcp_listen._ctx = ctx;

    EV_SET(kev, sock->_fd, EVFILT_READ, EV_ADD, 0u, 0, evt);
    sock->_read_or_listen_evt = evt;

    sock->_state = AH_I_TCP_STATE_LISTENING;
    ctx->listen_cb(sock, AH_ENONE);
    return AH_ENONE;
}

static void s_on_accept(ah_i_loop_evt_t* evt, struct kevent* kev)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(kev != NULL);

    ah_tcp_sock_t* listener = evt->_body._tcp_listen._sock;
    ah_assert_if_debug(listener != NULL);

    ah_tcp_listen_ctx_t* ctx = evt->_body._tcp_listen._ctx;
    ah_assert_if_debug(ctx != NULL);
    ah_assert_if_debug(ctx->listen_cb != NULL);
    ah_assert_if_debug(ctx->accept_cb != NULL);
    ah_assert_if_debug(ctx->alloc_cb != NULL);

    if (ah_unlikely((kev->flags & EV_ERROR) != 0)) {
        ctx->listen_cb(listener, (ah_err_t) kev->data);
        return;
    }

    for (int64_t i = 0; i < kev->data; i += 1) {
        ah_tcp_sock_t* conn = NULL;
        ctx->alloc_cb(listener, &conn);
        if (conn == NULL) {
            ctx->accept_cb(listener, NULL, NULL, ENOMEM);
            continue;
        }

        ah_sockaddr_t sockaddr;
        socklen_t socklen = sizeof(ah_sockaddr_t);

        const int fd = accept(listener->_fd, ah_i_sockaddr_into_bsd(&sockaddr), &socklen);
        if (fd == -1) {
            ctx->accept_cb(listener, NULL, NULL, errno);
            continue;
        }

#if AH_I_SOCKADDR_HAS_SIZE
        ah_assert_if_debug(socklen <= UINT8_MAX);
        sockaddr.as_any.size = socklen;
#endif

        *conn = (ah_tcp_sock_t) {
            ._loop = listener->_loop,
            ._fd = fd,
            ._state = AH_I_TCP_STATE_CONNECTED,
            ._state_read = AH_I_TCP_STATE_READ_STOPPED,
            ._state_write = AH_I_TCP_STATE_WRITE_STOPPED,
        };

        ctx->accept_cb(listener, conn, &sockaddr, AH_ENONE);
    }

    if (ah_unlikely((kev->flags & EV_EOF) != 0)) {
        ctx->listen_cb(listener, kev->fflags != 0 ? (ah_err_t) kev->fflags : AH_EEOF);
    }
}

ah_extern ah_err_t ah_tcp_read_start(ah_tcp_sock_t* sock, ah_tcp_read_ctx_t* ctx)
{
    if (sock == NULL || ctx == NULL || ctx->alloc_cb == NULL || ctx->read_cb == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state != AH_I_TCP_STATE_CONNECTED || sock->_state_read != AH_I_TCP_STATE_READ_STOPPED) {
        return AH_ESTATE;
    }

    ah_i_loop_evt_t* evt;
    struct kevent* kev;

    ah_err_t err = ah_i_loop_evt_alloc_with_kev(sock->_loop, &evt, &kev);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_read;
    evt->_body._tcp_read._sock = sock;
    evt->_body._tcp_read._ctx = ctx;

    EV_SET(kev, sock->_fd, EVFILT_READ, EV_ADD, 0u, 0, evt);
    sock->_read_or_listen_evt = evt;

    sock->_state_read = AH_I_TCP_STATE_READ_STARTED;

    return AH_ENONE;
}

static void s_on_read(ah_i_loop_evt_t* evt, struct kevent* kev)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(kev != NULL);

    ah_tcp_sock_t* sock = evt->_body._tcp_read._sock;
    ah_assert_if_debug(sock != NULL);

    ah_tcp_read_ctx_t* ctx = evt->_body._tcp_read._ctx;
    ah_assert_if_debug(ctx != NULL);
    ah_assert_if_debug(ctx->read_cb != NULL);
    ah_assert_if_debug(ctx->alloc_cb != NULL);

    if (sock->_state != AH_I_TCP_STATE_CONNECTED || sock->_state_read != AH_I_TCP_STATE_READ_STARTED) {
        return;
    }

    ah_err_t err;

    if (ah_unlikely((kev->flags & EV_ERROR) != 0)) {
        err = (ah_err_t) kev->data;
        goto call_read_cb_with_err_and_return;
    }

    size_t n_bytes_left = kev->data;

    ah_bufvec_t bufvec;

    while (n_bytes_left != 0u) {
        bufvec = (ah_bufvec_t) { .items = NULL, .length = 0u };
        ctx->alloc_cb(sock, &bufvec, n_bytes_left);
        if (bufvec.items == NULL) {
            err = AH_ENOMEM;
            goto call_read_cb_with_err_and_return;
        }

        struct iovec* iov;
        int iovcnt;
        err = ah_i_bufvec_into_iovec(&bufvec, &iov, &iovcnt);
        if (err != AH_ENONE) {
            goto call_read_cb_with_err_and_return;
        }

        ssize_t n_bytes_read = readv(sock->_fd, iov, iovcnt);
        if (n_bytes_read < 0) {
            err = errno;
            goto call_read_cb_with_err_and_return;
        }

        ctx->read_cb(sock, &bufvec, (size_t) n_bytes_read, AH_ENONE);

        if (sock->_state_read != AH_I_TCP_STATE_READ_STARTED) {
            return;
        }

        if (ah_p_sub_overflow(n_bytes_left, n_bytes_read, &n_bytes_left)) {
            err = AH_ERANGE;
            goto call_read_cb_with_err_and_return;
        }
    }

    if (ah_unlikely((kev->flags & EV_EOF) != 0)) {
        err = kev->fflags != 0 ? (ah_err_t) kev->fflags : AH_EEOF;
        sock->_state_read = AH_I_TCP_STATE_READ_OFF;
        goto call_read_cb_with_err_and_return;
    }

    return;

call_read_cb_with_err_and_return:
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

    struct kevent* kev;
    ah_err_t err = ah_i_loop_alloc_kev(sock->_loop, &kev);
    if (err == AH_ENONE) {
        EV_SET(kev, sock->_fd, EVFILT_READ, EV_DELETE, 0, 0u, NULL);
    }
    else if (err == AH_ENOMEM) {
        return err;
    }

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

    if (ctx->bufvec.length == 0u) {
        ctx->write_cb(sock, AH_ENONE);
        return AH_ENONE;
    }

    ah_err_t err = s_prep_write(sock, ctx);
    if (err != AH_ENONE) {
        return err;
    }

    sock->_state_write = AH_I_TCP_STATE_WRITE_STARTED;

    return AH_ENONE;
}

static ah_err_t s_prep_write(ah_tcp_sock_t* sock, ah_tcp_write_ctx_t* ctx)
{
    ah_assert_if_debug(sock != NULL);
    ah_assert_if_debug(ctx != NULL);

    ah_i_loop_evt_t* evt;
    struct kevent* kev;

    ah_err_t err = ah_i_loop_evt_alloc_with_kev(sock->_loop, &evt, &kev);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_write;
    evt->_body._tcp_write._sock = sock;
    evt->_body._tcp_write._ctx = ctx;

    EV_SET(kev, sock->_fd, EVFILT_WRITE, EV_ADD | EV_ONESHOT, 0u, 0, evt);

    return AH_ENONE;
}

static void s_on_write(ah_i_loop_evt_t* evt, struct kevent* kev)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(kev != NULL);

    ah_tcp_sock_t* sock = evt->_body._tcp_write._sock;
    ah_assert_if_debug(sock != NULL);

    ah_tcp_write_ctx_t* ctx = evt->_body._tcp_write._ctx;
    ah_assert_if_debug(ctx != NULL);
    ah_assert_if_debug(ctx->write_cb != NULL);
    ah_assert_if_debug(ctx->bufvec.items != NULL || ctx->bufvec.length == 0u);

    if (sock->_state != AH_I_TCP_STATE_CONNECTED || sock->_state_write != AH_I_TCP_STATE_WRITE_STARTED) {
        return;
    }

    ah_err_t err;

    if (ah_unlikely((kev->flags & EV_ERROR) != 0)) {
        err = (ah_err_t) kev->data;
        goto stop_writing_and_report_err;
    }

    if (ah_unlikely((kev->flags & EV_EOF) != 0)) {
        err = kev->fflags != 0 ? (ah_err_t) kev->fflags : AH_EEOF;
        sock->_state_write = AH_I_TCP_STATE_WRITE_OFF;
        goto report_err;
    }

    struct iovec* iovecs;
    int iovecs_length;
    err = ah_i_bufvec_into_iovec(&ctx->bufvec, &iovecs, &iovecs_length);
    if (ah_unlikely(err != AH_ENONE)) {
        err = AH_EDOM;
        goto stop_writing_and_report_err;
    }

    ssize_t res = writev(sock->_fd, iovecs, iovecs_length);
    if (ah_unlikely(res < 0)) {
        err = errno;
        goto stop_writing_and_report_err;
    }

    // If there is more to write, adjust bufvec and schedule another writing.
    for (size_t i = 0u; i < ctx->bufvec.length; i += 1u) {
        ah_buf_t* buf = &ctx->bufvec.items[0u];

        if (((size_t) res) >= buf->_size) {
            res -= (ssize_t) buf->_size;
            continue;
        }

        ctx->bufvec.items = &ctx->bufvec.items[i];
        ctx->bufvec.length -= i;

        buf->_octets = &buf->_octets[(size_t) res];
        buf->_size -= (size_t) res;

        err = s_prep_write(sock, ctx);
        if (err != AH_ENONE) {
            goto stop_writing_and_report_err;
        }
        return;
    }

    err = AH_ENONE;

stop_writing_and_report_err:
    sock->_state_write = AH_I_TCP_STATE_WRITE_STOPPED;

report_err:
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
    if (sock->_fd == 0) {
        return AH_ESTATE;
    }
#endif
    sock->_state = AH_I_TCP_STATE_CLOSED;
    sock->_state_read = AH_I_TCP_STATE_READ_OFF;
    sock->_state_write = AH_I_TCP_STATE_WRITE_OFF;

    ah_err_t err = ah_i_sock_close(sock->_loop, sock->_fd);

    if (sock->_read_or_listen_evt != NULL) {
        ah_i_loop_evt_dealloc(sock->_loop, sock->_read_or_listen_evt);
    }

#ifndef NDEBUG
    sock->_fd = 0;
#endif

    if (cb != NULL) {
        cb(sock, err);
    }

    return err;
}
