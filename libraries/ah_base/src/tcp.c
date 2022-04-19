// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/tcp.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"
#include "sock-internal.h"

#include <stddef.h>

#if AH_HAS_BSD_SOCKETS
#    include <netinet/tcp.h>
#    include <sys/socket.h>
#endif

#if AH_USE_KQUEUE
#    include <sys/uio.h>
#endif

#define S_STATE_CLOSED     0x01
#define S_STATE_OPEN       0x02
#define S_STATE_CONNECTING 0x04
#define S_STATE_CONNECTED  0x08
#define S_STATE_LISTENING  0x10

#define S_STATE_READ_OFF     0x01
#define S_STATE_READ_STOPPED 0x02
#define S_STATE_READ_STARTED 0x04

#define S_STATE_WRITE_OFF     0x01
#define S_STATE_WRITE_STOPPED 0x02
#define S_STATE_WRITE_STARTED 0x04

static void s_on_accept(ah_i_loop_evt_t* evt, ah_i_loop_res_t* res);
#if AH_USE_URING
static void s_on_close(ah_i_loop_evt_t* evt, ah_i_loop_res_t* res);
#endif
static void s_on_connect(ah_i_loop_evt_t* evt, ah_i_loop_res_t* res);
static void s_on_read(ah_i_loop_evt_t* evt, ah_i_loop_res_t* res);
static void s_on_write(ah_i_loop_evt_t* evt, ah_i_loop_res_t* res);

static ah_err_t s_prep_read(ah_tcp_sock_t* sock, ah_tcp_read_ctx_t* ctx);

ah_extern ah_err_t ah_tcp_open(ah_tcp_sock_t* sock, ah_loop_t* loop, const ah_sockaddr_t* local_addr, ah_tcp_open_cb cb)
{
    if (sock == NULL || loop == NULL || local_addr == NULL) {
        return AH_EINVAL;
    }

#if AH_HAS_BSD_SOCKETS

    ah_i_sockfd_t fd;

    ah_err_t err = ah_i_sock_open(loop, AH_I_SOCK_STREAM, local_addr, &fd);

    if (err == AH_ENONE) {
        *sock = (ah_tcp_sock_t) {
            ._loop = loop,
            ._fd = fd,
            ._state = S_STATE_OPEN,
        };
    }

    if (cb != NULL) {
        cb(sock, err);
        return AH_ENONE;
    }

    return err;
#endif
}

ah_extern ah_err_t ah_tcp_get_local_addr(const ah_tcp_sock_t* sock, ah_sockaddr_t* local_addr)
{
    if (sock == NULL || local_addr == NULL) {
        return AH_EINVAL;
    }
    if ((sock->_state & (S_STATE_OPEN | S_STATE_CONNECTED | S_STATE_LISTENING)) == 0u) {
        return AH_ESTATE;
    }

#if AH_HAS_BSD_SOCKETS
    return ah_i_sock_getsockname(sock->_fd, local_addr);
#endif
}

ah_extern ah_err_t ah_tcp_get_remote_addr(const ah_tcp_sock_t* sock, ah_sockaddr_t* remote_addr)
{
    if (sock == NULL || remote_addr == NULL) {
        return AH_EINVAL;
    }
    if ((sock->_state & (S_STATE_OPEN | S_STATE_CONNECTED | S_STATE_LISTENING)) == 0u) {
        return AH_ESTATE;
    }

#if AH_HAS_BSD_SOCKETS
    return ah_i_sock_getpeername(sock->_fd, remote_addr);
#endif
}

ah_extern ah_err_t ah_tcp_set_keepalive(ah_tcp_sock_t* sock, bool keepalive)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if ((sock->_state & (S_STATE_OPEN | S_STATE_CONNECTED | S_STATE_LISTENING)) == 0u) {
        return AH_ESTATE;
    }

#if AH_HAS_BSD_SOCKETS
    int value = keepalive ? 1 : 0;
    if (setsockopt(sock->_fd, SOL_SOCKET, SO_KEEPALIVE, (void*) &value, sizeof(value)) != 0) {
        return errno;
    }
    return AH_ENONE;
#endif
}

ah_extern ah_err_t ah_tcp_set_no_delay(ah_tcp_sock_t* sock, bool no_delay)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if ((sock->_state & (S_STATE_OPEN | S_STATE_CONNECTED | S_STATE_LISTENING)) == 0u) {
        return AH_ESTATE;
    }

#if AH_HAS_BSD_SOCKETS
    int value = no_delay ? 1 : 0;
    if (setsockopt(sock->_fd, IPPROTO_TCP, TCP_NODELAY, (void*) &value, sizeof(value)) != 0) {
        return errno;
    }
    return AH_ENONE;
#endif
}

ah_extern ah_err_t ah_tcp_set_reuse_addr(ah_tcp_sock_t* sock, bool reuse_addr)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if ((sock->_state & (S_STATE_OPEN | S_STATE_CONNECTED | S_STATE_LISTENING)) == 0u) {
        return AH_ESTATE;
    }

#if AH_HAS_BSD_SOCKETS
    int value = reuse_addr ? 1 : 0;
    if (setsockopt(sock->_fd, SOL_SOCKET, SO_REUSEADDR, (void*) &value, sizeof(value)) != 0) {
        return errno;
    }
    return AH_ENONE;
#endif
}

ah_extern ah_err_t ah_tcp_connect(ah_tcp_sock_t* sock, const ah_sockaddr_t* remote_addr, ah_tcp_connect_cb cb)
{
    if (sock == NULL || !ah_sockaddr_is_ip(remote_addr) || cb == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state != S_STATE_OPEN) {
        return AH_ESTATE;
    }

    ah_err_t err;

#if AH_USE_KQUEUE

    if (connect(sock->_fd, ah_sockaddr_cast_const(remote_addr), ah_sockaddr_get_size(remote_addr)) != 0) {
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

            sock->_state = S_STATE_CONNECTING;

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

    sock->_state = S_STATE_CONNECTED;
    sock->_state_read = S_STATE_READ_STOPPED;
    sock->_state_write = S_STATE_WRITE_STOPPED;

    cb(sock, AH_ENONE);

    return AH_ENONE;

#elif AH_USE_URING

    ah_i_loop_evt_t* evt;
    struct io_uring_sqe* sqe;

    err = ah_i_loop_evt_alloc_with_sqe(sock->_loop, &evt, &sqe);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_connect;
    evt->_body._tcp_connect._sock = sock;
    evt->_body._tcp_connect._cb = cb;

    io_uring_prep_connect(sqe, sock->_fd, ah_sockaddr_cast_const(remote_addr), ah_sockaddr_get_size(remote_addr));
    io_uring_sqe_set_data(sqe, evt);

    sock->_state = S_STATE_CONNECTING;

    return AH_ENONE;

#endif
}

static void s_on_connect(ah_i_loop_evt_t* evt, ah_i_loop_res_t* res)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(res != NULL);

    ah_tcp_sock_t* sock = evt->_body._tcp_connect._sock;
    ah_assert_if_debug(sock != NULL);

    ah_tcp_connect_cb cb = evt->_body._tcp_connect._cb;

    ah_err_t err;

#if AH_USE_KQUEUE

    if (ah_unlikely((res->flags & EV_ERROR) != 0)) {
        err = (ah_err_t) res->data;
    }
    else if (ah_unlikely((res->flags & EV_EOF) != 0)) {
        err = AH_EEOF;
    }
    else {
        err = AH_ENONE;
    }

#elif AH_USE_URING

    if (ah_unlikely(res->res != 0)) {
        err = -(res->res);
    }
    else {
        err = AH_ENONE;
    }

#endif

    if (ah_likely(err == AH_ENONE)) {
        sock->_state = S_STATE_CONNECTED;
        sock->_state_read = S_STATE_READ_STOPPED;
        sock->_state_write = S_STATE_WRITE_STOPPED;
    }

    cb(sock, err);
}

ah_extern ah_err_t ah_tcp_listen(ah_tcp_sock_t* sock, unsigned backlog, ah_tcp_listen_ctx_t* ctx)
{
    if (sock == NULL || ctx == NULL || ctx->listen_cb == NULL || ctx->accept_cb == NULL || ctx->alloc_cb == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state != S_STATE_OPEN) {
        return AH_ESTATE;
    }

    ah_err_t err;

    int backlog_int = (backlog == 0u || backlog > SOMAXCONN) ? SOMAXCONN : (int) backlog;
    if (listen(sock->_fd, backlog_int) != 0) {
        err = errno;
        ctx->listen_cb(sock, err);
        return AH_ENONE;
    }

#if AH_USE_KQUEUE

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

#elif AH_USE_URING

    ah_i_loop_evt_t* evt;
    struct io_uring_sqe* sqe;

    err = ah_i_loop_evt_alloc_with_sqe(sock->_loop, &evt, &sqe);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_accept;
    evt->_body._tcp_listen._sock = sock;
    evt->_body._tcp_listen._ctx = ctx;

    ctx->_remote_addr_len = sizeof(ah_sockaddr_t);
    io_uring_prep_accept(sqe, sock->_fd, ah_sockaddr_cast(&ctx->_remote_addr), &ctx->_remote_addr_len, 0);
    io_uring_sqe_set_data(sqe, evt);

#endif

    sock->_state = S_STATE_LISTENING;
    ctx->listen_cb(sock, AH_ENONE);
    return AH_ENONE;
}

static void s_on_accept(ah_i_loop_evt_t* evt, ah_i_loop_res_t* res)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(res != NULL);

    ah_tcp_sock_t* listener = evt->_body._tcp_listen._sock;
    ah_assert_if_debug(listener != NULL);

    ah_tcp_listen_ctx_t* ctx = evt->_body._tcp_listen._ctx;
    ah_assert_if_debug(ctx != NULL);
    ah_assert_if_debug(ctx->listen_cb != NULL);
    ah_assert_if_debug(ctx->accept_cb != NULL);
    ah_assert_if_debug(ctx->alloc_cb != NULL);

#if AH_USE_KQUEUE

    struct kevent* kev = res;
    ah_assert_if_debug(kev != NULL);

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

        const int fd = accept(listener->_fd, ah_sockaddr_cast(&sockaddr), &socklen);
        if (fd == -1) {
            ctx->accept_cb(listener, NULL, NULL, errno);
            continue;
        }

#    if AH_I_SOCKADDR_HAS_SIZE
        ah_assert_if_debug(socklen <= UINT8_MAX);
        sockaddr.as_any.size = socklen;
#    endif

        *conn = (ah_tcp_sock_t) {
            ._loop = listener->_loop,
            ._fd = fd,
            ._state = S_STATE_CONNECTED,
            ._state_read = S_STATE_READ_STOPPED,
            ._state_write = S_STATE_WRITE_STOPPED,
        };

        ctx->accept_cb(listener, conn, &sockaddr, AH_ENONE);
    }

    if (ah_unlikely((kev->flags & EV_EOF) != 0)) {
        ctx->listen_cb(listener, AH_EEOF);
    }

#elif AH_USE_URING

    struct io_uring_cqe* cqe = res;
    ah_assert_if_debug(cqe != NULL);

    if (ah_unlikely(cqe->res < 0)) {
        ctx->accept_cb(listener, NULL, NULL, (ah_err_t) - (cqe->res));
        goto prep_another_accept;
    }

    ah_tcp_sock_t* conn = NULL;
    ctx->alloc_cb(listener, &conn);
    if (conn == NULL) {
        ctx->accept_cb(listener, NULL, NULL, ENOMEM);
        goto prep_another_accept;
    }
    *conn = (ah_tcp_sock_t) {
        ._loop = listener->_loop,
        ._fd = cqe->res,
        ._state = S_STATE_CONNECTED,
        ._state_read = S_STATE_READ_STOPPED,
        ._state_write = S_STATE_WRITE_STOPPED,
    };

    ctx->accept_cb(listener, conn, &ctx->_remote_addr, AH_ENONE);

    ah_err_t err;
    ah_i_loop_evt_t* evt0;
    struct io_uring_sqe* sqe;

prep_another_accept:

    err = ah_i_loop_evt_alloc_with_sqe(listener->_loop, &evt0, &sqe);
    if (err != AH_ENONE) {
        ctx->listen_cb(listener, err);
        return;
    }

    evt0->_cb = s_on_accept;
    evt0->_body._tcp_listen._sock = listener;
    evt0->_body._tcp_listen._ctx = ctx;

    ctx->_remote_addr_len = sizeof(ah_sockaddr_t);
    io_uring_prep_accept(sqe, listener->_fd, ah_sockaddr_cast(&ctx->_remote_addr), &ctx->_remote_addr_len, 0);
    io_uring_sqe_set_data(sqe, evt0);

#endif
}

ah_extern ah_err_t ah_tcp_read_start(ah_tcp_sock_t* sock, ah_tcp_read_ctx_t* ctx)
{
    if (sock == NULL || ctx == NULL || ctx->alloc_cb == NULL || ctx->read_cb == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state != S_STATE_CONNECTED || sock->_state_read != S_STATE_READ_STOPPED) {
        return AH_ESTATE;
    }

    ah_err_t err = s_prep_read(sock, ctx);
    if (err != AH_ENONE) {
        return err;
    }

    sock->_state_read = S_STATE_READ_STARTED;

    return AH_ENONE;
}

static ah_err_t s_prep_read(ah_tcp_sock_t* sock, ah_tcp_read_ctx_t* ctx)
{
    ah_assert_if_debug(sock != NULL);
    ah_assert_if_debug(ctx != NULL);

#if AH_USE_KQUEUE

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

    return AH_ENONE;

#elif AH_USE_URING

    ah_i_loop_evt_t* evt;
    struct io_uring_sqe* sqe;

    ah_err_t err = ah_i_loop_evt_alloc_with_sqe(sock->_loop, &evt, &sqe);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_read;
    evt->_body._tcp_read._sock = sock;
    evt->_body._tcp_read._ctx = ctx;

    ctx->_bufvec.items = NULL;
    ctx->_bufvec.length = 0u;
    ctx->alloc_cb(sock, &ctx->_bufvec, 0u);
    if (ctx->_bufvec.items == NULL) {
        return AH_ENOMEM;
    }

    struct iovec* iov;
    int iovcnt;
    err = ah_i_bufvec_into_iovec(&ctx->_bufvec, &iov, &iovcnt);
    if (err != AH_ENONE) {
        return err;
    }

    io_uring_prep_readv(sqe, sock->_fd, iov, iovcnt, 0);
    io_uring_sqe_set_data(sqe, evt);

    return AH_ENONE;

#endif
}

static void s_on_read(ah_i_loop_evt_t* evt, ah_i_loop_res_t* res)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(res != NULL);

    ah_tcp_sock_t* sock = evt->_body._tcp_read._sock;
    ah_assert_if_debug(sock != NULL);

    ah_tcp_read_ctx_t* ctx = evt->_body._tcp_read._ctx;
    ah_assert_if_debug(ctx != NULL);
    ah_assert_if_debug(ctx->read_cb != NULL);
    ah_assert_if_debug(ctx->alloc_cb != NULL);

    if (sock->_state != S_STATE_CONNECTED || sock->_state_read != S_STATE_READ_STARTED) {
        return;
    }

    ah_err_t err;

#if AH_USE_KQUEUE

    if (ah_unlikely((res->flags & EV_ERROR) != 0)) {
        err = (ah_err_t) res->data;
        goto call_read_cb_with_err_and_return;
    }

    size_t n_bytes_left = res->data;

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

        if (sock->_state_read != S_STATE_READ_STARTED) {
            return;
        }

        if (ah_p_sub_overflow(n_bytes_left, n_bytes_read, &n_bytes_left)) {
            err = AH_ERANGE;
            goto call_read_cb_with_err_and_return;
        }
    }

    if (ah_unlikely((res->flags & EV_EOF) != 0)) {
        err = AH_EEOF;
        sock->_state_read = S_STATE_READ_OFF;
        goto call_read_cb_with_err_and_return;
    }

#elif AH_USE_URING

    struct io_uring_cqe* cqe = res;
    ah_assert_if_debug(cqe != NULL);

    if (ah_unlikely(cqe->res < 0)) {
        err = -(cqe->res);
        goto call_read_cb_with_err_and_return;
    }

    ctx->read_cb(sock, &ctx->_bufvec, cqe->res, AH_ENONE);

    if (sock->_state_read != S_STATE_READ_STARTED) {
        return;
    }

    err = s_prep_read(sock, ctx);
    if (err != AH_ENONE) {
        goto call_read_cb_with_err_and_return;
    }

#endif

    return;

call_read_cb_with_err_and_return:
    ctx->read_cb(sock, NULL, 0u, err);
}

ah_extern ah_err_t ah_tcp_read_stop(ah_tcp_sock_t* sock)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state_read != S_STATE_READ_STARTED) {
        return AH_ESTATE;
    }
    sock->_state_read = S_STATE_READ_STOPPED;

#if AH_USE_KQUEUE

    struct kevent* kev;
    ah_err_t err = ah_i_loop_alloc_kev(sock->_loop, &kev);
    if (err == AH_ENONE) {
        EV_SET(kev, sock->_fd, EVFILT_READ, EV_DELETE, 0, 0u, NULL);
    }
    else if (err == AH_ENOMEM) {
        return err;
    }

#endif

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
    if (sock->_state != S_STATE_CONNECTED || sock->_state_write != S_STATE_WRITE_STOPPED) {
        return AH_ESTATE;
    }

#if AH_USE_KQUEUE

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

#elif AH_USE_URING

    ah_i_loop_evt_t* evt;
    struct io_uring_sqe* sqe;

    ah_err_t err = ah_i_loop_evt_alloc_with_sqe(sock->_loop, &evt, &sqe);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_write;
    evt->_body._tcp_write._sock = sock;
    evt->_body._tcp_write._ctx = ctx;

    struct iovec* iov;
    int iovcnt;
    err = ah_i_bufvec_into_iovec(&ctx->bufvec, &iov, &iovcnt);
    if (err != AH_ENONE) {
        return err;
    }

    io_uring_prep_writev(sqe, sock->_fd, iov, iovcnt, 0u);
    io_uring_sqe_set_data(sqe, evt);

#endif

    sock->_state_write = S_STATE_WRITE_STARTED;

    return AH_ENONE;
}

static void s_on_write(ah_i_loop_evt_t* evt, ah_i_loop_res_t* res)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(res != NULL);

    ah_tcp_sock_t* sock = evt->_body._tcp_write._sock;
    ah_assert_if_debug(sock != NULL);

    ah_tcp_write_ctx_t* ctx = evt->_body._tcp_write._ctx;
    ah_assert_if_debug(ctx != NULL);
    ah_assert_if_debug(ctx->write_cb != NULL);
    ah_assert_if_debug(ctx->bufvec.items != NULL || ctx->bufvec.length == 0u);

    if (sock->_state != S_STATE_CONNECTED || sock->_state_write != S_STATE_WRITE_STARTED) {
        return;
    }

    ah_err_t err;

#if AH_USE_KQUEUE

    if (ah_unlikely((res->flags & EV_ERROR) != 0)) {
        err = (ah_err_t) res->data;
        goto set_is_writing_to_false_and_call_write_cb_with_conn_err;
    }

    if (ah_unlikely((res->flags & EV_EOF) != 0)) {
        err = AH_EEOF;
        sock->_state_write = S_STATE_WRITE_OFF;
        goto set_is_writing_to_false_and_call_write_cb_with_conn_err;
    }

    struct iovec* iov;
    int iovcnt;
    err = ah_i_bufvec_into_iovec(&ctx->bufvec, &iov, &iovcnt);
    if (ah_unlikely(err != AH_ENONE)) {
        err = AH_EDOM;
        goto set_is_writing_to_false_and_call_write_cb_with_conn_err;
    }

    ssize_t write_res = writev(sock->_fd, iov, iovcnt);
    if (ah_unlikely(write_res < 0)) {
        err = errno;
        goto set_is_writing_to_false_and_call_write_cb_with_conn_err;
    }

    err = AH_ENONE;

set_is_writing_to_false_and_call_write_cb_with_conn_err:
    sock->_state_write = S_STATE_WRITE_STOPPED;
    ctx->write_cb(sock, err);

#else

    struct io_uring_cqe* cqe = res;
    ah_assert_if_debug(cqe != NULL);

    if (ah_unlikely(cqe->res < 0)) {
        err = -(cqe->res);
    }
    else {
        err = AH_ENONE;
    }

    sock->_state_write = S_STATE_WRITE_STOPPED;
    ctx->write_cb(sock, err);

#endif
}

ah_extern ah_err_t ah_tcp_shutdown(ah_tcp_sock_t* sock, ah_tcp_shutdown_t flags)
{
    if (sock == NULL || (flags & ~AH_TCP_SHUTDOWN_RDWR) != 0u) {
        return AH_EINVAL;
    }
    if ((flags & AH_TCP_SHUTDOWN_RDWR) == 0u) {
        return AH_ENONE;
    }
    if (sock->_state != S_STATE_CONNECTED) {
        return AH_ESTATE;
    }

#if AH_HAS_POSIX

    ah_err_t err;

#    if SHUT_RD == (AH_TCP_SHUTDOWN_RD - 1) && SHUT_WR == (AH_TCP_SHUTDOWN_WR - 1)                                     \
        && SHUT_RDWR == (AH_TCP_SHUTDOWN_RDWR - 1)

    const int how = ((int) flags) - 1;

#    else

    int how;
    switch (flags) {
    case AH_TCP_SHUTDOWN_RD:
        how = SHUT_RD;
        break;

    case AH_TCP_SHUTDOWN_WR:
        how = SHUT_WR;
        break;

    case AH_TCP_SHUTDOWN_RDWR:
        how = SHUT_RDWR;
        break;

    default:
        ah_unreachable();
    }

#    endif

    if (shutdown(sock->_fd, how) != 0) {
        err = errno;
    }
    else {
        err = AH_ENONE;

        if ((flags & AH_TCP_SHUTDOWN_RD) != 0) {
            sock->_state_read = S_STATE_READ_OFF;
        }
        if ((flags & AH_TCP_SHUTDOWN_WR) != 0) {
            sock->_state_write = S_STATE_WRITE_OFF;
        }
    }

    return err;

#endif
}

ah_extern ah_err_t ah_tcp_close(ah_tcp_sock_t* sock, ah_tcp_close_cb cb)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if ((sock->_state & (S_STATE_OPEN | S_STATE_CONNECTED | S_STATE_LISTENING)) == 0u) {
        return AH_ESTATE;
    }
#ifndef NDEBUG
    if (sock->_fd == 0) {
        return AH_ESTATE;
    }
#endif
    sock->_state = S_STATE_CLOSED;

    ah_err_t err;

#if AH_USE_URING

    if (cb != NULL) {
        ah_i_loop_evt_t* evt;
        struct io_uring_sqe* sqe;

        err = ah_i_loop_evt_alloc_with_sqe(sock->_loop, &evt, &sqe);
        if (err == AH_ENONE) {
            evt->_cb = s_on_close;
            evt->_body._tcp_close._sock = sock;
            evt->_body._tcp_close._cb = cb;

            io_uring_prep_close(sqe, sock->_fd);
            io_uring_sqe_set_data(sqe, evt);

            return AH_ENONE;
        }
    }

#endif

#if AH_HAS_BSD_SOCKETS

    err = ah_i_sock_close(sock->_loop, sock->_fd);

#    if AH_USE_KQUEUE
    if (sock->_read_or_listen_evt != NULL) {
        ah_i_loop_evt_dealloc(sock->_loop, sock->_read_or_listen_evt);
    }
#    endif

#    ifndef NDEBUG
    sock->_fd = 0;
#    endif

    if (cb != NULL) {
        cb(sock, err);
    }

    return err;

#endif
}

#if AH_USE_URING
static void s_on_close(ah_i_loop_evt_t* evt, ah_i_loop_res_t* res)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(res != NULL);

    ah_tcp_sock_t* sock = evt->_body._tcp_close._sock;
    ah_assert_if_debug(sock != NULL);

#    ifndef NDEBUG
    sock->_fd = 0;
#    endif

    ah_tcp_close_cb cb = evt->_body._tcp_close._cb;
    ah_assert_if_debug(cb != NULL);

    cb(sock, -(res->res));
}
#endif
