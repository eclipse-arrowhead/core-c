// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/tcp.h"

#include "ah/assert.h"
#include "ah/loop-internal.h"
#include "ah/loop.h"
#include "sock-internal.h"

#include <stddef.h>

#if AH_USE_BSD_SOCKETS
#    include <netinet/tcp.h>
#    include <sys/socket.h>
#    include <unistd.h>
#endif

#if AH_USE_KQUEUE
#    include "ah/math.h"

#    include <sys/uio.h>
#endif

static void s_on_accept(struct ah_i_loop_evt* evt, ah_i_loop_res_t* res);
#if AH_USE_URING
static void s_on_close(struct ah_i_loop_evt* evt, ah_i_loop_res_t* res);
#endif
static void s_on_connect(struct ah_i_loop_evt* evt, ah_i_loop_res_t* res);
static void s_on_read(struct ah_i_loop_evt* evt, ah_i_loop_res_t* res);
static void s_on_write(struct ah_i_loop_evt* evt, ah_i_loop_res_t* res);

ah_extern ah_err_t ah_tcp_init(struct ah_tcp_sock* sock, struct ah_loop* loop, void* user_data)
{
    if (sock == NULL || loop == NULL) {
        return AH_EINVAL;
    }
    *sock = (struct ah_tcp_sock) {
        ._loop = loop,
        ._user_data = user_data,
    };
    return AH_ENONE;
}

ah_extern ah_err_t ah_tcp_open(struct ah_tcp_sock* sock, const union ah_sockaddr* local_addr, ah_tcp_open_cb cb)
{
    if (sock == NULL || local_addr == NULL) {
        return AH_EINVAL;
    }

#if AH_USE_BSD_SOCKETS

    ah_err_t err = ah_i_sock_open(sock->_loop, AH_I_SOCK_STREAM, local_addr, &sock->_fd);

    if (cb != NULL) {
        cb(sock, err);
        return AH_ENONE;
    }

    return err;
#endif
}

#if AH_USE_BSD_SOCKETS
ah_extern ah_err_t ah_tcp_get_fd(const struct ah_tcp_sock* sock, ah_sockfd_t* fd)
{
    if (sock == NULL || fd == NULL) {
        return AH_EINVAL;
    }
#    ifndef NDEBUG
    if (sock->_fd == 0) {
        return AH_EBADF;
    }
#    endif

    *fd = sock->_fd;

    return AH_ENONE;
}
#endif

ah_extern ah_err_t ah_tcp_get_local_addr(const struct ah_tcp_sock* sock, union ah_sockaddr* local_addr)
{
    if (sock == NULL || local_addr == NULL) {
        return AH_EINVAL;
    }

#if AH_USE_BSD_SOCKETS
    return ah_i_sock_getsockname(sock->_fd, local_addr);
#endif
}

ah_extern ah_err_t ah_tcp_get_loop(const struct ah_tcp_sock* sock, struct ah_loop** loop)
{
    if (sock == NULL || loop == NULL) {
        return AH_EINVAL;
    }

    *loop = sock->_loop;

    return AH_ENONE;
}

ah_extern ah_err_t ah_tcp_get_remote_addr(const struct ah_tcp_sock* sock, union ah_sockaddr* remote_addr)
{
    if (sock == NULL || remote_addr == NULL) {
        return AH_EINVAL;
    }

#if AH_USE_BSD_SOCKETS
    return ah_i_sock_getpeername(sock->_fd, remote_addr);
#endif
}

ah_extern ah_err_t ah_tcp_get_user_data(const struct ah_tcp_sock* sock, void** user_data)
{
    if (sock == NULL || user_data == NULL) {
        return AH_EINVAL;
    }

    *user_data = sock->_user_data;

    return AH_ENONE;
}

ah_extern ah_err_t ah_tcp_set_keepalive(struct ah_tcp_sock* sock, bool keepalive)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }

#if AH_USE_BSD_SOCKETS
    int value = keepalive ? 1 : 0;
    if (setsockopt(sock->_fd, SOL_SOCKET, SO_KEEPALIVE, (void*) &value, sizeof(value)) != 0) {
        return errno;
    }
    return AH_ENONE;
#endif
}

ah_extern ah_err_t ah_tcp_set_no_delay(struct ah_tcp_sock* sock, bool no_delay)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }

#if AH_USE_BSD_SOCKETS
    int value = no_delay ? 1 : 0;
    if (setsockopt(sock->_fd, IPPROTO_TCP, TCP_NODELAY, (void*) &value, sizeof(value)) != 0) {
        return errno;
    }
    return AH_ENONE;
#endif
}

ah_extern ah_err_t ah_tcp_set_reuse_addr(struct ah_tcp_sock* sock, bool reuse_addr)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }

#if AH_USE_BSD_SOCKETS
    int value = reuse_addr ? 1 : 0;
    if (setsockopt(sock->_fd, SOL_SOCKET, SO_REUSEADDR, (void*) &value, sizeof(value)) != 0) {
        return errno;
    }
    return AH_ENONE;
#endif
}

ah_extern ah_err_t ah_tcp_set_user_data(struct ah_tcp_sock* sock, void* user_data)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }

    sock->_user_data = user_data;

    return AH_ENONE;
}

ah_extern ah_err_t ah_tcp_connect(struct ah_tcp_sock* sock, const union ah_sockaddr* remote_addr, ah_tcp_connect_cb cb)
{
    if (sock == NULL || !ah_sockaddr_is_ip(remote_addr) || cb == NULL) {
        return AH_EINVAL;
    }

#if AH_USE_KQUEUE

    ah_err_t err;

    if (connect(sock->_fd, ah_sockaddr_cast_const(remote_addr), ah_sockaddr_get_size(remote_addr)) != 0) {
        if (errno == EINPROGRESS) {
            struct ah_i_loop_evt* evt;
            struct kevent* req;

            err = ah_i_loop_alloc_evt_and_req(sock->_loop, &evt, &req);
            if (err != AH_ENONE) {
                return err;
            }

            evt->_cb = s_on_connect;
            evt->_body._tcp_connect._sock = sock;
            evt->_body._tcp_connect._cb = cb;

            EV_SET(req, sock->_fd, EVFILT_WRITE, EV_ADD, 0u, 0u, evt);

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

    cb(sock, AH_ENONE);

    return AH_ENONE;

#endif
}

static void s_on_connect(struct ah_i_loop_evt* evt, ah_i_loop_res_t* res)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(res != NULL);

    struct ah_tcp_sock* conn = evt->_body._tcp_connect._sock;
    ah_assert_if_debug(conn != NULL);

    ah_tcp_connect_cb cb = evt->_body._tcp_connect._cb;

#if AH_USE_KQUEUE

    ah_err_t cb_err;

    if (ah_unlikely((res->flags & EV_ERROR) != 0)) {
        cb_err = (ah_err_t) res->data;
    }
    else if (ah_unlikely((res->flags & EV_EOF) != 0)) {
        cb_err = AH_EEOF;
    }
    else {
        cb_err = AH_ENONE;
    }

    cb(conn, cb_err);

#endif
}

ah_extern ah_err_t ah_tcp_listen(struct ah_tcp_sock* sock, unsigned backlog, const struct ah_tcp_listen_ctx* ctx)
{
    if (sock == NULL || ctx == NULL || ctx->listen_cb == NULL || ctx->accept_cb == NULL || ctx->alloc_cb == NULL) {
        return AH_EINVAL;
    }

#if AH_USE_KQUEUE

    struct ah_i_loop_evt* evt;

    ah_err_t err = ah_i_loop_alloc_evt(sock->_loop, &evt);
    if (err != AH_ENONE) {
        return err;
    }

    int backlog_int = (backlog == 0u || backlog > SOMAXCONN) ? SOMAXCONN : (int) backlog;
    if (listen(sock->_fd, backlog_int) != 0) {
        err = errno;
        ah_i_loop_dealloc_evt(sock->_loop, evt);
        ctx->listen_cb(sock, err);
        return AH_ENONE;
    }

    evt->_cb = s_on_accept;
    evt->_body._tcp_listen._sock = sock;
    evt->_body._tcp_listen._ctx = ctx;

    struct kevent* req;

    err = ah_i_loop_alloc_req(sock->_loop, &req);
    if (err != AH_ENONE) {
        ah_i_loop_dealloc_evt(sock->_loop, evt);
        return err;
    }

    EV_SET(req, sock->_fd, EVFILT_READ, EV_ADD, 0u, 0, evt);

    ctx->listen_cb(sock, AH_ENONE);

    return AH_ENONE;

#endif
}

static void s_on_accept(struct ah_i_loop_evt* evt, ah_i_loop_res_t* res)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(res != NULL);

    struct ah_tcp_sock* listener = evt->_body._tcp_listen._sock;
    ah_assert_if_debug(listener != NULL);

    const struct ah_tcp_listen_ctx* ctx = evt->_body._tcp_listen._ctx;
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
        struct ah_tcp_sock* conn = NULL;

        ctx->alloc_cb(listener, &conn);

        if (conn == NULL) {
            ctx->accept_cb(listener, NULL, NULL, ENOMEM);
            continue;
        }

        union ah_sockaddr sockaddr;
        socklen_t socklen = sizeof(union ah_sockaddr);

        const int fd = accept(listener->_fd, ah_sockaddr_cast_mut(&sockaddr), &socklen);
        if (fd == -1) {
            ctx->alloc_cb(listener, &conn);
            ctx->accept_cb(listener, NULL, NULL, errno);
            continue;
        }

#    if AH_I_SOCKADDR_HAS_SIZE
        ah_assert_if_debug(socklen <= UINT8_MAX);
        sockaddr.as_any.size = socklen;
#    endif

        *conn = (struct ah_tcp_sock) {
            ._fd = fd,
            ._loop = listener->_loop,
        };

        ctx->accept_cb(listener, conn, &sockaddr, AH_ENONE);
    }

    if (ah_unlikely((kev->flags & EV_EOF) != 0)) {
        ctx->listen_cb(listener, AH_EEOF);
    }

#endif
}

ah_extern ah_err_t ah_tcp_read_start(struct ah_tcp_sock* sock, const struct ah_tcp_read_ctx* ctx)
{
    if (sock == NULL || ctx == NULL || ctx->alloc_cb == NULL || ctx->read_cb == NULL) {
        return AH_EINVAL;
    }
    if (sock->_is_reading || sock->_is_reading_shutdown) {
        return AH_ESTATE;
    }

    struct ah_i_loop_evt* evt;
    ah_i_loop_req_t* req;

    ah_err_t err = ah_i_loop_alloc_evt_and_req(sock->_loop, &evt, &req);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_read;
    evt->_body._tcp_read._sock = sock;
    evt->_body._tcp_read._ctx = ctx;

#if AH_USE_KQUEUE

    EV_SET(req, sock->_fd, EVFILT_READ, EV_ADD, 0u, 0, evt);

#endif

    sock->_is_reading = true;

    return AH_ENONE;
}

static void s_on_read(struct ah_i_loop_evt* evt, ah_i_loop_res_t* res)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(res != NULL);

    struct ah_tcp_sock* conn = evt->_body._tcp_read._sock;
    ah_assert_if_debug(conn != NULL);

    const struct ah_tcp_read_ctx* ctx = evt->_body._tcp_read._ctx;
    ah_assert_if_debug(ctx != NULL);
    ah_assert_if_debug(ctx->read_cb != NULL);
    ah_assert_if_debug(ctx->alloc_cb != NULL);

    if (!conn->_is_reading || conn->_is_reading_shutdown) {
        return;
    }

    struct ah_buf buf;
    ah_err_t err;

#if AH_USE_KQUEUE

    if (ah_unlikely((res->flags & EV_ERROR) != 0)) {
        err = (ah_err_t) res->data;
        goto call_read_cb_with_err_and_return;
    }

    size_t n_bytes_left;

    if (ah_i_add_overflow(res->data, 0, &n_bytes_left)) {
        err = AH_ERANGE;
        goto call_read_cb_with_err_and_return;
    }

    buf = (struct ah_buf) { .octets = NULL, .size = n_bytes_left };

    while (n_bytes_left != 0u) {
        ctx->alloc_cb(conn, &buf);

        if (buf.octets == NULL || buf.size == 0u) {
            err = AH_ENOMEM;
            goto call_read_cb_with_err_and_return;
        }

        if (buf.size > n_bytes_left) {
            buf.size = n_bytes_left;
        }

        ssize_t size = read(conn->_fd, buf.octets, buf.size);
        if (size < 0) {
            err = errno;
            goto call_read_cb_with_err_and_return;
        }

        buf.size = size;

        ctx->read_cb(conn, &buf, AH_ENONE);

        if (ah_i_sub_overflow(n_bytes_left, size, &n_bytes_left)) {
            err = AH_ERANGE;
            goto call_read_cb_with_err_and_return;
        }
    }

    if (ah_unlikely((res->flags & EV_EOF) != 0)) {
        err = AH_EEOF;
        conn->_is_reading_shutdown = true;
        goto call_read_cb_with_err_and_return;
    }

#endif

    return;

call_read_cb_with_err_and_return:
    ctx->read_cb(conn, err != AH_ENONE ? &buf : NULL, err);
}

ah_extern ah_err_t ah_tcp_read_stop(struct ah_tcp_sock* sock)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_reading) {
        return AH_ESTATE;
    }

    ah_i_loop_req_t* req;

    ah_err_t err = ah_i_loop_alloc_req(sock->_loop, &req);
    if (err != AH_ENONE) {
        if (err != AH_ENOMEM) {
            return err;
        }
        goto set_is_reading_to_false_and_return;
    }

#if AH_USE_KQUEUE

    EV_SET(req, sock->_fd, EVFILT_READ, EV_DELETE, 0, 0u, NULL);

#endif

set_is_reading_to_false_and_return:
    sock->_is_reading = false;
    return AH_ENONE;
}

ah_extern ah_err_t ah_tcp_write(struct ah_tcp_sock* sock, struct ah_tcp_write_ctx* ctx)
{
    if (sock == NULL || ctx == NULL || ctx->write_cb == NULL) {
        return AH_EINVAL;
    }
    if (ctx->bufvec.items == NULL && ctx->bufvec.length != 0u) {
        return AH_EINVAL;
    }
    if (sock->_is_writing || sock->_is_writing_shutdown) {
        return AH_ESTATE;
    }

    struct ah_i_loop_evt* evt;
    ah_i_loop_req_t* req;

    ah_err_t err = ah_i_loop_alloc_evt_and_req(sock->_loop, &evt, &req);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_write;
    evt->_body._tcp_write._sock = sock;
    evt->_body._tcp_write._ctx = ctx;

#if AH_USE_KQUEUE

    EV_SET(req, sock->_fd, EVFILT_WRITE, EV_ADD, 0u, 0, evt);

    sock->_is_writing = true;

    return AH_ENONE;

#endif
}

static void s_on_write(struct ah_i_loop_evt* evt, ah_i_loop_res_t* res)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(res != NULL);

    struct ah_tcp_sock* conn = evt->_body._tcp_write._sock;
    ah_assert_if_debug(conn != NULL);

    struct ah_tcp_write_ctx* ctx = evt->_body._tcp_write._ctx;
    ah_assert_if_debug(ctx != NULL);
    ah_assert_if_debug(ctx->write_cb != NULL);
    ah_assert_if_debug(ctx->bufvec.items != NULL || ctx->bufvec.length == 0u);

    if (!conn->_is_writing || conn->_is_writing_shutdown) {
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
        conn->_is_writing_shutdown = true;
        goto set_is_writing_to_false_and_call_write_cb_with_conn_err;
    }

    struct iovec* iov;
    int iovcnt;
    err = ah_bufvec_to_iovec(&ctx->bufvec, &iov, &iovcnt);
    if (ah_unlikely(err != AH_ENONE)) {
        err = AH_EDOM;
        goto set_is_writing_to_false_and_call_write_cb_with_conn_err;
    }

    ssize_t write_res = writev(conn->_fd, iov, iovcnt);
    if (ah_unlikely(write_res < 0)) {
        err = errno;
        goto set_is_writing_to_false_and_call_write_cb_with_conn_err;
    }

#else

    (void) res;
    (void) ctx;
    (void) err;

    size_t write_res;
    (void) write_res;

    err = AH_ENOIMPL;
    goto set_is_writing_to_false_and_call_write_cb_with_conn_err;

#endif

    size_t item_i = 0u;
    for (size_t byte_i = write_res; byte_i != 0u; item_i += 1u) {
        struct ah_buf* buf = &ctx->bufvec.items[item_i];

        if (byte_i > buf->size) {
            byte_i -= buf->size;
            buf->size = 0u;
            continue;
        }

        buf->octets = &buf->octets[byte_i];
        buf->size -= byte_i;

        if (buf->size == 0u) {
            item_i += 1u;
        }

        break;
    }

    ctx->bufvec.items = &ctx->bufvec.items[item_i];
    ctx->bufvec.length -= item_i;

    if (ctx->bufvec.length > 0u) {
        return;
    }

#if AH_USE_KQUEUE

    ah_i_loop_req_t* req;
    err = ah_i_loop_alloc_req(conn->_loop, &req);
    if (err != AH_ENONE && err != AH_ENOMEM) {
        goto set_is_writing_to_false_and_call_write_cb_with_conn_err;
    }

    EV_SET(req, conn->_fd, EVFILT_WRITE, EV_DISABLE, 0u, 0, NULL);

#endif

    err = AH_ENONE;

set_is_writing_to_false_and_call_write_cb_with_conn_err:
    conn->_is_writing = false;
    ctx->write_cb(conn, err);
}

ah_extern ah_err_t ah_tcp_shutdown(struct ah_tcp_sock* sock, ah_tcp_shutdown_t flags)
{
    if (sock == NULL || (flags & ~AH_TCP_SHUTDOWN_RDWR) != 0u) {
        return AH_EINVAL;
    }
    if ((flags & AH_TCP_SHUTDOWN_RDWR) == 0u) {
        return AH_ENONE;
    }

#if AH_USE_POSIX

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
        ah_abort();
    }

#    endif

    if (shutdown(sock->_fd, how) != 0) {
        err = errno;
    }
    else {
        err = AH_ENONE;

        if ((flags & AH_TCP_SHUTDOWN_RD) != 0) {
            sock->_is_reading = false;
            sock->_is_reading_shutdown = true;
        }
        if ((flags & AH_TCP_SHUTDOWN_WR) != 0) {
            sock->_is_writing = false;
            sock->_is_writing_shutdown = true;
        }
    }

    return err;

#endif
}

ah_extern ah_err_t ah_tcp_close(struct ah_tcp_sock* sock, ah_tcp_close_cb cb)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }

#if AH_USE_BSD_SOCKETS

    ah_err_t err = ah_i_sock_close(sock->_loop, sock->_fd);

#    ifndef NDEBUG
    sock->_fd = 0;
#    endif

    if (cb != NULL) {
        cb(sock, err);
    }

    return err;

#endif
}

ah_extern ah_err_t ah_tcp_term(struct ah_tcp_sock* sock)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }

#ifndef NDEBUG
    if (sock->_fd != 0) {
        return AH_ESTATE;
    }
    *sock = (struct ah_tcp_sock) { 0 };
#endif

    return AH_ENONE;
}
