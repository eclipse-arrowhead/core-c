// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/udp.h"

#include "ah/assert.h"
#include "ah/loop-internal.h"
#include "ah/loop.h"
#include "ah/math.h"
#include "sock-internal.h"

#if AH_USE_URING
static void s_on_close(struct ah_i_loop_evt* evt, ah_i_loop_res_t* res);
#endif
static void s_on_recv(struct ah_i_loop_evt* evt, ah_i_loop_res_t* res);
static void s_on_send(struct ah_i_loop_evt* evt, ah_i_loop_res_t* res);

static ah_err_t s_prep_recv(struct ah_udp_sock* sock, struct ah_udp_recv_ctx* ctx);

ah_extern ah_err_t ah_udp_init(struct ah_udp_sock* sock, struct ah_loop* loop, void* user_data)
{
    if (sock == NULL || loop == NULL) {
        return AH_EINVAL;
    }
    *sock = (struct ah_udp_sock) {
        ._loop = loop,
        ._user_data = user_data,
        ._is_open = false,
    };
    return AH_ENONE;
}

ah_extern ah_err_t ah_udp_open(struct ah_udp_sock* sock, const union ah_sockaddr* local_addr, ah_udp_open_cb cb)
{
    if (sock == NULL || local_addr == NULL) {
        return AH_EINVAL;
    }
    if (sock->_is_open) {
        return AH_ESTATE;
    }

#if AH_USE_BSD_SOCKETS

    ah_err_t err = ah_i_sock_open(sock->_loop, AH_I_SOCK_DGRAM, local_addr, &sock->_fd);

    if (err == AH_ENONE) {
        sock->_is_open = true;
        sock->_is_ipv6 = local_addr->as_any.family == AH_SOCKFAMILY_IPV6;
    }

    if (cb != NULL) {
        cb(sock, err);
        return AH_ENONE;
    }

    return err;
#endif
}

ah_extern ah_err_t ah_udp_get_local_addr(const struct ah_udp_sock* sock, union ah_sockaddr* local_addr)
{
    if (sock == NULL || local_addr == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open) {
        return AH_ESTATE;
    }

#if AH_USE_BSD_SOCKETS
    return ah_i_sock_getsockname(sock->_fd, local_addr);
#endif
}

ah_extern ah_err_t ah_udp_set_multicast_hop_limit(struct ah_udp_sock* sock, uint8_t hop_limit)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open) {
        return AH_ESTATE;
    }

#if AH_USE_BSD_SOCKETS

    int level;
    int name;

    if (sock->_is_ipv6) {
        level = IPPROTO_IPV6;
        name = IPV6_MULTICAST_HOPS;
    }
    else {
        level = IPPROTO_IP;
        name = IP_MULTICAST_TTL;
    }

    int value = hop_limit;
    if (setsockopt(sock->_fd, level, name, (void*) &value, sizeof(value)) != 0) {
        return errno;
    }

    return AH_ENONE;

#endif
}

ah_extern ah_err_t ah_udp_set_multicast_loopback(struct ah_udp_sock* sock, bool loopback)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open) {
        return AH_ESTATE;
    }

#if AH_USE_BSD_SOCKETS

    int level;
    int name;

    if (sock->_is_ipv6) {
        level = IPPROTO_IPV6;
        name = IPV6_MULTICAST_LOOP;
    }
    else {
        level = IPPROTO_IP;
        name = IP_MULTICAST_LOOP;
    }

    int value = loopback ? 1 : 0;
    if (setsockopt(sock->_fd, level, name, (void*) &value, sizeof(value)) != 0) {
        return errno;
    }

    return AH_ENONE;

#endif
}

ah_extern ah_err_t ah_udp_set_reuse_addr(struct ah_udp_sock* sock, bool reuse_addr)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open) {
        return AH_ESTATE;
    }

#if AH_USE_BSD_SOCKETS
    int value = reuse_addr ? 1 : 0;
    if (setsockopt(sock->_fd, SOL_SOCKET, SO_REUSEADDR, (void*) &value, sizeof(value)) != 0) {
        return errno;
    }
    return AH_ENONE;
#endif
}

ah_extern ah_err_t ah_udp_set_unicast_hop_limit(struct ah_udp_sock* sock, uint8_t hop_limit)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open) {
        return AH_ESTATE;
    }

#if AH_USE_BSD_SOCKETS

    int level;
    int name;

    if (sock->_is_ipv6) {
        level = IPPROTO_IPV6;
        name = IPV6_UNICAST_HOPS;
    }
    else {
        level = IPPROTO_IP;
        name = IP_TTL;
    }

    int value = hop_limit;
    if (setsockopt(sock->_fd, level, name, (void*) &value, sizeof(value)) != 0) {
        return errno;
    }

    return AH_ENONE;

#endif
}

ah_extern ah_err_t ah_udp_join(struct ah_udp_sock* sock, const union ah_udp_group* group)
{
    if (sock == NULL || group == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open) {
        return AH_ESTATE;
    }

#if AH_USE_BSD_SOCKETS

    int level;
    int name;

    if (sock->_is_ipv6) {
        level = IPPROTO_IPV6;
        name = IPV6_JOIN_GROUP;
    }
    else {
        level = IPPROTO_IP;
        name = IP_ADD_MEMBERSHIP;
    }

    if (setsockopt(sock->_fd, level, name, (void*) group, sizeof(union ah_udp_group)) != 0) {
        return errno;
    }

    return AH_ENONE;

#endif
}

ah_extern ah_err_t ah_udp_leave(struct ah_udp_sock* sock, const union ah_udp_group* group)
{
    if (sock == NULL || group == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open) {
        return AH_ESTATE;
    }

#if AH_USE_BSD_SOCKETS

    int level;
    int name;

    if (sock->_is_ipv6) {
        level = IPPROTO_IPV6;
        name = IPV6_LEAVE_GROUP;
    }
    else {
        level = IPPROTO_IP;
        name = IP_DROP_MEMBERSHIP;
    }

    if (setsockopt(sock->_fd, level, name, (void*) group, sizeof(union ah_udp_group)) != 0) {
        return errno;
    }

    return AH_ENONE;

#endif
}

ah_extern ah_err_t ah_udp_recv_start(struct ah_udp_sock* sock, struct ah_udp_recv_ctx* ctx)
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

static ah_err_t s_prep_recv(struct ah_udp_sock* sock, struct ah_udp_recv_ctx* ctx)
{
    ah_assert_if_debug(sock != NULL);
    ah_assert_if_debug(ctx != NULL);

    struct ah_i_loop_evt* evt;
    ah_i_loop_req_t* req;

    ah_err_t err = ah_i_loop_alloc_evt_and_req(sock->_loop, &evt, &req);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_recv;
    evt->_body._udp_recv._sock = sock;
    evt->_body._udp_recv._ctx = ctx;

#if AH_USE_KQUEUE

    EV_SET(req, sock->_fd, EVFILT_READ, EV_ADD, 0u, 0, evt);

#elif AH_USE_URING

    struct ah_bufvec bufvec = { .items = NULL, .length = 0u };
    ctx->alloc_cb(sock, &bufvec, 0u);
    if (bufvec.items == NULL) {
        return AH_ENOMEM;
    }

    struct iovec* iov;
    int iovcnt;
    err = ah_bufvec_into_iovec(&bufvec, &iov, &iovcnt);
    if (ah_unlikely(err != AH_ENONE)) {
        return err;
    }

    ctx->_msghdr = (struct msghdr) {
        .msg_name = ah_sockaddr_cast(&ctx->_remote_addr),
        .msg_namelen = sizeof(union ah_sockaddr),
        .msg_iov = iov,
        .msg_iovlen = iovcnt,
    };

    io_uring_prep_recvmsg(req, sock->_fd, &ctx->_msghdr, 0);
    io_uring_sqe_set_data(req, evt);

#endif

    return AH_ENONE;
}

static void s_on_recv(struct ah_i_loop_evt* evt, ah_i_loop_res_t* res)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(res != NULL);

    struct ah_udp_sock* sock = evt->_body._udp_recv._sock;
    ah_assert_if_debug(sock != NULL);

    struct ah_udp_recv_ctx* ctx = evt->_body._udp_recv._ctx;
    ah_assert_if_debug(ctx != NULL);
    ah_assert_if_debug(ctx->recv_cb != NULL);
    ah_assert_if_debug(ctx->alloc_cb != NULL);

    if (!sock->_is_open || !sock->_is_receiving) {
        return;
    }

    ah_err_t err;

#if AH_USE_KQUEUE

    if (ah_unlikely((res->flags & EV_ERROR) != 0)) {
        err = (ah_err_t) res->data;
        goto call_recv_cb_with_err_and_return;
    }

    size_t dgram_size;

    if (ah_i_add_overflow(res->data, 0, &dgram_size)) {
        err = AH_ERANGE;
        goto call_recv_cb_with_err_and_return;
    }

    struct ah_bufvec bufvec = { .items = NULL, .length = 0u };
    ctx->alloc_cb(sock, &bufvec, dgram_size);
    if (bufvec.items == NULL) {
        err = AH_ENOMEM;
        goto call_recv_cb_with_err_and_return;
    }

    struct iovec* iov;
    int iovcnt;
    err = ah_bufvec_into_iovec(&bufvec, &iov, &iovcnt);
    if (ah_unlikely(err != AH_ENONE)) {
        goto call_recv_cb_with_err_and_return;
    }

    union ah_sockaddr remote_addr;
    socklen_t socklen = sizeof(remote_addr);

    struct msghdr msghdr = {
        .msg_name = ah_sockaddr_cast(&remote_addr),
        .msg_namelen = socklen,
        .msg_iov = iov,
        .msg_iovlen = iovcnt,
    };

    ssize_t n_bytes_read = recvmsg(sock->_fd, &msghdr, 0);
    if (n_bytes_read < 0) {
        err = errno;
        goto call_recv_cb_with_err_and_return;
    }

    ctx->recv_cb(sock, &remote_addr, &bufvec, n_bytes_read, AH_ENONE);

    if (ah_unlikely((res->flags & EV_EOF) != 0)) {
        err = AH_EEOF;
        goto call_recv_cb_with_err_and_return;
    }

#elif AH_USE_URING

    struct io_uring_cqe* cqe = res;
    ah_assert_if_debug(cqe != NULL);

    if (ah_unlikely(cqe->res < 0)) {
        err = -(cqe->res);
        goto call_recv_cb_with_err_and_return;
    }

    struct ah_bufvec bufvec;
    err = ah_bufvec_from_iovec(&bufvec, ctx->_msghdr.msg_iov, 0);
    if (err != AH_ENONE) {
        goto call_recv_cb_with_err_and_return;
    }
    bufvec.length = ctx->_msghdr.msg_iovlen;

    ctx->recv_cb(sock, &ctx->_remote_addr, &bufvec, cqe->res, AH_ENONE);

    err = s_prep_recv(sock, ctx);
    if (err != AH_ENONE) {
        goto call_recv_cb_with_err_and_return;
    }

#endif

    return;

call_recv_cb_with_err_and_return:
    ctx->recv_cb(sock, NULL, NULL, 0u, err);
}

ah_extern ah_err_t ah_udp_recv_stop(struct ah_udp_sock* sock)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_receiving) {
        return AH_ESTATE;
    }
    sock->_is_receiving = false;

#if AH_USE_KQUEUE

    ah_i_loop_req_t* req;
    ah_err_t err = ah_i_loop_alloc_req(sock->_loop, &req);
    if (err == AH_ENONE) {
        EV_SET(req, sock->_fd, EVFILT_READ, EV_DELETE, 0, 0u, NULL);
    }
    else if (err == AH_ENOMEM) {
        return err;
    }

#endif

    return AH_ENONE;
}

ah_extern ah_err_t ah_udp_send(struct ah_udp_sock* sock, struct ah_udp_send_ctx* ctx)
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

    struct ah_i_loop_evt* evt;
    ah_i_loop_req_t* req;

    ah_err_t err = ah_i_loop_alloc_evt_and_req(sock->_loop, &evt, &req);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_send;
    evt->_body._udp_send._sock = sock;
    evt->_body._udp_send._ctx = ctx;

#if AH_USE_KQUEUE

    EV_SET(req, sock->_fd, EVFILT_WRITE, EV_ADD | EV_ONESHOT, 0u, 0, evt);

#elif AH_USE_URING

    struct iovec* iov;
    int iovcnt;
    err = ah_bufvec_into_iovec(&ctx->bufvec, &iov, &iovcnt);
    if (err != AH_ENONE) {
        return err;
    }

    ctx->_msghdr = (struct msghdr) {
        .msg_name = ah_sockaddr_cast(&ctx->remote_addr),
        .msg_namelen = ah_sockaddr_get_size(&ctx->remote_addr),
        .msg_iov = iov,
        .msg_iovlen = iovcnt,
    };

    io_uring_prep_sendmsg(req, sock->_fd, &ctx->_msghdr, 0u);
    io_uring_sqe_set_data(req, evt);

#endif

    return AH_ENONE;
}

static void s_on_send(struct ah_i_loop_evt* evt, ah_i_loop_res_t* res)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(res != NULL);

    struct ah_udp_sock* sock = evt->_body._udp_send._sock;
    ah_assert_if_debug(sock != NULL);

    struct ah_udp_send_ctx* ctx = evt->_body._udp_send._ctx;
    ah_assert_if_debug(ctx != NULL);
    ah_assert_if_debug(ctx->send_cb != NULL);
    ah_assert_if_debug(ctx->bufvec.items != NULL || ctx->bufvec.length == 0u);

    ah_err_t err;

#if AH_USE_KQUEUE

    if (ah_unlikely((res->flags & EV_ERROR) != 0)) {
        err = (ah_err_t) res->data;
        goto call_send_cb_with_sock_and_err;
    }

    if (ah_unlikely((res->flags & EV_EOF) != 0)) {
        err = AH_EEOF;
        goto call_send_cb_with_sock_and_err;
    }

    struct iovec* iov;
    int iovcnt;
    err = ah_bufvec_into_iovec(&ctx->bufvec, &iov, &iovcnt);
    if (ah_unlikely(err != AH_ENONE)) {
        err = AH_EDOM;
        goto call_send_cb_with_sock_and_err;
    }

    struct msghdr msghdr = {
        .msg_name = ah_sockaddr_cast(&ctx->remote_addr),
        .msg_namelen = ah_sockaddr_get_size(&ctx->remote_addr),
        .msg_iov = iov,
        .msg_iovlen = iovcnt,
    };

    ssize_t send_res = sendmsg(sock->_fd, &msghdr, 0);
    if (ah_unlikely(send_res < 0)) {
        err = errno;
        goto call_send_cb_with_sock_and_err;
    }

#elif AH_USE_URING

    struct io_uring_cqe* cqe = res;
    ah_assert_if_debug(cqe != NULL);

    if (ah_unlikely(cqe->res < 0)) {
        err = -(cqe->res);
        goto call_send_cb_with_sock_and_err;
    }

#endif

    err = AH_ENONE;

call_send_cb_with_sock_and_err:
    ctx->send_cb(sock, err);
}

ah_extern ah_err_t ah_udp_close(struct ah_udp_sock* sock, ah_udp_close_cb cb)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open) {
        return AH_ESTATE;
    }
    sock->_is_open = false;

    ah_err_t err;

#if AH_USE_URING

    struct ah_i_loop_evt* evt;
    ah_i_loop_req_t* req;

    err = ah_i_loop_alloc_evt_and_req(sock->_loop, &evt, &req);
    if (err == AH_ENONE) {
        evt->_cb = s_on_close;
        evt->_body._udp_close._sock = sock;
        evt->_body._udp_close._cb = cb;

        io_uring_prep_close(req, sock->_fd);
        io_uring_sqe_set_data(req, evt);

        return AH_ENONE;
    }

#endif

#if AH_USE_BSD_SOCKETS

    err = ah_i_sock_close(sock->_loop, sock->_fd);

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
static void s_on_close(struct ah_i_loop_evt* evt, ah_i_loop_res_t* res)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(res != NULL);

    struct ah_udp_sock* sock = evt->_body._udp_close._sock;
    ah_assert_if_debug(sock != NULL);

    ah_udp_close_cb cb = evt->_body._udp_close._cb;

    if (cb != NULL) {
        cb(sock, -(res->res));
    }
}
#endif

ah_extern ah_err_t ah_udp_term(struct ah_udp_sock* sock)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }

#ifndef NDEBUG
    if (sock->_fd != 0) {
        return AH_ESTATE;
    }
    *sock = (struct ah_udp_sock) { 0 };
#endif

    return AH_ENONE;
}
