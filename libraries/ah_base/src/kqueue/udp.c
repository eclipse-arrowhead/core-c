// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/udp.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"

static void s_on_recv(ah_i_loop_evt_t* evt, ah_i_loop_res_t* res);
static void s_on_send(ah_i_loop_evt_t* evt, ah_i_loop_res_t* res);

ah_extern ah_err_t ah_udp_open(ah_udp_sock_t* sock, ah_loop_t* loop, const ah_sockaddr_t* local_addr, ah_udp_open_cb cb)
{
    if (sock == NULL || loop == NULL || local_addr == NULL) {
        return AH_EINVAL;
    }

    ah_i_sockfd_t fd;
    ah_err_t err = ah_i_sock_open(loop, AH_I_SOCK_DGRAM, local_addr, &fd);

    if (err == AH_ENONE) {
        *sock = (ah_udp_sock_t) {
            ._loop = loop,
            ._fd = fd,
            ._is_ipv6 = local_addr->as_any.family == AH_SOCKFAMILY_IPV6,
            ._is_open = true,
        };
    }

    if (cb != NULL) {
        cb(sock, err);
        return AH_ENONE;
    }

    return err;
}

ah_extern ah_err_t ah_udp_get_local_addr(const ah_udp_sock_t* sock, ah_sockaddr_t* local_addr)
{
    if (sock == NULL || local_addr == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open) {
        return AH_ESTATE;
    }
    return ah_i_sock_getsockname(sock->_fd, local_addr);
}

ah_extern ah_err_t ah_udp_set_multicast_hop_limit(ah_udp_sock_t* sock, uint8_t hop_limit)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open) {
        return AH_ESTATE;
    }

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
}

ah_extern ah_err_t ah_udp_set_multicast_loopback(ah_udp_sock_t* sock, bool loopback)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open) {
        return AH_ESTATE;
    }

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
}

ah_extern ah_err_t ah_udp_set_reuse_addr(ah_udp_sock_t* sock, bool reuse_addr)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open) {
        return AH_ESTATE;
    }
    int value = reuse_addr ? 1 : 0;
    if (setsockopt(sock->_fd, SOL_SOCKET, SO_REUSEADDR, (void*) &value, sizeof(value)) != 0) {
        return errno;
    }
    return AH_ENONE;
}

ah_extern ah_err_t ah_udp_set_unicast_hop_limit(ah_udp_sock_t* sock, uint8_t hop_limit)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open) {
        return AH_ESTATE;
    }

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
}

ah_extern ah_err_t ah_udp_join(ah_udp_sock_t* sock, const ah_udp_group_t* group)
{
    if (sock == NULL || group == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open) {
        return AH_ESTATE;
    }

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

    if (setsockopt(sock->_fd, level, name, (void*) group, sizeof(ah_udp_group_t)) != 0) {
        return errno;
    }

    return AH_ENONE;
}

ah_extern ah_err_t ah_udp_leave(ah_udp_sock_t* sock, const ah_udp_group_t* group)
{
    if (sock == NULL || group == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open) {
        return AH_ESTATE;
    }

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

    if (setsockopt(sock->_fd, level, name, (void*) group, sizeof(ah_udp_group_t)) != 0) {
        return errno;
    }

    return AH_ENONE;
}

ah_extern ah_err_t ah_udp_recv_start(ah_udp_sock_t* sock, ah_udp_recv_ctx_t* ctx)
{
    if (sock == NULL || ctx == NULL || ctx->alloc_cb == NULL || ctx->recv_cb == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open || sock->_is_receiving) {
        return AH_ESTATE;
    }

    ah_i_loop_evt_t* evt;
    struct kevent* kev;

    ah_err_t err = ah_i_loop_evt_alloc_with_kev(sock->_loop, &evt, &kev);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_recv;
    evt->_body._udp_recv._sock = sock;
    evt->_body._udp_recv._ctx = ctx;

    EV_SET(kev, sock->_fd, EVFILT_READ, EV_ADD, 0u, 0, evt);

    sock->_is_receiving = true;

    return AH_ENONE;
}

static void s_on_recv(ah_i_loop_evt_t* evt, ah_i_loop_res_t* res)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(res != NULL);

    ah_udp_sock_t* sock = evt->_body._udp_recv._sock;
    ah_assert_if_debug(sock != NULL);

    ah_udp_recv_ctx_t* ctx = evt->_body._udp_recv._ctx;
    ah_assert_if_debug(ctx != NULL);
    ah_assert_if_debug(ctx->recv_cb != NULL);
    ah_assert_if_debug(ctx->alloc_cb != NULL);

    if (!sock->_is_open || !sock->_is_receiving) {
        return;
    }

    ah_err_t err;

    if (ah_unlikely((res->flags & EV_ERROR) != 0)) {
        err = (ah_err_t) res->data;
        goto call_recv_cb_with_err_and_return;
    }

    size_t dgram_size;

    if (ah_p_add_overflow(res->data, 0, &dgram_size)) {
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
    err = ah_i_bufvec_into_iovec(&bufvec, &iov, &iovcnt);
    if (ah_unlikely(err != AH_ENONE)) {
        goto call_recv_cb_with_err_and_return;
    }

    ah_sockaddr_t remote_addr;
    socklen_t socklen = sizeof(remote_addr);

    struct msghdr msghdr = {
        .msg_name = ah_i_sockaddr_cast(&remote_addr),
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

    if (!sock->_is_open) {
        return;
    }

    if (ah_unlikely((res->flags & EV_EOF) != 0)) {
        err = AH_EEOF;
        goto call_recv_cb_with_err_and_return;
    }

    return;

call_recv_cb_with_err_and_return:
    ctx->recv_cb(sock, NULL, NULL, 0u, err);
}

ah_extern ah_err_t ah_udp_recv_stop(ah_udp_sock_t* sock)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_receiving) {
        return AH_ESTATE;
    }
    sock->_is_receiving = false;

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

ah_extern ah_err_t ah_udp_send(ah_udp_sock_t* sock, ah_udp_send_ctx_t* ctx)
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

    ah_i_loop_evt_t* evt;
    struct kevent* kev;

    ah_err_t err = ah_i_loop_evt_alloc_with_kev(sock->_loop, &evt, &kev);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_send;
    evt->_body._udp_send._sock = sock;
    evt->_body._udp_send._ctx = ctx;

    EV_SET(kev, sock->_fd, EVFILT_WRITE, EV_ADD | EV_ONESHOT, 0u, 0, evt);

    return AH_ENONE;
}

static void s_on_send(ah_i_loop_evt_t* evt, ah_i_loop_res_t* res)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(res != NULL);

    ah_udp_sock_t* sock = evt->_body._udp_send._sock;
    ah_assert_if_debug(sock != NULL);

    ah_udp_send_ctx_t* ctx = evt->_body._udp_send._ctx;
    ah_assert_if_debug(ctx != NULL);
    ah_assert_if_debug(ctx->send_cb != NULL);
    ah_assert_if_debug(ctx->bufvec.items != NULL || ctx->bufvec.length == 0u);

    ah_err_t err;

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
    err = ah_i_bufvec_into_iovec(&ctx->bufvec, &iov, &iovcnt);
    if (ah_unlikely(err != AH_ENONE)) {
        err = AH_EDOM;
        goto call_send_cb_with_sock_and_err;
    }

    struct msghdr msghdr = {
        .msg_name = ah_i_sockaddr_cast(&ctx->remote_addr),
        .msg_namelen = ah_i_sockaddr_get_size(&ctx->remote_addr),
        .msg_iov = iov,
        .msg_iovlen = iovcnt,
    };

    ssize_t send_res = sendmsg(sock->_fd, &msghdr, 0);
    if (ah_unlikely(send_res < 0)) {
        err = errno;
        goto call_send_cb_with_sock_and_err;
    }

    err = AH_ENONE;

call_send_cb_with_sock_and_err:
    ctx->send_cb(sock, err);
}

ah_extern ah_err_t ah_udp_close(ah_udp_sock_t* sock, ah_udp_close_cb cb)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open) {
        return AH_ESTATE;
    }
#ifndef NDEBUG
    if (sock->_fd == 0) {
        return AH_ESTATE;
    }
#endif
    sock->_is_open = false;

    ah_err_t err = ah_i_sock_close(sock->_loop, sock->_fd);

#ifndef NDEBUG
    sock->_fd = 0;
#endif

    if (cb != NULL) {
        cb(sock, err);
    }

    return err;
}
