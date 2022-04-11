// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_UDP_H_
#define AH_UDP_H_

#include "buf.h"
#include "err.h"
#include "ip.h"
#include "sock.h"

#include <stdbool.h>

#if AH_USE_IOCP
#    include <winsock2.h>
#endif

typedef void (*ah_udp_open_cb)(struct ah_udp_sock* sock, ah_err_t err);
typedef void (*ah_udp_close_cb)(struct ah_udp_sock* sock, ah_err_t err);

struct ah_udp_group_ipv4 {
    struct ah_ipaddr_v4 group_addr;
    struct ah_ipaddr_v4 interface_addr; // Default if zeroed.
};

struct ah_udp_group_ipv6 {
    struct ah_ipaddr_v6 group_addr;
    uint32_t zone_id; // Default if zero.
};

union ah_udp_group {
    struct ah_udp_group_ipv4 as_ipv4;
    struct ah_udp_group_ipv6 as_ipv6;
};

struct ah_udp_recv_ctx {
    void (*recv_cb)(struct ah_udp_sock* sock, union ah_sockaddr* addr, struct ah_buf* buf, ah_err_t err);
    void (*alloc_cb)(struct ah_udp_sock* sock, struct ah_buf* buf);
};

struct ah_udp_send_ctx {
    void (*send_cb)(struct ah_udp_sock* sock, ah_err_t err);
    union ah_sockaddr remote_addr;
    struct ah_bufvec bufvec;
};

struct ah_udp_sock {
    struct ah_loop* _loop;
    void* _user_data;

#if AH_USE_BSD_SOCKETS
    ah_sockfd_t _fd;
#endif

    bool _is_open;
    bool _is_ipv6;
    bool _is_receiving;
};

ah_extern ah_err_t ah_udp_init(struct ah_udp_sock* sock, struct ah_loop* loop, void* user_data);
ah_extern ah_err_t ah_udp_open(struct ah_udp_sock* sock, const union ah_sockaddr* local_addr, ah_udp_open_cb cb);

ah_extern ah_err_t ah_udp_get_local_addr(const struct ah_udp_sock* sock, union ah_sockaddr* local_addr);

#if AH_USE_BSD_SOCKETS
ah_extern_inline ah_sockfd_t ah_udp_get_fd(const struct ah_udp_sock* sock)
{
    ah_assert_if_debug(sock != NULL);
    return sock->_fd;
}
#endif

ah_extern_inline struct ah_loop* ah_udp_get_loop(const struct ah_udp_sock* sock)
{
    ah_assert_if_debug(sock != NULL);
    return sock->_loop;
}

ah_extern_inline void* ah_udp_get_user_data(const struct ah_udp_sock* sock)
{
    ah_assert_if_debug(sock != NULL);
    return sock->_user_data;
}

ah_extern ah_err_t ah_udp_set_multicast_hop_limit(struct ah_udp_sock* sock, uint8_t hop_limit);
ah_extern ah_err_t ah_udp_set_multicast_loopback(struct ah_udp_sock* sock, bool loopback);
ah_extern ah_err_t ah_udp_set_reuse_addr(struct ah_udp_sock* sock, bool reuseaddr);
ah_extern ah_err_t ah_udp_set_unicast_hop_limit(struct ah_udp_sock* sock, uint8_t hop_limit);

ah_extern_inline void ah_udp_set_user_data(struct ah_udp_sock* sock, void* user_data)
{
    ah_assert_if_debug(sock != NULL);
    sock->_user_data = user_data;
}

ah_extern ah_err_t ah_udp_join(struct ah_udp_sock* sock, const union ah_udp_group* group);
ah_extern ah_err_t ah_udp_leave(struct ah_udp_sock* sock, const union ah_udp_group* group);

ah_extern ah_err_t ah_udp_send(struct ah_udp_sock* sock, struct ah_udp_send_ctx* ctx);
ah_extern ah_err_t ah_udp_recv_start(struct ah_udp_sock* sock, const struct ah_udp_recv_ctx* ctx);
ah_extern ah_err_t ah_udp_recv_stop(struct ah_udp_sock* sock);

ah_extern ah_err_t ah_udp_close(struct ah_udp_sock* sock, ah_udp_close_cb cb);
ah_extern ah_err_t ah_udp_term(struct ah_udp_sock* sock);

#endif
