// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_UDP_H_
#define AH_UDP_H_

#include "assert.h"
#include "buf.h"
#include "internal/udp.h"
#include "sock.h"

#include <stdbool.h>

typedef void (*ah_udp_open_cb)(ah_udp_sock_t* sock, ah_err_t err);
typedef void (*ah_udp_close_cb)(ah_udp_sock_t* sock, ah_err_t err);

struct ah_udp_group_ipv4 {
    ah_ipaddr_v4_t group_addr;
    ah_ipaddr_v4_t interface_addr; // Default if zeroed.
};

struct ah_udp_group_ipv6 {
    ah_ipaddr_v6_t group_addr;
    uint32_t zone_id; // Default if zero.
};

union ah_udp_group {
    ah_udp_group_ipv4_t as_ipv4;
    ah_udp_group_ipv6_t as_ipv6;
};

struct ah_udp_recv_ctx {
    void (*recv_cb)(ah_udp_sock_t* sock, ah_sockaddr_t* remote_addr, ah_bufs_t* bufs, size_t n_bytes_read,
        ah_err_t err);
    void (*alloc_cb)(ah_udp_sock_t* sock, ah_bufs_t* bufs, size_t n_bytes_expected);

    AH_I_UDP_RECV_CTX_FIELDS
};

struct ah_udp_send_ctx {
    void (*send_cb)(ah_udp_sock_t* sock, ah_err_t err);
    ah_sockaddr_t remote_addr;
    ah_bufs_t bufs;

    AH_I_UDP_SEND_CTX_FIELDS
};

struct ah_udp_sock {
    AH_I_UDP_SOCK_FIELDS
};

ah_inline void ah_udp_init(ah_udp_sock_t* sock, ah_loop_t* loop)
{
    ah_assert_if_debug(sock != NULL);
    ah_assert_if_debug(loop != NULL);

    *sock = (ah_udp_sock_t) { ._loop = loop };
}

ah_extern ah_err_t ah_udp_open(ah_udp_sock_t* sock, const ah_sockaddr_t* local_addr, ah_udp_open_cb cb);

ah_extern ah_err_t ah_udp_get_local_addr(const ah_udp_sock_t* sock, ah_sockaddr_t* local_addr);

ah_inline ah_loop_t* ah_udp_get_loop(const ah_udp_sock_t* sock)
{
    ah_assert_if_debug(sock != NULL);
    return sock->_loop;
}

ah_inline void* ah_udp_get_user_data(const ah_udp_sock_t* sock)
{
    ah_assert_if_debug(sock != NULL);
    return sock->_user_data;
}

ah_extern ah_err_t ah_udp_set_multicast_hop_limit(ah_udp_sock_t* sock, uint8_t hop_limit);
ah_extern ah_err_t ah_udp_set_multicast_loopback(ah_udp_sock_t* sock, bool loopback);
ah_extern ah_err_t ah_udp_set_reuse_addr(ah_udp_sock_t* sock, bool reuseaddr);
ah_extern ah_err_t ah_udp_set_unicast_hop_limit(ah_udp_sock_t* sock, uint8_t hop_limit);

ah_inline void ah_udp_set_user_data(ah_udp_sock_t* sock, void* user_data)
{
    ah_assert_if_debug(sock != NULL);
    sock->_user_data = user_data;
}

ah_extern ah_err_t ah_udp_join(ah_udp_sock_t* sock, const ah_udp_group_t* group);
ah_extern ah_err_t ah_udp_leave(ah_udp_sock_t* sock, const ah_udp_group_t* group);

ah_extern ah_err_t ah_udp_send(ah_udp_sock_t* sock, ah_udp_send_ctx_t* ctx);
ah_extern ah_err_t ah_udp_recv_start(ah_udp_sock_t* sock, ah_udp_recv_ctx_t* ctx);
ah_extern ah_err_t ah_udp_recv_stop(ah_udp_sock_t* sock);  // Caller is responsible for freeing any memory allocated by ah_udp_recv_start().

ah_extern ah_err_t ah_udp_close(ah_udp_sock_t* sock, ah_udp_close_cb cb);

#endif
