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

struct ah_udp_omsg {
    AH_I_UDP_OMSG_FIELDS
};

struct ah_udp_sock {
    AH_I_UDP_SOCK_FIELDS
};

struct ah_udp_sock_vtab {
    void (*on_open)(ah_udp_sock_t* sock, ah_err_t err);
    void (*on_connect)(ah_udp_sock_t* sock, ah_err_t err);
    void (*on_close)(ah_udp_sock_t* sock, ah_err_t err);

    // If both are NULL, all attempts to receive data will fail with AH_ESTATE. Either both or none must be set.
    void (*on_recv_alloc)(ah_udp_sock_t* sock, ah_bufs_t* bufs);
    void (*on_recv_done)(ah_udp_sock_t* sock, ah_bufs_t bufs, size_t n_recv, const ah_sockaddr_t* raddr, ah_err_t err);

    // If NULL, all attempts to send data will fail with AH_ESTATE.
    void (*on_send_done)(ah_udp_sock_t* sock, size_t n_sent, const ah_sockaddr_t* raddr, ah_err_t err);
};

struct ah_udp_trans {
    AH_I_UDP_TRANS_FIELDS
};

struct ah_udp_trans_vtab {
    ah_err_t (*sock_init)(ah_udp_sock_t* sock, ah_loop_t* loop, const ah_udp_sock_vtab_t* vtab);
    ah_err_t (*sock_open)(ah_udp_sock_t* sock, const ah_sockaddr_t* laddr);
    ah_err_t (*sock_recv_start)(ah_udp_sock_t* sock);
    ah_err_t (*sock_recv_stop)(ah_udp_sock_t* sock);
    ah_err_t (*sock_send)(ah_udp_sock_t* sock, ah_udp_omsg_t* omsg);
    ah_err_t (*sock_close)(ah_udp_sock_t* sock);
};

ah_extern ah_err_t ah_udp_omsg_init(ah_udp_omsg_t* omsg, ah_bufs_t bufs, ah_sockaddr_t* raddr);
ah_extern ah_sockaddr_t* ah_udp_omsg_get_raddr(ah_udp_omsg_t* omsg);
ah_extern ah_bufs_t ah_udp_omsg_get_bufs(ah_udp_omsg_t* omsg);

ah_extern ah_err_t ah_udp_sock_init(ah_udp_sock_t* sock, ah_loop_t* loop, const ah_udp_sock_vtab_t* vtab);
ah_extern ah_err_t ah_udp_sock_open(ah_udp_sock_t* sock, const ah_sockaddr_t* laddr);
ah_extern ah_err_t ah_udp_sock_recv_start(ah_udp_sock_t* sock);
ah_extern ah_err_t ah_udp_sock_recv_stop(ah_udp_sock_t* sock);
ah_extern ah_err_t ah_udp_sock_send(ah_udp_sock_t* sock, ah_udp_omsg_t* omsg);
ah_extern ah_err_t ah_udp_sock_close(ah_udp_sock_t* sock);

ah_extern ah_err_t ah_udp_sock_get_laddr(const ah_udp_sock_t* sock, ah_sockaddr_t* laddr);

ah_inline ah_loop_t* ah_udp_sock_get_loop(const ah_udp_sock_t* sock)
{
    ah_assert_if_debug(sock != NULL);
    return sock->_loop;
}

ah_inline void* ah_udp_sock_get_user_data(const ah_udp_sock_t* sock)
{
    ah_assert_if_debug(sock != NULL);
    return sock->_user_data;
}

ah_extern ah_err_t ah_udp_sock_set_multicast_hop_limit(ah_udp_sock_t* sock, uint8_t hop_limit);
ah_extern ah_err_t ah_udp_sock_set_multicast_loopback(ah_udp_sock_t* sock, bool is_enabled);
ah_extern ah_err_t ah_udp_sock_set_reuseaddr(ah_udp_sock_t* sock, bool is_enabled);
ah_extern ah_err_t ah_udp_sock_set_unicast_hop_limit(ah_udp_sock_t* sock, uint8_t hop_limit);

ah_inline void ah_udp_sock_set_user_data(ah_udp_sock_t* sock, void* user_data)
{
    ah_assert_if_debug(sock != NULL);
    sock->_user_data = user_data;
}

ah_extern ah_err_t ah_udp_sock_join(ah_udp_sock_t* sock, const ah_udp_group_t* group);
ah_extern ah_err_t ah_udp_sock_leave(ah_udp_sock_t* sock, const ah_udp_group_t* group);

ah_extern void ah_udp_trans_init(ah_udp_trans_t* trans, ah_loop_t* loop);

#endif
