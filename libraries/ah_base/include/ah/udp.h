// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_UDP_H_
#define AH_UDP_H_

#include "buf.h"
#include "internal/_udp.h"
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

// A UDP-based message transport.
struct ah_udp_trans {
    const ah_udp_vtab_t* vtab;
    void* ctx;
};

struct ah_udp_vtab {
    ah_err_t (*sock_open)(void* ctx, ah_udp_sock_t* sock, const ah_sockaddr_t* laddr);
    ah_err_t (*sock_recv_start)(void* ctx, ah_udp_sock_t* sock);
    ah_err_t (*sock_recv_stop)(void* ctx, ah_udp_sock_t* sock);
    ah_err_t (*sock_send)(void* ctx, ah_udp_sock_t* sock, ah_udp_out_t* out);
    ah_err_t (*sock_close)(void* ctx, ah_udp_sock_t* sock);
};

struct ah_udp_sock {
    AH_I_UDP_SOCK_FIELDS
};

// An incoming UDP message.
struct ah_udp_in {
    const ah_sockaddr_t* raddr;

    ah_buf_t buf;
    size_t nrecv;

    AH_I_UDP_IN_FIELDS
};

// An outgoing UDP message.
struct ah_udp_out {
    const ah_sockaddr_t* raddr;

    ah_buf_t buf;
    size_t nsent;

    AH_I_UDP_OUT_FIELDS
};

struct ah_udp_sock_cbs {
    void (*on_open)(ah_udp_sock_t* sock, ah_err_t err);

    // If NULL, every attempt to start receiving data will fail with AH_ESTATE.
    void (*on_recv)(ah_udp_sock_t* sock, ah_udp_in_t* in, ah_err_t err);

    // If NULL, every attempt to send data will fail with AH_ESTATE.
    void (*on_send)(ah_udp_sock_t* sock, ah_udp_out_t* out, ah_err_t err);

    void (*on_close)(ah_udp_sock_t* sock, ah_err_t err);
};

ah_extern ah_udp_trans_t ah_udp_trans_get_default();

ah_extern bool ah_udp_vtab_is_valid(const ah_udp_vtab_t* vtab);

ah_extern ah_err_t ah_udp_sock_init(ah_udp_sock_t* sock, ah_loop_t* loop, ah_udp_trans_t trans, const ah_udp_sock_cbs_t* cbs);
ah_extern ah_err_t ah_udp_sock_open(ah_udp_sock_t* sock, const ah_sockaddr_t* laddr);
ah_extern ah_err_t ah_udp_sock_recv_start(ah_udp_sock_t* sock);
ah_extern ah_err_t ah_udp_sock_recv_stop(ah_udp_sock_t* sock);
ah_extern ah_err_t ah_udp_sock_send(ah_udp_sock_t* sock, ah_udp_out_t* out);
ah_extern ah_err_t ah_udp_sock_close(ah_udp_sock_t* sock);
ah_extern ah_err_t ah_udp_sock_get_laddr(const ah_udp_sock_t* sock, ah_sockaddr_t* laddr);
ah_extern ah_loop_t* ah_udp_sock_get_loop(const ah_udp_sock_t* sock);
ah_extern void* ah_udp_sock_get_user_data(const ah_udp_sock_t* sock);
ah_extern bool ah_udp_sock_is_closed(const ah_udp_sock_t* sock);
ah_extern bool ah_udp_sock_is_receiving(const ah_udp_sock_t* sock);
ah_extern ah_err_t ah_udp_sock_set_multicast_hop_limit(ah_udp_sock_t* sock, uint8_t hop_limit);
ah_extern ah_err_t ah_udp_sock_set_multicast_loopback(ah_udp_sock_t* sock, bool is_enabled);
ah_extern ah_err_t ah_udp_sock_set_reuseaddr(ah_udp_sock_t* sock, bool is_enabled);
ah_extern ah_err_t ah_udp_sock_set_unicast_hop_limit(ah_udp_sock_t* sock, uint8_t hop_limit);
ah_extern void ah_udp_sock_set_user_data(ah_udp_sock_t* sock, void* user_data);
ah_extern ah_err_t ah_udp_sock_join(ah_udp_sock_t* sock, const ah_udp_group_t* group);
ah_extern ah_err_t ah_udp_sock_leave(ah_udp_sock_t* sock, const ah_udp_group_t* group);

ah_extern ah_err_t ah_udp_in_detach(ah_udp_in_t* in);

// Must only be called after successful call to ah_udp_in_detach() with same `in`.
ah_extern ah_err_t ah_udp_in_free(ah_udp_in_t* in);

#endif
