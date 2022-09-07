// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_UDP_TRANS_DEFAULT_H_
#define SRC_UDP_TRANS_DEFAULT_H_

#include "ah/defs.h"

#include <stdbool.h>
#include <stdint.h>

ah_err_t ah_i_udp_trans_default_sock_init(void* ctx, ah_udp_sock_t* sock, ah_loop_t* loop, ah_udp_trans_t trans, ah_udp_sock_obs_t obs);
ah_err_t ah_i_udp_trans_default_sock_open(void* ctx, ah_udp_sock_t* sock, const ah_sockaddr_t* laddr);
ah_err_t ah_i_udp_trans_default_sock_recv_start(void* ctx, ah_udp_sock_t* sock);
ah_err_t ah_i_udp_trans_default_sock_recv_stop(void* ctx, ah_udp_sock_t* sock);
ah_err_t ah_i_udp_trans_default_sock_send(void* ctx, ah_udp_sock_t* sock, ah_udp_out_t* out);
ah_err_t ah_i_udp_trans_default_sock_close(void* ctx, ah_udp_sock_t* sock);
ah_err_t ah_i_udp_trans_default_sock_term(void* ctx, ah_udp_sock_t* sock);
int ah_i_udp_trans_default_sock_get_family(void* ctx, const ah_udp_sock_t* sock);
ah_err_t ah_i_udp_trans_default_sock_get_laddr(void* ctx, const ah_udp_sock_t* sock, ah_sockaddr_t* laddr);
ah_loop_t* ah_i_udp_trans_default_sock_get_loop(void* ctx, const ah_udp_sock_t* sock);
bool ah_i_udp_trans_default_sock_is_closed(void* ctx, const ah_udp_sock_t* sock);
bool ah_i_udp_trans_default_sock_is_receiving(void* ctx, const ah_udp_sock_t* sock);
ah_err_t ah_i_udp_trans_default_sock_set_multicast_hop_limit(void* ctx, ah_udp_sock_t* sock, uint8_t hop_limit);
ah_err_t ah_i_udp_trans_default_sock_set_multicast_loopback(void* ctx, ah_udp_sock_t* sock, bool is_enabled);
ah_err_t ah_i_udp_trans_default_sock_set_reuseaddr(void* ctx, ah_udp_sock_t* sock, bool is_enabled);
ah_err_t ah_i_udp_trans_default_sock_set_unicast_hop_limit(void* ctx, ah_udp_sock_t* sock, uint8_t hop_limit);
ah_err_t ah_i_udp_trans_default_sock_join(void* ctx, ah_udp_sock_t* sock, const ah_udp_group_t* group);
ah_err_t ah_i_udp_trans_default_sock_leave(void* ctx, ah_udp_sock_t* sock, const ah_udp_group_t* group);

#endif
