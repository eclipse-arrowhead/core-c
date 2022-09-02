// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_TCP_TRANS_DEFAULT_H_
#define SRC_TCP_TRANS_DEFAULT_H_

#include "ah/defs.h"

#include <stdbool.h>
#include <stdint.h>

ah_err_t ah_i_tcp_trans_default_conn_init(void* ctx, ah_tcp_conn_t* conn, ah_loop_t* loop, ah_tcp_trans_t trans, ah_tcp_conn_obs_t obs);
ah_err_t ah_i_tcp_trans_default_conn_open(void* ctx, ah_tcp_conn_t* conn, const ah_sockaddr_t* laddr);
ah_err_t ah_i_tcp_trans_default_conn_connect(void* ctx, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr);
ah_err_t ah_i_tcp_trans_default_conn_read_start(void* ctx, ah_tcp_conn_t* conn);
ah_err_t ah_i_tcp_trans_default_conn_read_stop(void* ctx, ah_tcp_conn_t* conn);
ah_err_t ah_i_tcp_trans_default_conn_write(void* ctx, ah_tcp_conn_t* conn, ah_tcp_out_t* out);
ah_err_t ah_i_tcp_trans_default_conn_shutdown(void* ctx, ah_tcp_conn_t* conn, uint8_t flags);
ah_err_t ah_i_tcp_trans_default_conn_close(void* ctx, ah_tcp_conn_t* conn);
ah_err_t ah_i_tcp_trans_default_conn_term(void* ctx, ah_tcp_conn_t* conn);
int ah_i_tcp_trans_default_conn_get_family(void* ctx, const ah_tcp_conn_t* conn);
ah_err_t ah_i_tcp_trans_default_conn_get_laddr(void* ctx, const ah_tcp_conn_t* conn, ah_sockaddr_t* laddr);
ah_err_t ah_i_tcp_trans_default_conn_get_raddr(void* ctx, const ah_tcp_conn_t* conn, ah_sockaddr_t* raddr);
ah_loop_t* ah_i_tcp_trans_default_conn_get_loop(void* ctx, const ah_tcp_conn_t* conn);
void* ah_i_tcp_trans_default_conn_get_obs_ctx(void* ctx, const ah_tcp_conn_t* conn);
bool ah_i_tcp_trans_default_conn_is_closed(void* ctx, const ah_tcp_conn_t* conn);
bool ah_i_tcp_trans_default_conn_is_readable(void* ctx, const ah_tcp_conn_t* conn);
bool ah_i_tcp_trans_default_conn_is_reading(void* ctx, const ah_tcp_conn_t* conn);
bool ah_i_tcp_trans_default_conn_is_writable(void* ctx, const ah_tcp_conn_t* conn);
ah_err_t ah_i_tcp_trans_default_conn_set_keepalive(void* ctx, ah_tcp_conn_t* conn, bool is_enabled);
ah_err_t ah_i_tcp_trans_default_conn_set_nodelay(void* ctx, ah_tcp_conn_t* conn, bool is_enabled);
ah_err_t ah_i_tcp_trans_default_conn_set_reuseaddr(void* ctx, ah_tcp_conn_t* conn, bool is_enabled);

ah_err_t ah_i_tcp_trans_default_listener_init(void* ctx, ah_tcp_listener_t* ln, ah_loop_t* loop, ah_tcp_trans_t trans, ah_tcp_listener_obs_t obs);
ah_err_t ah_i_tcp_trans_default_listener_open(void* ctx, ah_tcp_listener_t* ln, const ah_sockaddr_t* laddr);
ah_err_t ah_i_tcp_trans_default_listener_listen(void* ctx, ah_tcp_listener_t* ln, unsigned backlog);
ah_err_t ah_i_tcp_trans_default_listener_close(void* ctx, ah_tcp_listener_t* ln);
ah_err_t ah_i_tcp_trans_default_listener_term(void* ctx, ah_tcp_listener_t* ln);
int ah_i_tcp_trans_default_listener_get_family(void* ctx, const ah_tcp_listener_t* ln);
ah_err_t ah_i_tcp_trans_default_listener_get_laddr(void* ctx, const ah_tcp_listener_t* ln, ah_sockaddr_t* laddr);
ah_loop_t* ah_i_tcp_trans_default_listener_get_loop(void* ctx, const ah_tcp_listener_t* ln);
void* ah_i_tcp_trans_default_listener_get_obs_ctx(void* ctx, const ah_tcp_listener_t* ln);
bool ah_i_tcp_trans_default_listener_is_closed(void* ctx, ah_tcp_listener_t* ln);
ah_err_t ah_i_tcp_trans_default_listener_set_keepalive(void* ctx, ah_tcp_listener_t* ln, bool is_enabled);
ah_err_t ah_i_tcp_trans_default_listener_set_nodelay(void* ctx, ah_tcp_listener_t* ln, bool is_enabled);
ah_err_t ah_i_tcp_trans_default_listener_set_reuseaddr(void* ctx, ah_tcp_listener_t* ln, bool is_enabled);
ah_err_t ah_i_tcp_trans_default_trans_init(void* ctx, ah_tcp_trans_t* trans);

#endif
