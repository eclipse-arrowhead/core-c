// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_TLS_SERVER_H_
#define SRC_TLS_SERVER_H_

#include "ah/mbedtls.h"

void ah_i_tls_server_free_accepted_client(ah_mbedtls_server_t* server, ah_mbedtls_client_t* client);

ah_err_t ah_i_mbedtls_listener_init(void* srv_, ah_tcp_listener_t* ln, ah_loop_t* loop, ah_tcp_trans_t trans, ah_tcp_listener_obs_t obs);
ah_err_t ah_i_mbedtls_listener_open(void* srv_, ah_tcp_listener_t* ln, const ah_sockaddr_t* laddr);
ah_err_t ah_i_mbedtls_listener_listen(void* srv_, ah_tcp_listener_t* ln, unsigned backlog);
ah_err_t ah_i_mbedtls_listener_close(void* srv_, ah_tcp_listener_t* ln);
ah_err_t ah_i_mbedtls_listener_term(void* srv_, ah_tcp_listener_t* ln);
int ah_i_mbedtls_listener_get_family(void* srv_, const ah_tcp_listener_t* ln);
ah_err_t ah_i_mbedtls_listener_get_laddr(void* srv_, const ah_tcp_listener_t* ln, ah_sockaddr_t* laddr);
ah_loop_t* ah_i_mbedtls_listener_get_loop(void* srv_, const ah_tcp_listener_t* ln);
void* ah_i_mbedtls_listener_get_obs_ctx(void* srv_, const ah_tcp_listener_t* ln);
bool ah_i_mbedtls_listener_is_closed(void* srv_, ah_tcp_listener_t* ln);
ah_err_t ah_i_mbedtls_listener_set_keepalive(void* srv_, ah_tcp_listener_t* ln, bool is_enabled);
ah_err_t ah_i_mbedtls_listener_set_nodelay(void* srv_, ah_tcp_listener_t* ln, bool is_enabled);
ah_err_t ah_i_mbedtls_listener_set_reuseaddr(void* srv_, ah_tcp_listener_t* ln, bool is_enabled);
ah_err_t ah_i_mbedtls_listener_prepare(void* srv_, ah_tcp_listener_t* ln, ah_tcp_trans_t* trans);

#endif
