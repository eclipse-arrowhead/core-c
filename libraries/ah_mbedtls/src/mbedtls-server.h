// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_TLS_SERVER_H_
#define SRC_TLS_SERVER_H_

#include "ah/mbedtls.h"

void ah_i_tls_server_free_accepted_client(ah_mbedtls_server_t* server, ah_mbedtls_client_t* client);

ah_err_t ah_i_mbedtls_listener_init(void* server_, ah_tcp_listener_t* ln, ah_tcp_listener_obs_t obs);
ah_err_t ah_i_mbedtls_listener_open(void* server_, ah_tcp_listener_t* ln, const ah_sockaddr_t* laddr);
ah_err_t ah_i_mbedtls_listener_listen(void* server_, ah_tcp_listener_t* ln, unsigned backlog, ah_tcp_conn_obs_t conn_obs);
ah_err_t ah_i_mbedtls_listener_close(void* server_, ah_tcp_listener_t* ln);

#endif
