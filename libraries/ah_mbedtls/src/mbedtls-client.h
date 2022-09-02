// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_TLS_CLIENT_H_
#define SRC_TLS_CLIENT_H_

#include "ah/mbedtls.h"

extern const ah_tcp_conn_cbs_t ah_i_mbedtls_tcp_conn_cbs;

ah_err_t ah_i_mbedtls_client_init(ah_mbedtls_client_t* cln, ah_tcp_trans_t trans, mbedtls_ssl_config* ssl_conf, ah_mbedtls_on_handshake_done_cb on_handshake_done_cb);

ah_err_t ah_i_mbedtls_conn_init(void* cln_, ah_tcp_conn_t* conn, ah_loop_t* loop, ah_tcp_trans_t trans, ah_tcp_conn_obs_t obs);
ah_err_t ah_i_mbedtls_conn_open(void* cln_, ah_tcp_conn_t* conn, const ah_sockaddr_t* laddr);
ah_err_t ah_i_mbedtls_conn_connect(void* cln_, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr);
ah_err_t ah_i_mbedtls_conn_read_start(void* cln_, ah_tcp_conn_t* conn);
ah_err_t ah_i_mbedtls_conn_read_stop(void* cln_, ah_tcp_conn_t* conn);
ah_err_t ah_i_mbedtls_conn_write(void* cln_, ah_tcp_conn_t* conn, ah_tcp_out_t* out);
ah_err_t ah_i_mbedtls_conn_shutdown(void* cln_, ah_tcp_conn_t* conn, uint8_t flags);
ah_err_t ah_i_mbedtls_conn_close(void* cln_, ah_tcp_conn_t* conn);
int ah_i_mbedtls_conn_get_family(void* cln_, const ah_tcp_conn_t* conn);
ah_err_t ah_i_mbedtls_conn_get_laddr(void* cln_, const ah_tcp_conn_t* conn, ah_sockaddr_t* laddr);
ah_err_t ah_i_mbedtls_conn_get_raddr(void* cln_, const ah_tcp_conn_t* conn, ah_sockaddr_t* raddr);
ah_loop_t* ah_i_mbedtls_conn_get_loop(void* cln_, const ah_tcp_conn_t* conn);
void* ah_i_mbedtls_conn_get_obs_ctx(void* cln_, const ah_tcp_conn_t* conn);
bool ah_i_mbedtls_conn_is_closed(void* cln_, const ah_tcp_conn_t* conn);
bool ah_i_mbedtls_conn_is_readable(void* cln_, const ah_tcp_conn_t* conn);
bool ah_i_mbedtls_conn_is_reading(void* cln_, const ah_tcp_conn_t* conn);
bool ah_i_mbedtls_conn_is_writable(void* cln_, const ah_tcp_conn_t* conn);
ah_err_t ah_i_mbedtls_conn_set_keepalive(void* cln_, ah_tcp_conn_t* conn, bool is_enabled);
ah_err_t ah_i_mbedtls_conn_set_nodelay(void* cln_, ah_tcp_conn_t* conn, bool is_enabled);
ah_err_t ah_i_mbedtls_conn_set_reuseaddr(void* cln_, ah_tcp_conn_t* conn, bool is_enabled);

void ah_i_mbedtls_handshake(ah_mbedtls_client_t* cln);

int ah_i_mbedtls_client_write_ciphertext(void* conn_, const unsigned char* buf, size_t len);
int ah_i_mbedtls_client_read_ciphertext(void* conn_, unsigned char* buf, size_t len);

#endif
