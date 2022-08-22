// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_TLS_CLIENT_H_
#define SRC_TLS_CLIENT_H_

#include "ah/mbedtls.h"

extern const ah_tcp_conn_cbs_t ah_i_mbedtls_tcp_conn_cbs;

ah_err_t ah_i_mbedtls_client_init(ah_mbedtls_client_t* client, ah_tcp_trans_t trans, mbedtls_ssl_config* ssl_conf, ah_mbedtls_on_handshake_done_cb on_handshake_done_cb);

ah_err_t ah_i_mbedtls_client_open(void* client_, ah_tcp_conn_t* conn, const ah_sockaddr_t* laddr);
ah_err_t ah_i_mbedtls_client_connect(void* client_, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr);
ah_err_t ah_i_mbedtls_client_read_start(void* client_, ah_tcp_conn_t* conn);
ah_err_t ah_i_mbedtls_client_read_stop(void* client_, ah_tcp_conn_t* conn);
ah_err_t ah_i_mbedtls_client_write(void* client_, ah_tcp_conn_t* conn, ah_tcp_out_t* out);
ah_err_t ah_i_mbedtls_client_shutdown(void* client_, ah_tcp_conn_t* conn, uint8_t flags);
ah_err_t ah_i_mbedtls_client_close(void* client_, ah_tcp_conn_t* conn);

void ah_i_mbedtls_handshake(ah_tcp_conn_t* conn);

int ah_i_mbedtls_client_write_ciphertext(void* conn_, const unsigned char* buf, size_t len);
int ah_i_mbedtls_client_read_ciphertext(void* conn_, unsigned char* buf, size_t len);

#endif
