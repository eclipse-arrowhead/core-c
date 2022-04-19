// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_TCP_H_
#define AH_TCP_H_

#include "assert.h"
#include "buf.h"
#include "sock.h"

#include <stdbool.h>


#define AH_TCP_SHUTDOWN_RD   1u
#define AH_TCP_SHUTDOWN_WR   2u
#define AH_TCP_SHUTDOWN_RDWR 3u

typedef unsigned ah_tcp_shutdown_t;

typedef void (*ah_tcp_open_cb)(ah_tcp_sock_t* sock, ah_err_t err);
typedef void (*ah_tcp_close_cb)(ah_tcp_sock_t* sock, ah_err_t err);
typedef void (*ah_tcp_connect_cb)(ah_tcp_sock_t* conn, ah_err_t err);

struct ah_tcp_listen_ctx {
    void (*listen_cb)(ah_tcp_sock_t* sock, ah_err_t err);
    void (*accept_cb)(ah_tcp_sock_t* sock, ah_tcp_sock_t* conn, ah_sockaddr_t* remote_addr, ah_err_t err);
    void (*alloc_cb)(ah_tcp_sock_t* sock, ah_tcp_sock_t** conn);

#if AH_USE_URING
    ah_sockaddr_t _remote_addr;
    socklen_t _remote_addr_len;
#endif
};

struct ah_tcp_read_ctx {
    void (*read_cb)(ah_tcp_sock_t* sock, ah_bufvec_t* bufvec, size_t n_bytes_read, ah_err_t err);
    void (*alloc_cb)(ah_tcp_sock_t* sock, ah_bufvec_t* bufvec, size_t n_bytes_expected);

#if AH_USE_URING
    ah_bufvec_t _bufvec;
#endif
};

struct ah_tcp_write_ctx {
    void (*write_cb)(ah_tcp_sock_t* conn, ah_err_t err);
    ah_bufvec_t bufvec;
};

struct ah_tcp_sock {
    ah_loop_t* _loop;
    void* _user_data;

#if AH_USE_KQUEUE
    struct ah_i_loop_evt* _read_or_listen_evt;
#endif

#if AH_HAS_BSD_SOCKETS
    ah_i_sockfd_t _fd;
#endif

    uint8_t _state;
    uint8_t _state_read;
    uint8_t _state_write;
};

ah_extern ah_err_t ah_tcp_open(ah_tcp_sock_t* sock, ah_loop_t* loop, const ah_sockaddr_t* local_addr,
    ah_tcp_open_cb cb);

ah_extern ah_err_t ah_tcp_get_local_addr(const ah_tcp_sock_t* sock, ah_sockaddr_t* local_addr);
ah_extern ah_err_t ah_tcp_get_remote_addr(const ah_tcp_sock_t* sock, ah_sockaddr_t* remote_addr);

#if AH_HAS_BSD_SOCKETS
ah_extern_inline ah_i_sockfd_t ah_tcp_get_fd(const ah_tcp_sock_t* sock)
{
    ah_assert_if_debug(sock != NULL);
    return sock->_fd;
}
#endif

ah_extern_inline ah_loop_t* ah_tcp_get_loop(const ah_tcp_sock_t* sock)
{
    ah_assert_if_debug(sock != NULL);
    return sock->_loop;
}

ah_extern_inline void* ah_tcp_get_user_data(const ah_tcp_sock_t* sock)
{
    ah_assert_if_debug(sock != NULL);
    return sock->_user_data;
}

ah_extern ah_err_t ah_tcp_set_keepalive(ah_tcp_sock_t* sock, bool keepalive);
ah_extern ah_err_t ah_tcp_set_no_delay(ah_tcp_sock_t* sock, bool no_delay);
ah_extern ah_err_t ah_tcp_set_reuse_addr(ah_tcp_sock_t* sock, bool reuse_addr);

ah_extern_inline void ah_tcp_set_user_data(ah_tcp_sock_t* sock, void* user_data)
{
    ah_assert_if_debug(sock != NULL);
    sock->_user_data = user_data;
}

ah_extern ah_err_t ah_tcp_connect(ah_tcp_sock_t* sock, const ah_sockaddr_t* remote_addr, ah_tcp_connect_cb cb);
ah_extern ah_err_t ah_tcp_listen(ah_tcp_sock_t* sock, unsigned backlog, ah_tcp_listen_ctx_t* ctx);

ah_extern ah_err_t ah_tcp_read_start(ah_tcp_sock_t* sock, ah_tcp_read_ctx_t* ctx);
ah_extern ah_err_t ah_tcp_read_stop(ah_tcp_sock_t* sock);
ah_extern ah_err_t ah_tcp_write(ah_tcp_sock_t* sock, ah_tcp_write_ctx_t* ctx);
ah_extern ah_err_t ah_tcp_shutdown(ah_tcp_sock_t* sock, ah_tcp_shutdown_t flags);

ah_extern ah_err_t ah_tcp_close(ah_tcp_sock_t* sock, ah_tcp_close_cb cb);

#endif
