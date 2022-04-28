// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_TCP_H_
#define AH_TCP_H_

#include "assert.h"
#include "buf.h"
#include "internal/tcp.h"
#include "sock.h"

#include <stdbool.h>

#define AH_TCP_SHUTDOWN_RD   1u
#define AH_TCP_SHUTDOWN_WR   2u
#define AH_TCP_SHUTDOWN_RDWR 3u

/*
typedef struct ah_tcp_conn ah_tcp_conn_t;
typedef struct ah_tcp_listener ah_tcp_listener_t;
 */

typedef unsigned ah_tcp_shutdown_t;

typedef void (*ah_tcp_open_cb)(ah_tcp_sock_t* sock, ah_err_t err);
typedef void (*ah_tcp_close_cb)(ah_tcp_sock_t* sock, ah_err_t err);
typedef void (*ah_tcp_connect_cb)(ah_tcp_sock_t* conn, ah_err_t err);

/*
struct ah_tcp_conn_vtab {
    void (*on_open)(ah_tcp_conn_t* conn, ah_err_t err);
    void (*on_connect)(ah_tcp_conn_t* conn, ah_err_t err);
    void (*on_close)(ah_tcp_conn_t* conn, ah_err_t err);

    void (*on_data_alloc)(ah_tcp_conn_t* conn, ah_bufs_t* bufs, size_t n_bytes_expected);
    void (*on_data_read)(ah_tcp_conn_t* conn, ah_bufs_t bufs, size_t n_bytes_read, ah_err_t err);
    void (*on_data_write)(ah_tcp_conn_t* conn, ah_bufs_t bufs, size_t n_bytes_written, ah_err_t err);
};

struct ah_tcp_conn {
    AH_I_TCP_CONN_FIELDS
};

struct ah_tcp_listener_vtab {
    void (*on_open)(ah_tcp_listener_t* ln, ah_err_t err);
    void (*on_listen)(ah_tcp_listener_t* ln, ah_err_t err);
    void (*on_close)(ah_tcp_listener_t* ln, ah_err_t err);

    void (*on_conn_alloc)(ah_tcp_listener_t* ln, ah_tcp_conn_t** conn);
    void (*on_conn_accept)(ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, const ah_sockaddr_t* conn_addr, ah_err_t err);
    void (*on_conn_close)(ah_tcp_listener_t* ln, ah_tcp_conn_t* conn);
};

struct ah_tcp_listener {
    AH_I_TCP_LISTENER_FIELDS
};
*/


struct ah_tcp_listen_ctx {
    void (*listen_cb)(ah_tcp_sock_t* sock, ah_err_t err);
    void (*accept_cb)(ah_tcp_sock_t* sock, ah_tcp_sock_t* conn, const ah_sockaddr_t* remote_addr, ah_err_t err);
    void (*alloc_cb)(ah_tcp_sock_t* sock, ah_tcp_sock_t** conn);

    AH_I_TCP_LISTEN_CTX_FIELDS
};

struct ah_tcp_read_ctx {
    void (*read_cb)(ah_tcp_sock_t* sock, ah_bufs_t* bufs, size_t n_bytes_read, ah_err_t err);
    void (*alloc_cb)(ah_tcp_sock_t* sock, ah_bufs_t* bufs, size_t n_bytes_expected);

    AH_I_TCP_READ_CTX_FIELDS
};

struct ah_tcp_write_ctx {
    void (*write_cb)(ah_tcp_sock_t* conn, ah_err_t err);
    ah_bufs_t bufs;

    AH_I_TCP_WRITE_CTX_FIELDS
};

struct ah_tcp_sock {
    AH_I_TCP_SOCK_FIELDS
};

struct ah_tcp_vtab {
    void (*init)(ah_tcp_sock_t* sock, ah_loop_t* loop);
    ah_err_t (*open)(ah_tcp_sock_t* sock, const ah_sockaddr_t* local_addr, ah_tcp_open_cb cb);
    ah_err_t (*connect)(ah_tcp_sock_t* sock, const ah_sockaddr_t* remote_addr, ah_tcp_connect_cb cb);
    ah_err_t (*listen)(ah_tcp_sock_t* sock, unsigned backlog, ah_tcp_listen_ctx_t* ctx);
    ah_err_t (*read_start)(ah_tcp_sock_t* sock, ah_tcp_read_ctx_t* ctx);
    ah_err_t (*read_stop)(ah_tcp_sock_t* sock);
    ah_err_t (*write)(ah_tcp_sock_t* sock, ah_tcp_write_ctx_t* ctx);
    ah_err_t (*shutdown)(ah_tcp_sock_t* sock, ah_tcp_shutdown_t flags);
    ah_err_t (*close)(ah_tcp_sock_t* sock, ah_tcp_close_cb cb);
};

struct ah_tcp_trans {
    AH_I_TCP_TRANS_FIELDS
};

ah_extern ah_tcp_trans_t ah_tcp_transport(ah_loop_t* loop);

ah_extern void ah_tcp_init(ah_tcp_sock_t* sock, ah_loop_t* loop);
ah_extern ah_err_t ah_tcp_open(ah_tcp_sock_t* sock, const ah_sockaddr_t* local_addr, ah_tcp_open_cb cb);

ah_extern ah_err_t ah_tcp_get_local_addr(const ah_tcp_sock_t* sock, ah_sockaddr_t* local_addr);
ah_extern ah_err_t ah_tcp_get_remote_addr(const ah_tcp_sock_t* sock, ah_sockaddr_t* remote_addr);

ah_inline ah_loop_t* ah_tcp_get_loop(const ah_tcp_sock_t* sock)
{
    ah_assert_if_debug(sock != NULL);
    return sock->_loop;
}

ah_inline void* ah_tcp_get_user_data(const ah_tcp_sock_t* sock)
{
    ah_assert_if_debug(sock != NULL);
    return sock->_user_data;
}

ah_extern ah_err_t ah_tcp_set_keepalive(ah_tcp_sock_t* sock, bool keepalive);
ah_extern ah_err_t ah_tcp_set_no_delay(ah_tcp_sock_t* sock, bool no_delay);
ah_extern ah_err_t ah_tcp_set_reuse_addr(ah_tcp_sock_t* sock, bool reuse_addr);

ah_inline void ah_tcp_set_user_data(ah_tcp_sock_t* sock, void* user_data)
{
    ah_assert_if_debug(sock != NULL);
    sock->_user_data = user_data;
}

ah_extern ah_err_t ah_tcp_connect(ah_tcp_sock_t* sock, const ah_sockaddr_t* remote_addr, ah_tcp_connect_cb cb);
ah_extern ah_err_t ah_tcp_listen(ah_tcp_sock_t* sock, unsigned backlog, ah_tcp_listen_ctx_t* ctx);

ah_extern ah_err_t ah_tcp_read_start(ah_tcp_sock_t* sock, ah_tcp_read_ctx_t* ctx);
ah_extern ah_err_t ah_tcp_read_stop(ah_tcp_sock_t* sock); // Caller is responsible for freeing any memory allocated by ah_tcp_read_start().
ah_extern ah_err_t ah_tcp_write(ah_tcp_sock_t* sock, ah_tcp_write_ctx_t* ctx); // May modify ctx->bufs and its items.
ah_extern ah_err_t ah_tcp_shutdown(ah_tcp_sock_t* sock, ah_tcp_shutdown_t flags);

ah_extern ah_err_t ah_tcp_close(ah_tcp_sock_t* sock, ah_tcp_close_cb cb);

#endif
