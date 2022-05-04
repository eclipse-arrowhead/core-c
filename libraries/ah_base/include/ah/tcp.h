// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_TCP_H_
#define AH_TCP_H_

#include "assert.h"
#include "buf.h"
#include "internal/_tcp.h"
#include "sock.h"

#include <stdbool.h>

#define AH_TCP_SHUTDOWN_RD   1u
#define AH_TCP_SHUTDOWN_WR   2u
#define AH_TCP_SHUTDOWN_RDWR 3u

typedef uint8_t ah_tcp_shutdown_t;

struct ah_tcp_conn {
    AH_I_TCP_CONN_FIELDS
};

struct ah_tcp_conn_vtab {
    void (*on_open)(ah_tcp_conn_t* conn, ah_err_t err); // Never called for accepted connections.
    void (*on_connect)(ah_tcp_conn_t* conn, ah_err_t err); // Never called for accepted connections.
    void (*on_close)(ah_tcp_conn_t* conn, ah_err_t err);

    // If all three are NULL, receiving is shutdown automatically. Either all or none must be set.
    void (*on_read_alloc)(ah_tcp_conn_t* conn, ah_bufs_t* bufs);
    void (*on_read_data)(ah_tcp_conn_t* conn, ah_bufs_t bufs, size_t n_bytes_read);
    void (*on_read_err)(ah_tcp_conn_t* conn, ah_err_t err);

    // If NULL, sending is shutdown automatically.
    void (*on_write_done)(ah_tcp_conn_t* conn, ah_err_t err);
};

struct ah_tcp_listener {
    AH_I_TCP_LISTENER_FIELDS
};

struct ah_tcp_listener_vtab {
    void (*on_open)(ah_tcp_listener_t* ln, ah_err_t err);
    void (*on_listen)(ah_tcp_listener_t* ln, ah_err_t err);
    void (*on_close)(ah_tcp_listener_t* ln, ah_err_t err);

    void (*on_conn_alloc)(ah_tcp_listener_t* ln, ah_tcp_conn_t** conn);
    void (*on_conn_accept)(ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr);
    void (*on_conn_err)(ah_tcp_listener_t* ln, ah_err_t);
};

struct ah_tcp_omsg {
    AH_I_TCP_OMSG_FIELDS
};

struct ah_tcp_trans {
    AH_I_TCP_TRANS_FIELDS
};

struct ah_tcp_trans_vtab {
    ah_err_t (*conn_init)(ah_tcp_conn_t* conn, ah_loop_t* loop, const ah_tcp_conn_vtab_t* vtab);
    ah_err_t (*conn_open)(ah_tcp_conn_t* conn, const ah_sockaddr_t* laddr);
    ah_err_t (*conn_connect)(ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr);
    ah_err_t (*conn_read_start)(ah_tcp_conn_t* conn);
    ah_err_t (*conn_read_stop)(ah_tcp_conn_t* conn);
    ah_err_t (*conn_write)(ah_tcp_conn_t* conn, ah_tcp_omsg_t* omsg); // May modify ah_bufs_t items in omsg.
    ah_err_t (*conn_shutdown)(ah_tcp_conn_t* conn, ah_tcp_shutdown_t flags);
    ah_err_t (*conn_close)(ah_tcp_conn_t* conn);

    ah_err_t (*listener_init)(ah_tcp_listener_t* ln, ah_loop_t* loop, const ah_tcp_listener_vtab_t* vtab);
    ah_err_t (*listener_open)(ah_tcp_listener_t* ln, const ah_sockaddr_t* laddr);
    ah_err_t (*listener_listen)(ah_tcp_listener_t* ln, unsigned backlog, const ah_tcp_conn_vtab_t* conn_vtab);
    ah_err_t (*listener_close)(ah_tcp_listener_t* ln);
};

ah_extern ah_err_t ah_tcp_conn_init(ah_tcp_conn_t* conn, ah_loop_t* loop, const ah_tcp_conn_vtab_t* vtab);
ah_extern ah_err_t ah_tcp_conn_open(ah_tcp_conn_t* conn, const ah_sockaddr_t* laddr);
ah_extern ah_err_t ah_tcp_conn_connect(ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr);
ah_extern ah_err_t ah_tcp_conn_read_start(ah_tcp_conn_t* conn);
ah_extern ah_err_t ah_tcp_conn_read_stop(ah_tcp_conn_t* conn);
ah_extern ah_err_t ah_tcp_conn_write(ah_tcp_conn_t* conn, ah_tcp_omsg_t* omsg);  // May modify ah_bufs_t items in omsg.
ah_extern ah_err_t ah_tcp_conn_shutdown(ah_tcp_conn_t* conn, ah_tcp_shutdown_t flags);
ah_extern ah_err_t ah_tcp_conn_close(ah_tcp_conn_t* conn);

ah_extern ah_err_t ah_tcp_conn_get_laddr(const ah_tcp_conn_t* conn, ah_sockaddr_t* laddr);
ah_extern ah_err_t ah_tcp_conn_get_raddr(const ah_tcp_conn_t* conn, ah_sockaddr_t* raddr);

ah_inline ah_loop_t* ah_tcp_conn_get_loop(const ah_tcp_conn_t* conn)
{
    ah_assert_if_debug(conn != NULL);
    return conn->_loop;
}

ah_inline void* ah_tcp_conn_get_user_data(const ah_tcp_conn_t* conn)
{
    ah_assert_if_debug(conn != NULL);
    return conn->_user_data;
}

ah_extern ah_err_t ah_tcp_conn_set_keepalive(ah_tcp_conn_t* conn, bool is_enabled);
ah_extern ah_err_t ah_tcp_conn_set_nodelay(ah_tcp_conn_t* conn, bool is_enabled);
ah_extern ah_err_t ah_tcp_conn_set_reuseaddr(ah_tcp_conn_t* conn, bool is_enabled);

ah_inline void ah_tcp_conn_set_user_data(ah_tcp_conn_t* conn, void* user_data)
{
    ah_assert_if_debug(conn != NULL);
    conn->_user_data = user_data;
}

ah_extern ah_err_t ah_tcp_listener_init(ah_tcp_listener_t* ln, ah_loop_t* loop, const ah_tcp_listener_vtab_t* vtab);
ah_extern ah_err_t ah_tcp_listener_open(ah_tcp_listener_t* ln, const ah_sockaddr_t* laddr);
ah_extern ah_err_t ah_tcp_listener_listen(ah_tcp_listener_t* ln, unsigned backlog, const ah_tcp_conn_vtab_t* conn_vtab);
ah_extern ah_err_t ah_tcp_listener_close(ah_tcp_listener_t* ln);

ah_extern ah_err_t ah_tcp_listener_get_laddr(const ah_tcp_listener_t* ln, ah_sockaddr_t* laddr);

ah_inline ah_loop_t* ah_tcp_listener_get_loop(const ah_tcp_listener_t* ln)
{
    ah_assert_if_debug(ln != NULL);
    return ln->_loop;
}

ah_inline void* ah_tcp_listener_get_user_data(const ah_tcp_listener_t* ln)
{
    ah_assert_if_debug(ln != NULL);
    return ln->_user_data;
}

ah_extern ah_err_t ah_tcp_listener_set_keepalive(ah_tcp_listener_t* ln, bool is_enabled);
ah_extern ah_err_t ah_tcp_listener_set_nodelay(ah_tcp_listener_t* ln, bool is_enabled);
ah_extern ah_err_t ah_tcp_listener_set_reuseaddr(ah_tcp_listener_t* ln, bool is_enabled);

ah_inline void ah_tcp_listener_set_user_data(ah_tcp_listener_t* ln, void* user_data)
{
    ah_assert_if_debug(ln != NULL);
    ln->_user_data = user_data;
}

ah_extern ah_err_t ah_tcp_omsg_init(ah_tcp_omsg_t* omsg, ah_bufs_t bufs);
ah_extern ah_bufs_t ah_tcp_omsg_get_bufs(ah_tcp_omsg_t* omsg);

ah_extern void ah_tcp_trans_init(ah_tcp_trans_t* trans, ah_loop_t* loop);

#endif
