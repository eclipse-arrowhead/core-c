// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_TCP_H_
#define AH_TCP_H_

#include "buf.h"
#include "internal/_tcp.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define AH_TCP_SHUTDOWN_RD   1u
#define AH_TCP_SHUTDOWN_WR   2u
#define AH_TCP_SHUTDOWN_RDWR 3u

typedef uint8_t ah_tcp_shutdown_t;

// A TCP-based transport.
struct ah_tcp_trans {
    const ah_tcp_vtab_t* vtab;
    void* ctx;
};

struct ah_tcp_vtab {
    ah_err_t (*conn_open)(void* ctx, ah_tcp_conn_t* conn, const ah_sockaddr_t* laddr);
    ah_err_t (*conn_connect)(void* ctx, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr);
    ah_err_t (*conn_read_start)(void* ctx, ah_tcp_conn_t* conn);
    ah_err_t (*conn_read_stop)(void* ctx, ah_tcp_conn_t* conn);
    ah_err_t (*conn_write)(void* ctx, ah_tcp_conn_t* conn, ah_tcp_msg_t* msg);
    ah_err_t (*conn_shutdown)(void* ctx, ah_tcp_conn_t* conn, ah_tcp_shutdown_t flags);
    ah_err_t (*conn_close)(void* ctx, ah_tcp_conn_t* conn);

    ah_err_t (*listener_open)(void* ctx, ah_tcp_listener_t* ln, const ah_sockaddr_t* laddr);
    ah_err_t (*listener_listen)(void* ctx, ah_tcp_listener_t* ln, unsigned backlog, const ah_tcp_conn_cbs_t* conn_cbs);
    ah_err_t (*listener_close)(void* ctx, ah_tcp_listener_t* ln);
};

struct ah_tcp_conn {
    AH_I_TCP_CONN_FIELDS
};

struct ah_tcp_conn_cbs {
    void (*on_open)(ah_tcp_conn_t* conn, ah_err_t err);    // Never called for accepted connections.
    void (*on_connect)(ah_tcp_conn_t* conn, ah_err_t err); // Never called for accepted connections.

    // If both are NULL, receiving is shutdown automatically. Either both or none must be non-NULL.
    void (*on_read_alloc)(ah_tcp_conn_t* conn, ah_buf_t* buf);
    void (*on_read_data)(ah_tcp_conn_t* conn, ah_buf_t buf, size_t nread, ah_err_t err);

    // If NULL, sending is shutdown automatically.
    void (*on_write_done)(ah_tcp_conn_t* conn, ah_err_t err);

    void (*on_close)(ah_tcp_conn_t* conn, ah_err_t err);
};

struct ah_tcp_listener {
    AH_I_TCP_LISTENER_FIELDS
};

struct ah_tcp_listener_cbs {
    void (*on_open)(ah_tcp_listener_t* ln, ah_err_t err);
    void (*on_listen)(ah_tcp_listener_t* ln, ah_err_t err);
    void (*on_close)(ah_tcp_listener_t* ln, ah_err_t err);

    void (*on_conn_alloc)(ah_tcp_listener_t* ln, ah_tcp_conn_t** conn);
    void (*on_conn_accept)(ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr, ah_err_t err);
};

// A buffer part of a stream of outgoing TCP bytes.
struct ah_tcp_msg {
    ah_buf_t buf;

    AH_I_TCP_MSG_FIELDS
};

ah_extern ah_tcp_trans_t ah_tcp_trans_get_default(void);

ah_extern bool ah_tcp_vtab_is_valid(const ah_tcp_vtab_t* vtab);

ah_extern ah_err_t ah_tcp_conn_init(ah_tcp_conn_t* conn, ah_loop_t* loop, ah_tcp_trans_t trans, const ah_tcp_conn_cbs_t* cbs);
ah_extern ah_err_t ah_tcp_conn_open(ah_tcp_conn_t* conn, const ah_sockaddr_t* laddr);
ah_extern ah_err_t ah_tcp_conn_connect(ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr);
ah_extern ah_err_t ah_tcp_conn_read_start(ah_tcp_conn_t* conn);
ah_extern ah_err_t ah_tcp_conn_read_stop(ah_tcp_conn_t* conn);
ah_extern ah_err_t ah_tcp_conn_write(ah_tcp_conn_t* conn, ah_tcp_msg_t* msg);
ah_extern ah_err_t ah_tcp_conn_shutdown(ah_tcp_conn_t* conn, ah_tcp_shutdown_t flags);
ah_extern ah_err_t ah_tcp_conn_close(ah_tcp_conn_t* conn);
ah_extern ah_err_t ah_tcp_conn_get_laddr(const ah_tcp_conn_t* conn, ah_sockaddr_t* laddr);
ah_extern ah_err_t ah_tcp_conn_get_raddr(const ah_tcp_conn_t* conn, ah_sockaddr_t* raddr);
ah_extern ah_loop_t* ah_tcp_conn_get_loop(const ah_tcp_conn_t* conn);
ah_extern ah_tcp_shutdown_t ah_tcp_conn_get_shutdown_flags(const ah_tcp_conn_t* conn);
ah_extern void* ah_tcp_conn_get_user_data(const ah_tcp_conn_t* conn);
ah_extern bool ah_tcp_conn_is_closed(const ah_tcp_conn_t* conn);
ah_extern bool ah_tcp_conn_is_readable(const ah_tcp_conn_t* conn);
ah_extern bool ah_tcp_conn_is_readable_and_writable(const ah_tcp_conn_t* conn);
ah_extern bool ah_tcp_conn_is_reading(const ah_tcp_conn_t* conn);
ah_extern bool ah_tcp_conn_is_writable(const ah_tcp_conn_t* conn);
ah_extern ah_err_t ah_tcp_conn_set_keepalive(ah_tcp_conn_t* conn, bool is_enabled);
ah_extern ah_err_t ah_tcp_conn_set_nodelay(ah_tcp_conn_t* conn, bool is_enabled);
ah_extern ah_err_t ah_tcp_conn_set_reuseaddr(ah_tcp_conn_t* conn, bool is_enabled);
ah_extern void ah_tcp_conn_set_user_data(ah_tcp_conn_t* conn, void* user_data);

ah_extern ah_err_t ah_tcp_listener_init(ah_tcp_listener_t* ln, ah_loop_t* loop, ah_tcp_trans_t trans, const ah_tcp_listener_cbs_t* cbs);
ah_extern ah_err_t ah_tcp_listener_open(ah_tcp_listener_t* ln, const ah_sockaddr_t* laddr);
ah_extern ah_err_t ah_tcp_listener_listen(ah_tcp_listener_t* ln, unsigned backlog, const ah_tcp_conn_cbs_t* conn_cbs);
ah_extern ah_err_t ah_tcp_listener_close(ah_tcp_listener_t* ln);
ah_extern ah_err_t ah_tcp_listener_get_laddr(const ah_tcp_listener_t* ln, ah_sockaddr_t* laddr);
ah_extern ah_loop_t* ah_tcp_listener_get_loop(const ah_tcp_listener_t* ln);
ah_extern void* ah_tcp_listener_get_user_data(const ah_tcp_listener_t* ln);
ah_extern bool ah_tcp_listener_is_closed(ah_tcp_listener_t* ln);
ah_extern ah_err_t ah_tcp_listener_set_keepalive(ah_tcp_listener_t* ln, bool is_enabled);
ah_extern ah_err_t ah_tcp_listener_set_nodelay(ah_tcp_listener_t* ln, bool is_enabled);
ah_extern ah_err_t ah_tcp_listener_set_reuseaddr(ah_tcp_listener_t* ln, bool is_enabled);
ah_extern void ah_tcp_listener_set_user_data(ah_tcp_listener_t* ln, void* user_data);

#endif
