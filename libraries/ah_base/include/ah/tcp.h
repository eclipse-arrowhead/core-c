// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_TCP_H_
#define AH_TCP_H_

#include "buf.h"
#include "err.h"

#include <stdbool.h>

#if AH_USE_BSD_SOCKETS
#    include "sock.h"
#    if AH_USE_IOCP
#        include <winsock2.h>
#    else
#        include <netinet/in.h>
#    endif
#endif

#define AH_TCP_SHUTDOWN_RD   1u
#define AH_TCP_SHUTDOWN_WR   2u
#define AH_TCP_SHUTDOWN_RDWR 3u

typedef unsigned ah_tcp_shutdown_t;

typedef void (*ah_tcp_open_cb)(struct ah_tcp_sock* sock, ah_err_t err);
typedef void (*ah_tcp_close_cb)(struct ah_tcp_sock* sock, ah_err_t err);
typedef void (*ah_tcp_connect_cb)(struct ah_tcp_sock* conn, ah_err_t err);

struct ah_tcp_listen_ctx {
    void (*listen_cb)(struct ah_tcp_sock* sock, ah_err_t err);
    void (*accept_cb)(struct ah_tcp_sock* sock, struct ah_tcp_sock* conn, union ah_sockaddr* remote_addr, ah_err_t err);
    void (*alloc_cb)(struct ah_tcp_sock* sock, struct ah_tcp_sock** conn);
};

struct ah_tcp_read_ctx {
    void (*read_cb)(struct ah_tcp_sock* sock, struct ah_buf* buf, ah_err_t err);
    void (*alloc_cb)(struct ah_tcp_sock* sock, struct ah_buf* buf);
};

struct ah_tcp_write_ctx {
    void (*write_cb)(struct ah_tcp_sock* conn, ah_err_t err);
    struct ah_bufvec bufvec;
};

struct ah_tcp_sock {
    // INTERNAL START

    struct ah_loop* _loop;
    void* _user_data;

#if AH_USE_BSD_SOCKETS
    ah_sockfd_t _fd;
#endif

    bool _is_reading          : 1;
    bool _is_reading_shutdown : 1;
    bool _is_writing          : 1;
    bool _is_writing_shutdown : 1;

    // INTERNAL STOP
};

ah_extern ah_err_t ah_tcp_init(struct ah_tcp_sock* sock, struct ah_loop* loop, void* user_data);
ah_extern ah_err_t ah_tcp_open(struct ah_tcp_sock* sock, const union ah_sockaddr* local_addr, ah_tcp_open_cb cb);

#if AH_USE_BSD_SOCKETS
ah_extern ah_err_t ah_tcp_get_fd(const struct ah_tcp_sock* sock, ah_sockfd_t* fd);
#endif
ah_extern ah_err_t ah_tcp_get_local_addr(const struct ah_tcp_sock* sock, union ah_sockaddr* local_addr);
ah_extern ah_err_t ah_tcp_get_loop(const struct ah_tcp_sock* sock, struct ah_loop** loop);
ah_extern ah_err_t ah_tcp_get_remote_addr(const struct ah_tcp_sock* sock, union ah_sockaddr* remote_addr);
ah_extern ah_err_t ah_tcp_get_user_data(const struct ah_tcp_sock* sock, void** user_data);

ah_extern ah_err_t ah_tcp_set_keepalive(struct ah_tcp_sock* sock, bool keepalive);
ah_extern ah_err_t ah_tcp_set_no_delay(struct ah_tcp_sock* sock, bool no_delay);
ah_extern ah_err_t ah_tcp_set_reuse_addr(struct ah_tcp_sock* sock, bool reuse_addr);
ah_extern ah_err_t ah_tcp_set_user_data(struct ah_tcp_sock* sock, void* user_data);

ah_extern ah_err_t ah_tcp_connect(struct ah_tcp_sock* sock, const union ah_sockaddr* remote_addr, ah_tcp_connect_cb cb);
ah_extern ah_err_t ah_tcp_listen(struct ah_tcp_sock* sock, unsigned backlog, const struct ah_tcp_listen_ctx* ctx);

ah_extern ah_err_t ah_tcp_read_start(struct ah_tcp_sock* sock, const struct ah_tcp_read_ctx* ctx);
ah_extern ah_err_t ah_tcp_read_stop(struct ah_tcp_sock* sock);
ah_extern ah_err_t ah_tcp_write(struct ah_tcp_sock* sock, struct ah_tcp_write_ctx* ctx);
ah_extern ah_err_t ah_tcp_shutdown(struct ah_tcp_sock* sock, ah_tcp_shutdown_t flags);

ah_extern ah_err_t ah_tcp_close(struct ah_tcp_sock* sock, ah_tcp_close_cb cb);
ah_extern ah_err_t ah_tcp_term(struct ah_tcp_sock* sock);

#endif
