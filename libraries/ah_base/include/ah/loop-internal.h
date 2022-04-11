// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_LOOP_INTERNAL_H_
#define AH_LOOP_INTERNAL_H_

// This file is intended for direct use only by this library and other
// officially supported core-c libraries. While ABI-compatibility will not be
// compromised between minor or patch releases of this library, other breaking
// changes may be introduced.

#include "defs.h"
#include "time.h"

#include <stddef.h>

#if AH_USE_KQUEUE
typedef struct kevent ah_i_loop_req_t;
typedef struct kevent ah_i_loop_res_t;
#elif AH_USE_URING
typedef struct io_uring_sqe ah_i_loop_req_t;
typedef struct io_uring_cqe ah_i_loop_res_t;
#else
typedef int ah_i_loop_req_t;
typedef int ah_i_loop_res_t;
#endif

struct ah_i_loop_evt_body_task_schedule_at {
    struct ah_task* _task;
#if AH_USE_URING
    struct ah_time _baseline;
#endif
};

#if AH_USE_URING
struct ah_i_loop_evt_body_tcp_close {
    struct ah_tcp_sock* _sock;
    void (*_cb)(struct ah_tcp_sock*, ah_err_t);
};
#endif

struct ah_i_loop_evt_body_tcp_connect {
    struct ah_tcp_sock* _sock;
    void (*_cb)(struct ah_tcp_sock*, ah_err_t);
};

struct ah_i_loop_evt_body_tcp_listen {
    struct ah_tcp_sock* _sock;
    struct ah_tcp_listen_ctx* _ctx;
};

#if 0
struct ah_i_loop_evt_body_tcp_open {
    struct ah_tcp_sock* _sock;
    void (*_cb)(struct ah_tcp_sock*, ah_err_t);
};
#endif

struct ah_i_loop_evt_body_tcp_read {
    struct ah_tcp_sock* _sock;
    struct ah_tcp_read_ctx* _ctx;
};

struct ah_i_loop_evt_body_tcp_write {
    struct ah_tcp_sock* _sock;
    struct ah_tcp_write_ctx* _ctx;
};

struct ah_i_loop_evt_body_udp_recv {
    struct ah_udp_sock* _sock;
    const struct ah_udp_recv_ctx* _ctx;
};

struct ah_i_loop_evt_body_udp_send {
    struct ah_udp_sock* _sock;
    struct ah_udp_send_ctx* _ctx;
};

union ah_i_loop_evt_body {
    struct ah_i_loop_evt_body_task_schedule_at _task_schedule_at;
#if AH_USE_URING
    struct ah_i_loop_evt_body_tcp_close _tcp_close;
#endif
    struct ah_i_loop_evt_body_tcp_connect _tcp_connect;
    struct ah_i_loop_evt_body_tcp_listen _tcp_listen;
#if 0
    struct ah_i_loop_evt_body_tcp_open _tcp_open;
#endif
    struct ah_i_loop_evt_body_tcp_read _tcp_read;
    struct ah_i_loop_evt_body_tcp_write _tcp_write;
    struct ah_i_loop_evt_body_udp_recv _udp_recv;
    struct ah_i_loop_evt_body_udp_send _udp_send;
};

struct ah_i_loop_evt {
    void (*_cb)(struct ah_i_loop_evt*, ah_i_loop_res_t*);
    union ah_i_loop_evt_body _body;
    struct ah_i_loop_evt* _next_free; // Used by loop allocator. Do not use directly.
};

ah_err_t ah_i_loop_alloc_evt(struct ah_loop* loop, struct ah_i_loop_evt** evt);
ah_err_t ah_i_loop_alloc_evt_and_req(struct ah_loop* loop, struct ah_i_loop_evt** evt, ah_i_loop_req_t** req);
ah_err_t ah_i_loop_alloc_req(struct ah_loop* loop, ah_i_loop_req_t** req);
void ah_i_loop_dealloc_evt(struct ah_loop* loop, struct ah_i_loop_evt* evt);

bool ah_i_loop_try_set_pending_err(struct ah_loop* loop, ah_err_t err);

#endif
