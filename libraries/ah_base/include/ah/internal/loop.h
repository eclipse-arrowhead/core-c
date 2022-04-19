// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_LOOP_H_
#define AH_INTERNAL_LOOP_H_

#include "../alloc.h"
#include "../defs.h"
#include "../time.h"

#if AH_USE_IOCP
#    include "iocp/loop.h"
#elif AH_USE_KQUEUE
#    include "kqueue/loop.h"
#elif AH_USE_URING
#    include "uring/loop.h"
#endif

#define AH_I_LOOP_FIELDS                                                                                               \
    ah_alloc_cb _alloc_cb;                                                                                             \
                                                                                                                       \
    struct ah_i_loop_evt_page* _evt_page_list;                                                                         \
    struct ah_i_loop_evt* _evt_free_list;                                                                              \
                                                                                                                       \
    ah_time_t _now;                                                                                                    \
    ah_err_t _pending_err;                                                                                             \
    int _state;                                                                                                        \
                                                                                                                       \
    AH_I_LOOP_PLATFORM_FIELDS

#define AH_I_LOOP_STATE_INITIAL     0x01
#define AH_I_LOOP_STATE_RUNNING     0x02
#define AH_I_LOOP_STATE_STOPPED     0x04
#define AH_I_LOOP_STATE_TERMINATING 0x08
#define AH_I_LOOP_STATE_TERMINATED  0x10

#define AH_I_LOOP_EVT_PAGE_SIZE     8192
#define AH_I_LOOP_EVT_PAGE_CAPACITY ((AH_I_LOOP_EVT_PAGE_SIZE / sizeof(ah_i_loop_evt_t)) - 1)

#if AH_I_LOOP_EVT_BODY_HAS_TASK_SCHEDULE_AT
struct ah_i_loop_evt_body_task_schedule_at {
    struct ah_task* _task;
    AH_I_LOOP_EVT_BODY_TASK_SCHEDULE_AT_PLATFORM_FIELDS
};
#endif

#if AH_I_LOOP_EVT_BODY_HAS_TCP_CLOSE
struct ah_i_loop_evt_body_tcp_close {
    struct ah_tcp_sock* _sock;
    void (*_cb)(struct ah_tcp_sock*, ah_err_t);
};
#endif

#if AH_I_LOOP_EVT_BODY_HAS_TCP_CONNECT
struct ah_i_loop_evt_body_tcp_connect {
    struct ah_tcp_sock* _sock;
    void (*_cb)(struct ah_tcp_sock*, ah_err_t);
};
#endif

#if AH_I_LOOP_EVT_BODY_HAS_TCP_LISTEN
struct ah_i_loop_evt_body_tcp_listen {
    struct ah_tcp_sock* _sock;
    struct ah_tcp_listen_ctx* _ctx;
};
#endif

#if AH_I_LOOP_EVT_BODY_HAS_TCP_OPEN
struct ah_i_loop_evt_body_tcp_open {
    struct ah_tcp_sock* _sock;
    void (*_cb)(struct ah_tcp_sock*, ah_err_t);
};
#endif

#if AH_I_LOOP_EVT_BODY_HAS_TCP_READ
struct ah_i_loop_evt_body_tcp_read {
    struct ah_tcp_sock* _sock;
    struct ah_tcp_read_ctx* _ctx;
};
#endif

#if AH_I_LOOP_EVT_BODY_HAS_TCP_WRITE
struct ah_i_loop_evt_body_tcp_write {
    struct ah_tcp_sock* _sock;
    struct ah_tcp_write_ctx* _ctx;
};
#endif

#if AH_I_LOOP_EVT_BODY_HAS_UDP_CLOSE
struct ah_i_loop_evt_body_udp_close {
    struct ah_udp_sock* _sock;
    void (*_cb)(struct ah_udp_sock*, ah_err_t);
};
#endif

#if AH_I_LOOP_EVT_BODY_HAS_UDP_OPEN
struct ah_i_loop_evt_body_udp_open {
    struct ah_udp_sock* _sock;
    void (*_cb)(struct ah_udp_sock*, ah_err_t);
};
#endif

#if AH_I_LOOP_EVT_BODY_HAS_UDP_RECV
struct ah_i_loop_evt_body_udp_recv {
    struct ah_udp_sock* _sock;
    struct ah_udp_recv_ctx* _ctx;
};
#endif

#if AH_I_LOOP_EVT_BODY_HAS_UDP_SEND
struct ah_i_loop_evt_body_udp_send {
    struct ah_udp_sock* _sock;
    struct ah_udp_send_ctx* _ctx;
};
#endif

union ah_i_loop_evt_body {
#if AH_I_LOOP_EVT_BODY_HAS_TASK_SCHEDULE_AT
    struct ah_i_loop_evt_body_task_schedule_at _task_schedule_at;
#endif

#if AH_I_LOOP_EVT_BODY_HAS_TCP_CLOSE
    struct ah_i_loop_evt_body_tcp_close _tcp_close;
#endif

#if AH_I_LOOP_EVT_BODY_HAS_TCP_CONNECT
    struct ah_i_loop_evt_body_tcp_connect _tcp_connect;
#endif

#if AH_I_LOOP_EVT_BODY_HAS_TCP_LISTEN
    struct ah_i_loop_evt_body_tcp_listen _tcp_listen;
#endif

#if AH_I_LOOP_EVT_BODY_HAS_TCP_OPEN
    struct ah_i_loop_evt_body_tcp_open _tcp_open;
#endif

#if AH_I_LOOP_EVT_BODY_HAS_TCP_READ
    struct ah_i_loop_evt_body_tcp_read _tcp_read;
#endif

#if AH_I_LOOP_EVT_BODY_HAS_TCP_WRITE
    struct ah_i_loop_evt_body_tcp_write _tcp_write;
#endif

#if AH_I_LOOP_EVT_BODY_HAS_UDP_CLOSE
    struct ah_i_loop_evt_body_udp_close _udp_close;
#endif

#if AH_I_LOOP_EVT_BODY_HAS_UDP_OPEN
    struct ah_i_loop_evt_body_udp_open _udp_open;
#endif

#if AH_I_LOOP_EVT_BODY_HAS_UDP_RECV
    struct ah_i_loop_evt_body_udp_recv _udp_recv;
#endif

#if AH_I_LOOP_EVT_BODY_HAS_UDP_SEND
    struct ah_i_loop_evt_body_udp_send _udp_send;
#endif
};

struct ah_i_loop_evt {
    void (*_cb)(ah_i_loop_evt_t*, ah_i_loop_res_t*);
    union ah_i_loop_evt_body _body;
    ah_i_loop_evt_t* _next_free; // Used by loop allocator. Do not use directly.
    AH_I_LOOP_EVT_PLATFORM_FIELDS
};

struct ah_i_loop_evt_page {
    ah_i_loop_evt_t _evt_array[AH_I_LOOP_EVT_PAGE_CAPACITY];
    char _pad[sizeof(ah_i_loop_evt_t) - sizeof(ah_i_loop_evt_page_t*)];
    ah_i_loop_evt_page_t* _next_page;
};

ah_extern ah_err_t ah_i_loop_init(ah_loop_t* loop, ah_loop_opts_t* opts);

ah_extern ah_err_t ah_i_loop_get_pending_err(ah_loop_t* loop);
ah_extern bool ah_i_loop_try_set_pending_err(ah_loop_t* loop, ah_err_t err);

ah_extern ah_err_t ah_i_loop_poll_no_longer_than_until(ah_loop_t* loop, struct ah_time* time);

ah_extern ah_err_t ah_i_loop_evt_alloc(ah_loop_t* loop, ah_i_loop_evt_t** evt);
ah_extern void ah_i_loop_evt_dealloc(ah_loop_t* loop, ah_i_loop_evt_t* evt);

ah_extern void ah_i_loop_term(ah_loop_t* loop);

#endif
