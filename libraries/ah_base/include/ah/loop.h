// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_LOOP_H_
#define AH_LOOP_H_

#include "alloc.h"
#include "time.h"

#include <stddef.h>
#include <stdint.h>

#if AH_USE_KQUEUE
#    include <sys/event.h>
#elif AH_USE_URING
#    include <liburing.h>
#elif AH_USE_IOCP
#    define WIN32_LEAN_AND_MEAN
#    include <windows.h>
#endif

struct ah_loop {
    ah_alloc_cb _alloc_cb;

    struct ah_i_loop_evt_page* _evt_page_list;
    struct ah_i_loop_evt* _evt_free_list;

    ah_time_t _now;
    ah_err_t _pending_err;
    int _state;

#if AH_USE_IOCP

    HANDLE _iocp_handle;

#elif AH_USE_KQUEUE

    int _kqueue_fd;
    int _kqueue_capacity;
    int _kqueue_nchanges;
    struct kevent* _kqueue_changelist;
    struct kevent* _kqueue_eventlist;

#elif AH_USE_URING

    struct io_uring _uring;

#endif
};

struct ah_loop_opts {
    ah_alloc_cb alloc_cb;
    size_t capacity;
};

ah_extern ah_err_t ah_loop_init(ah_loop_t* loop, const ah_loop_opts_t* opts);
ah_extern bool ah_loop_is_term(const ah_loop_t* loop);
ah_extern ah_time_t ah_loop_now(const ah_loop_t* loop);
ah_extern ah_err_t ah_loop_run(ah_loop_t* loop);
ah_extern ah_err_t ah_loop_run_until(ah_loop_t* loop, ah_time_t* time);
ah_extern ah_err_t ah_loop_stop(ah_loop_t* loop);
ah_extern ah_err_t ah_loop_term(ah_loop_t* loop);

#endif
