// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_LOOP_H_
#define AH_INTERNAL_LOOP_H_

#include "../defs.h"
#include "../time.h"

#if AH_USE_IOCP
# include "_loop-iocp.h"
#elif AH_USE_KQUEUE
# include "_loop-kqueue.h"
#elif AH_USE_URING
# include "_loop-uring.h"
#endif

#define AH_I_LOOP_STATE_INITIAL     0x01
#define AH_I_LOOP_STATE_RUNNING     0x02
#define AH_I_LOOP_STATE_STOPPED     0x04
#define AH_I_LOOP_STATE_TERMINATING 0x08
#define AH_I_LOOP_STATE_TERMINATED  0x10

#define AH_I_LOOP_EVT_PAGE_SIZE     4096
#define AH_I_LOOP_EVT_PAGE_CAPACITY ((AH_I_LOOP_EVT_PAGE_SIZE / sizeof(ah_i_loop_evt_t)) - 1)

#define AH_I_LOOP_FIELDS                        \
 struct ah_i_loop_evt_allocator _evt_allocator; \
                                                \
 ah_time_t _now;                                \
 ah_err_t _pending_err;                         \
 int _state;                                    \
                                                \
 AH_I_LOOP_PLATFORM_FIELDS

struct ah_i_loop_evt_allocator {
    struct ah_i_loop_evt_page* _page_list;
    struct ah_i_loop_evt* _free_list;
};

struct ah_i_loop_evt {
    AH_I_LOOP_EVT_PLATFORM_FIELDS

    void* _subject; // Must be non-NULL while the event is in use.
    void* _object;  // Arbitrary data associated with event.

    ah_i_loop_evt_t* _next_free; // Used by loop allocator. Do not use directly.
};

struct ah_i_loop_evt_page {
    ah_i_loop_evt_t _entries[AH_I_LOOP_EVT_PAGE_CAPACITY];
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
