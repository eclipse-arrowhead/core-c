// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_LOOP_H_
#define AH_INTERNAL_LOOP_H_

#include "../conf.h"
#include "../defs.h"
#include "../time.h"
#include "collections/slab.h"

#if AH_USE_IOCP
# include "_loop-iocp.h"
#elif AH_USE_KQUEUE
# include "_loop-kqueue.h"
#elif AH_USE_URING
# include "_loop-uring.h"
#endif

#define AH_I_LOOP_STATE_INITIAL     0
#define AH_I_LOOP_STATE_RUNNING     1
#define AH_I_LOOP_STATE_STOPPING    2
#define AH_I_LOOP_STATE_STOPPED     3
#define AH_I_LOOP_STATE_TERMINATING 4
#define AH_I_LOOP_STATE_TERMINATED  5

#define AH_I_LOOP_FIELDS     \
 struct ah_i_slab _evt_slab; \
                             \
 ah_time_t _now;             \
 ah_err_t _pending_err;      \
 int _state;                 \
                             \
 AH_I_LOOP_PLATFORM_FIELDS

typedef struct ah_i_loop_evt ah_i_loop_evt_t;

struct ah_i_loop_evt {
    AH_I_LOOP_EVT_PLATFORM_FIELDS

    void* _subject;
};

ah_err_t ah_i_loop_init(ah_loop_t* loop, size_t* capacity);

ah_err_t ah_i_loop_get_pending_err(ah_loop_t* loop);
bool ah_i_loop_try_set_pending_err(ah_loop_t* loop, ah_err_t err);

ah_err_t ah_i_loop_poll_no_longer_than_until(ah_loop_t* loop, ah_time_t* time);

ah_err_t ah_i_loop_evt_alloc(ah_loop_t* loop, ah_i_loop_evt_t** evt);
void ah_i_loop_evt_dealloc(ah_loop_t* loop, ah_i_loop_evt_t* evt);

void ah_i_loop_term(ah_loop_t* loop);

#endif
