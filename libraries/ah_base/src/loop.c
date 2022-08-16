// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/loop.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/internal/collections/slab.h"
#include "ah/intrin.h"
#include "loop-evt.h"

static void s_evt_cancel(void* evt);
static void s_term(ah_loop_t* loop);

ah_extern ah_err_t ah_loop_init(ah_loop_t* loop, size_t capacity)
{
    if (loop == NULL) {
        return AH_EINVAL;
    }

    *loop = (ah_loop_t) { 0u };

    ah_err_t err = ah_i_loop_init(loop, &capacity);
    if (err != AH_ENONE) {
        return err;
    }

    ah_assert_if_debug(capacity != 0u);

    err = ah_i_slab_init(&loop->_evt_slab, capacity, sizeof(ah_i_loop_evt_t));
    if (err != AH_ENONE) {
        ah_i_loop_term(loop);
        return err;
    }

    loop->_now = ah_time_now();
    loop->_state = AH_I_LOOP_STATE_INITIAL;

    return AH_ENONE;
}

ah_extern bool ah_loop_is_running(const ah_loop_t* loop)
{
    ah_assert(loop != NULL);

    return loop->_state == AH_I_LOOP_STATE_RUNNING;
}

ah_extern bool ah_loop_is_term(const ah_loop_t* loop)
{
    ah_assert(loop != NULL);

    return (loop->_state & (AH_I_LOOP_STATE_TERMINATING | AH_I_LOOP_STATE_TERMINATED)) != 0;
}

ah_extern struct ah_time ah_loop_now(const ah_loop_t* loop)
{
    ah_assert(loop != NULL);

    return loop->_now;
}

ah_extern ah_err_t ah_loop_run(ah_loop_t* loop)
{
    return ah_loop_run_until(loop, NULL);
}

ah_extern ah_err_t ah_loop_run_until(ah_loop_t* loop, struct ah_time* time)
{
    if (loop == NULL) {
        return AH_EINVAL;
    }
    if ((loop->_state & (AH_I_LOOP_STATE_RUNNING | AH_I_LOOP_STATE_TERMINATING | AH_I_LOOP_STATE_TERMINATED)) != 0) {
        return AH_ESTATE;
    }
    loop->_state = AH_I_LOOP_STATE_RUNNING;

    ah_err_t err;

    do {
        err = ah_i_loop_poll_no_longer_than_until(loop, time);
        if (err != AH_ENONE) {
            break;
        }
    } while (loop->_state == AH_I_LOOP_STATE_RUNNING && (time == NULL || ah_time_is_before(loop->_now, *time)));

    if (loop->_state == AH_I_LOOP_STATE_TERMINATING) {
        s_term(loop);
    }
    else {
        loop->_state = AH_I_LOOP_STATE_STOPPED;
    }

    return err;
}

static void s_term(ah_loop_t* loop)
{
    ah_assert_if_debug(loop != NULL);

    ah_i_slab_term(&loop->_evt_slab, s_evt_cancel);
    ah_i_loop_term(loop);

#ifndef NDEBUG
    *loop = (ah_loop_t) { 0 };
#endif

    loop->_state = AH_I_LOOP_STATE_TERMINATED;
}

static void s_evt_cancel(void* evt)
{
    ah_i_loop_evt_call_as_canceled(evt);
}

ah_extern ah_err_t ah_loop_stop(ah_loop_t* loop)
{
    if (loop == NULL) {
        return AH_EINVAL;
    }
    if (loop->_state != AH_I_LOOP_STATE_RUNNING) {
        return AH_ESTATE;
    }
    loop->_state = AH_I_LOOP_STATE_STOPPED;
    return AH_ENONE;
}

ah_err_t ah_loop_term(ah_loop_t* loop)
{
    if (loop == NULL) {
        return AH_EINVAL;
    }

    ah_err_t err;

    switch (loop->_state) {
    case AH_I_LOOP_STATE_INITIAL:
#ifndef NDEBUG
        *loop = (ah_loop_t) { 0 };
#endif
        loop->_state = AH_I_LOOP_STATE_TERMINATED;
        err = AH_ENONE;
        break;

    case AH_I_LOOP_STATE_STOPPED:
        s_term(loop);
        err = AH_ENONE;
        break;

    case AH_I_LOOP_STATE_RUNNING:
        loop->_state = AH_I_LOOP_STATE_TERMINATING;
        err = AH_ENONE;
        break;

    default:
        err = AH_ESTATE;
        break;
    }

    return err;
}

bool ah_i_loop_try_set_pending_err(ah_loop_t* loop, ah_err_t err)
{
    if (ah_loop_is_term(loop) || (loop->_pending_err != AH_ENONE && loop->_pending_err != err)) {
        return false;
    }
    loop->_pending_err = err;
    return true;
}

ah_err_t ah_i_loop_get_pending_err(ah_loop_t* loop)
{
    ah_assert_if_debug(loop != NULL);

    if (loop->_pending_err != AH_ENONE) {
        ah_err_t err = loop->_pending_err;
        loop->_pending_err = AH_ENONE;
        return err;
    }

    return AH_ENONE;
}

ah_err_t ah_i_loop_evt_alloc(ah_loop_t* loop, ah_i_loop_evt_t** evt)
{
    ah_assert_if_debug(loop != NULL);
    ah_assert_if_debug(evt != NULL);

    if (ah_loop_is_term(loop)) {
        return AH_ECANCELED;
    }

    ah_i_loop_evt_t* free_evt = ah_i_slab_alloc(&loop->_evt_slab);
    if (free_evt == NULL) {
        return AH_ENOMEM;
    }

#if AH_USE_IOCP
    free_evt->_overlapped = (OVERLAPPED) { 0u };
#endif

    *evt = free_evt;

    return AH_ENONE;
}

void ah_i_loop_evt_dealloc(ah_loop_t* loop, ah_i_loop_evt_t* evt)
{
    ah_assert_if_debug(loop != NULL);
    ah_assert_if_debug(evt != NULL);

    ah_i_slab_free(&loop->_evt_slab, evt);
}
