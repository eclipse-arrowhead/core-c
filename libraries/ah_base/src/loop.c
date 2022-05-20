// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/loop.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/intrin.h"
#include "ah/math.h"
#include "loop-evt.h"

static ah_err_t s_alloc_evt_page(ah_alloc_cb alloc_cb, ah_i_loop_evt_page_t** evt_page, ah_i_loop_evt_t** free_list);
static ah_err_t s_alloc_evt_page_list(ah_alloc_cb alloc_cb, size_t cap, ah_i_loop_evt_page_t** page_list,
    ah_i_loop_evt_t** free_list);
static void s_dealloc_evt_page_list(ah_alloc_cb alloc_cb, ah_i_loop_evt_page_t* evt_page_list);
static void s_cancel_all_pending_events(ah_i_loop_evt_page_t* evt_page_list, ah_i_loop_evt_t* evt_free_list);

static void s_term(ah_loop_t* loop);

ah_extern ah_err_t ah_loop_init(ah_loop_t* loop, ah_loop_opts_t* opts)
{
    if (loop == NULL || opts == NULL) {
        return AH_EINVAL;
    }

    *loop = (ah_loop_t) { 0u };

    ah_err_t err = ah_i_loop_init(loop, opts);
    if (err != AH_ENONE) {
        return err;
    }

    ah_assert_if_debug(opts->alloc_cb != NULL);
    ah_assert_if_debug(opts->capacity != 0u);

    ah_i_loop_evt_page_t* evt_page_list;
    ah_i_loop_evt_t* evt_free_list;
    err = s_alloc_evt_page_list(opts->alloc_cb, opts->capacity, &evt_page_list, &evt_free_list);
    if (err != AH_ENONE) {
        ah_i_loop_term(loop);
        return err;
    }

    loop->_alloc_cb = opts->alloc_cb;
    loop->_evt_page_list = evt_page_list;
    loop->_evt_free_list = evt_free_list;
    loop->_now = ah_time_now();
    loop->_state = AH_I_LOOP_STATE_INITIAL;

    return AH_ENONE;
}

static ah_err_t s_alloc_evt_page_list(ah_alloc_cb alloc_cb, size_t cap, ah_i_loop_evt_page_t** page_list,
    ah_i_loop_evt_t** free_list)
{
    ah_assert_if_debug(alloc_cb != NULL);
    ah_assert_if_debug(page_list != NULL);
    ah_assert_if_debug(free_list != NULL);

    ah_i_loop_evt_page_t* page_list_new = NULL;
    ah_i_loop_evt_t* free_list_new = NULL;

    for (size_t evt_cap_remaining = cap; evt_cap_remaining != 0;) {
        ah_err_t err = s_alloc_evt_page(alloc_cb, &page_list_new, &free_list_new);
        if (err != AH_ENONE) {
            s_dealloc_evt_page_list(alloc_cb, page_list_new);
            return err;
        }
        if (ah_sub_size(evt_cap_remaining, AH_I_LOOP_EVT_PAGE_CAPACITY, &evt_cap_remaining) != AH_ENONE) {
            break;
        }
    }

    *page_list = page_list_new;
    *free_list = free_list_new;

    return AH_ENONE;
}

static ah_err_t s_alloc_evt_page(ah_alloc_cb alloc_cb, ah_i_loop_evt_page_t** evt_page, ah_i_loop_evt_t** free_list)
{
    ah_assert_if_debug(alloc_cb != NULL);
    ah_assert_if_debug(evt_page != NULL);
    ah_assert_if_debug(free_list != NULL);

    ah_i_loop_evt_page_t* evt_page_next = *evt_page;
    ah_i_loop_evt_page_t* evt_page_first = ah_malloc(alloc_cb, sizeof(ah_i_loop_evt_page_t));
    if (evt_page_first == NULL) {
        return AH_ENOMEM;
    }

    ah_i_loop_evt_t* array = evt_page_first->_evt_array;
    for (size_t i = 1; i < AH_I_LOOP_EVT_PAGE_CAPACITY; i += 1) {
        array[i - 1]._next_free = &array[i];
    }

    array[AH_I_LOOP_EVT_PAGE_CAPACITY - 1]._next_free = (evt_page_next != NULL) ? &evt_page_next->_evt_array[0] : NULL;

    evt_page_first->_next_page = evt_page_next;

    *evt_page = evt_page_first;
    *free_list = &array[0];

    return AH_ENONE;
}

static void s_dealloc_evt_page_list(ah_alloc_cb alloc_cb, ah_i_loop_evt_page_t* evt_page_list)
{
    ah_assert_if_debug(alloc_cb != NULL);

    ah_i_loop_evt_page_t* page = evt_page_list;
    while (page != NULL) {
        ah_i_loop_evt_page_t* next_page = page->_next_page;
        ah_dealloc(alloc_cb, page);
        page = next_page;
    }
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

    s_cancel_all_pending_events(loop->_evt_page_list, loop->_evt_free_list);
    s_dealloc_evt_page_list(loop->_alloc_cb, loop->_evt_page_list);

    ah_i_loop_term(loop);

#ifndef NDEBUG
    *loop = (ah_loop_t) { 0 };
#endif

    loop->_state = AH_I_LOOP_STATE_TERMINATED;
}

static void s_cancel_all_pending_events(ah_i_loop_evt_page_t* evt_page_list, ah_i_loop_evt_t* evt_free_list)
{
    ah_assert_if_debug(evt_page_list != NULL);
    ah_assert_if_debug(evt_free_list != NULL);

    // Mark all free events.
    for (ah_i_loop_evt_t* free_evt = evt_free_list; free_evt != NULL; free_evt = free_evt->_next_free) {
        free_evt->_subject = NULL;
    }

    // Call all non-free events.
    for (ah_i_loop_evt_page_t* page = evt_page_list; page != NULL; page = page->_next_page) {
        for (size_t i = 1; i < AH_I_LOOP_EVT_PAGE_CAPACITY; i += 1) {
            ah_i_loop_evt_t* evt = &page->_evt_array[i];
            if (evt->_subject == NULL) {
                continue;
            }
            ah_i_loop_evt_call_as_canceled(evt);
        }
    }
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

    if (loop->_evt_free_list == NULL) {
        ah_err_t err = s_alloc_evt_page(loop->_alloc_cb, &loop->_evt_page_list, &loop->_evt_free_list);
        if (err != AH_ENONE) {
            return err;
        }
    }

    ah_i_loop_evt_t* free_evt = loop->_evt_free_list;
    ah_i_loop_evt_t* next_free = free_evt->_next_free;

    loop->_evt_free_list = next_free;

#ifndef NDEBUG
    // Help detect double free in debug builds.
    free_evt->_next_free = NULL;
#endif

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
    ah_assert_if_debug(evt->_next_free == NULL); // Detect double free in debug builds.

    evt->_next_free = loop->_evt_free_list;
    loop->_evt_free_list = evt;
}
