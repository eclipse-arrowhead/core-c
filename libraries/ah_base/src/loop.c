// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/loop.h"

#include "ah/assert.h"
#include "ah/loop-internal.h"
#include "ah/math.h"

#include <stdlib.h>

#if AH_USE_KQUEUE || AH_USE_URING
#    include <fcntl.h>
#    include <limits.h>
#endif

#if AH_USE_KQUEUE
#    include <unistd.h>
#endif

#define S_STATE_INITIAL     0x01
#define S_STATE_RUNNING     0x02
#define S_STATE_STOPPED     0x04
#define S_STATE_TERMINATING 0x08
#define S_STATE_TERMINATED  0x10

#define S_EVT_PAGE_SIZE     8192
#define S_EVT_PAGE_CAPACITY ((S_EVT_PAGE_SIZE / sizeof(struct ah_i_loop_evt)) - 1)

struct ah_i_loop_evt_page {
    struct ah_i_loop_evt _evt_array[S_EVT_PAGE_CAPACITY];
    void* _pad[3];
    struct ah_i_loop_evt_page* _next_page;
};

typedef struct ah_i_loop_evt_page s_evt_page_t;
typedef struct ah_i_loop_evt s_evt_t;

static ah_err_t s_alloc_evt_page(ah_alloc_cb alloc_cb, s_evt_page_t** evt_page, s_evt_t** free_list);
static ah_err_t s_alloc_evt_page_list(ah_alloc_cb alloc_cb, size_t cap, s_evt_page_t** page_list, s_evt_t** free_list);
static void s_dealloc_evt_page_list(ah_alloc_cb alloc_cb, s_evt_page_t* evt_page_list);
static ah_err_t s_get_pending_err(struct ah_loop* loop);
static ah_err_t s_poll_no_longer_than_until(struct ah_loop* loop, struct ah_time* time);
static void s_term(struct ah_loop* loop);

ah_err_t ah_loop_init(struct ah_loop* loop, const struct ah_loop_opts* opts)
{
    if (loop == NULL) {
        return AH_EINVAL;
    }

    *loop = (struct ah_loop) { 0 };

    size_t capacity = (opts != NULL && opts->capacity != 0u) ? opts->capacity : 1024;
    ah_alloc_cb alloc_cb = (opts != NULL && opts->alloc_cb != NULL) ? opts->alloc_cb : realloc;

    ah_err_t err;

    s_evt_page_t* evt_page_list;
    s_evt_t* evt_free_list;
    err = s_alloc_evt_page_list(alloc_cb, capacity, &evt_page_list, &evt_free_list);
    if (err != AH_ENONE) {
        return err;
    }

#if AH_USE_KQUEUE

    if (capacity > INT_MAX) {
        err = errno;
        goto free_evt_page_list_and_return_err;
    }

    int kqueue_fd = kqueue();
    if (kqueue_fd == -1) {
        err = errno;
        goto free_evt_page_list_and_return_err;
    }

    if (fcntl(kqueue_fd, F_SETFD, FD_CLOEXEC) != 0) {
        err = errno;
        goto free_evt_page_list_close_fd_and_return_err;
    }

    struct kevent* kqueue_changelist = ah_malloc_array(alloc_cb, capacity, sizeof(struct kevent));
    if (kqueue_changelist == NULL) {
        err = errno;
        goto free_evt_page_list_close_fd_and_return_err;
    }

    struct kevent* kqueue_eventlist = ah_malloc_array(alloc_cb, capacity, sizeof(struct kevent));
    if (kqueue_eventlist == NULL) {
        err = AH_ENOMEM;
        goto free_evt_page_list_close_fd_free_changelist_and_return_err;
    }

    loop->_kqueue_capacity = (int) capacity;
    loop->_kqueue_fd = kqueue_fd;
    loop->_kqueue_changelist = kqueue_changelist;
    loop->_kqueue_eventlist = kqueue_eventlist;

#elif AH_USE_URING

    if (capacity > UINT_MAX) {
        err = errno;
        goto free_evt_page_list_and_return_err;
    }

    err = io_uring_queue_init((unsigned) capacity, &loop->_uring, 0u);
    if (err != 0) {
        err = -err;
        goto free_evt_page_list_and_return_err;
    }

    err = io_uring_ring_dontfork(&loop->_uring);
    if (err != 0) {
        err = -err;
        goto free_evt_page_list_exit_uring_and_return_err;
    }

    if (fcntl(loop->_uring.ring_fd, F_SETFD, FD_CLOEXEC) != 0) {
        err = errno;
        goto free_evt_page_list_exit_uring_and_return_err;
    }

#else

    (void) capacity;
    err = AH_ENOIMPL;
    goto free_evt_page_list_and_return_err;

#endif

    loop->_alloc_cb = alloc_cb;
    loop->_evt_page_list = evt_page_list;
    loop->_evt_free_list = evt_free_list;
    loop->_now = ah_time_now();
    loop->_state = S_STATE_INITIAL;

    return AH_ENONE;

#if AH_USE_KQUEUE

free_evt_page_list_close_fd_free_changelist_and_return_err:
    ah_dealloc(alloc_cb, kqueue_changelist);

free_evt_page_list_close_fd_and_return_err:
    (void) close(kqueue_fd);

#elif AH_USE_URING

free_evt_page_list_exit_uring_and_return_err:
    io_uring_queue_exit(&loop->_uring);

#endif

free_evt_page_list_and_return_err:
    s_dealloc_evt_page_list(alloc_cb, evt_page_list);

    return err;
}

static ah_err_t s_alloc_evt_page_list(ah_alloc_cb alloc_cb, size_t cap, s_evt_page_t** page_list, s_evt_t** free_list)
{
    ah_assert_if_debug(alloc_cb != NULL);
    ah_assert_if_debug(page_list != NULL);
    ah_assert_if_debug(free_list != NULL);

    s_evt_page_t* page_list_new = NULL;
    s_evt_t* free_list_new;

    for (size_t evt_cap_remaining = cap; evt_cap_remaining != 0;) {
        ah_err_t err = s_alloc_evt_page(alloc_cb, &page_list_new, &free_list_new);
        if (err != AH_ENONE) {
            s_dealloc_evt_page_list(alloc_cb, page_list_new);
            return err;
        }
        if (ah_sub_size(evt_cap_remaining, S_EVT_PAGE_CAPACITY, &evt_cap_remaining) != AH_ENONE) {
            break;
        }
    }

    *page_list = page_list_new;
    *free_list = free_list_new;

    return AH_ENONE;
}

static ah_err_t s_alloc_evt_page(ah_alloc_cb alloc_cb, s_evt_page_t** evt_page, s_evt_t** free_list)
{
    ah_assert_if_debug(alloc_cb != NULL);
    ah_assert_if_debug(evt_page != NULL);
    ah_assert_if_debug(free_list != NULL);

    s_evt_page_t* evt_page_next = *evt_page;
    s_evt_page_t* evt_page_first = ah_malloc(alloc_cb, sizeof(s_evt_page_t));
    if (evt_page_first == NULL) {
        return AH_ENOMEM;
    }

    s_evt_t* array = evt_page_first->_evt_array;
    for (size_t i = 1; i < S_EVT_PAGE_CAPACITY; i += 1) {
        array[i - 1]._next_free = &array[i];
    }

    array[S_EVT_PAGE_CAPACITY - 1]._next_free = (evt_page_next != NULL) ? &evt_page_next->_evt_array[0] : NULL;

    evt_page_first->_next_page = evt_page_next;

    *evt_page = evt_page_first;
    *free_list = &array[0];

    return AH_ENONE;
}

static void s_dealloc_evt_page_list(ah_alloc_cb alloc_cb, s_evt_page_t* evt_page_list)
{
    ah_assert_if_debug(alloc_cb != NULL);

    s_evt_page_t* page = evt_page_list;
    while (page != NULL) {
        s_evt_page_t* next_page = page->_next_page;
        ah_dealloc(alloc_cb, page);
        page = next_page;
    }
}

ah_extern bool ah_loop_is_term(const struct ah_loop* loop)
{
    ah_assert(loop != NULL);

    return (loop->_state & (S_STATE_TERMINATING | S_STATE_TERMINATED)) != 0;
}

ah_extern struct ah_time ah_loop_now(const struct ah_loop* loop)
{
    ah_assert(loop != NULL);

    return loop->_now;
}

ah_extern ah_err_t ah_loop_run(struct ah_loop* loop)
{
    return ah_loop_run_until(loop, NULL);
}

ah_extern ah_err_t ah_loop_run_until(struct ah_loop* loop, struct ah_time* time)
{
    if (loop == NULL) {
        return AH_EINVAL;
    }
    if ((loop->_state & (S_STATE_RUNNING | S_STATE_TERMINATING | S_STATE_TERMINATED)) != 0) {
        return AH_ESTATE;
    }
    loop->_state = S_STATE_RUNNING;

    ah_err_t err;

    do {
        err = s_poll_no_longer_than_until(loop, time);
        if (err != AH_ENONE) {
            break;
        }
    } while (loop->_state == S_STATE_RUNNING && (time == NULL || ah_time_is_before(loop->_now, *time)));

    if (loop->_state == S_STATE_TERMINATING) {
        s_term(loop);
    }
    else {
        loop->_state = S_STATE_STOPPED;
    }

    return err;
}

static void s_term(struct ah_loop* loop)
{
    ah_assert_if_debug(loop != NULL);

    s_dealloc_evt_page_list(loop->_alloc_cb, loop->_evt_page_list);

#if AH_USE_KQUEUE

    ah_dealloc(loop->_alloc_cb, loop->_kqueue_changelist);
    ah_dealloc(loop->_alloc_cb, loop->_kqueue_eventlist);

    (void) close(loop->_kqueue_fd);

#elif AH_USE_URING

    io_uring_queue_exit(&loop->_uring);

#endif

#ifndef NDEBUG
    *loop = (struct ah_loop) { 0 };
#endif

    loop->_state = S_STATE_TERMINATED;
}

static ah_err_t s_poll_no_longer_than_until(struct ah_loop* loop, struct ah_time* time)
{
    ah_assert_if_debug(loop != NULL);

    ah_err_t err = s_get_pending_err(loop);
    if (err != AH_ENONE) {
        return err;
    }

    loop->_now = ah_time_now();

#if AH_USE_KQUEUE

    struct timespec timeout;
    if (time != NULL) {
        ah_timediff_t diff;
        err = ah_time_diff(*time, loop->_now, &diff);
        if (err != AH_ENONE) {
            return err;
        }
        if (diff < 0) {
            diff = 0;
        }
        timeout.tv_sec = diff / 1000000000;
        timeout.tv_nsec = diff % 1000000000;
    }
    else {
        timeout.tv_sec = 0;
        timeout.tv_nsec = 0;
    }

    const int nevents = kevent(loop->_kqueue_fd, loop->_kqueue_changelist, loop->_kqueue_nchanges,
        loop->_kqueue_eventlist, loop->_kqueue_capacity, time != NULL ? &timeout : NULL);

    if (ah_unlikely(nevents < 0)) {
        return errno;
    }

    loop->_kqueue_nchanges = 0;
    loop->_now = ah_time_now();

    for (int i = 0; i < nevents; i += 1) {
        struct kevent* kev = &loop->_kqueue_eventlist[i];
        s_evt_t* evt = (void*) kev->udata;

        if (evt != NULL) {
            if (evt->_cb != NULL) {
                evt->_cb(evt, kev);
            }
            ah_i_loop_dealloc_evt(loop, evt);
        }

        err = s_get_pending_err(loop);
        if (err != AH_ENONE) {
            return err;
        }

        if (ah_unlikely(loop->_state != S_STATE_RUNNING)) {
            break;
        }
    }

    return AH_ENONE;

#elif AH_USE_URING

    struct io_uring_cqe* cqe;

    int res;

    if (time != NULL) {
        struct __kernel_timespec timeout;

        ah_timediff_t diff;
        err = ah_time_diff(*time, loop->_now, &diff);
        if (err != AH_ENONE) {
            return err;
        }
        if (diff < 0) {
            diff = 0;
        }
        timeout.tv_sec = diff / 1000000000;
        timeout.tv_nsec = diff % 1000000000;

        // TODO: Replace these two calls with io_uring_submit_and_wait_timeout() when liburing-2.2 comes out.
        res = io_uring_submit(&loop->_uring);
        if (res < 0) {
            return -res;
        }

        res = io_uring_wait_cqes(&loop->_uring, &cqe, 1, &timeout, NULL);
        if (res == -ETIME) {
            return AH_ENONE;
        }
    }
    else {
        res = io_uring_submit_and_wait(&loop->_uring, 1);
    }

    if (ah_unlikely(res < 0)) {
        return -res;
    }

    loop->_now = ah_time_now();

    for (;;) {
        s_evt_t* evt = io_uring_cqe_get_data(cqe);

        if (evt != NULL && cqe->res != -ECANCELED) {
            if (evt->_cb != NULL) {
                evt->_cb(evt, cqe);
            }
            ah_i_loop_dealloc_evt(loop, evt);
        }

        io_uring_cqe_seen(&loop->_uring, cqe);

        err = s_get_pending_err(loop);
        if (err != AH_ENONE) {
            return err;
        }

        if (ah_unlikely(loop->_state != S_STATE_RUNNING)) {
            break;
        }

        res = io_uring_peek_cqe(&loop->_uring, &cqe);
        if (res != 0) {
            if (ah_likely(res == -EAGAIN)) {
                break;
            }
            return -res;
        }
    }

    return AH_ENONE;

#endif
}

static ah_err_t s_get_pending_err(struct ah_loop* loop)
{
    ah_assert_if_debug(loop != NULL);

    if (loop->_pending_err != AH_ENONE) {
        ah_err_t err = loop->_pending_err;
        loop->_pending_err = AH_ENONE;
        return err;
    }

    return AH_ENONE;
}

ah_extern ah_err_t ah_loop_stop(struct ah_loop* loop)
{
    if (loop == NULL) {
        return AH_EINVAL;
    }
    if (loop->_state != S_STATE_RUNNING) {
        return AH_ESTATE;
    }
    loop->_state = S_STATE_STOPPED;
    return AH_ENONE;
}

ah_err_t ah_loop_term(struct ah_loop* loop)
{
    if (loop == NULL) {
        return AH_EINVAL;
    }

    ah_err_t err;

    switch (loop->_state) {
    case S_STATE_INITIAL:
#ifndef NDEBUG
        *loop = (struct ah_loop) { 0 };
#endif
        loop->_state = S_STATE_TERMINATED;
        err = AH_ENONE;
        break;

    case S_STATE_STOPPED:
        s_term(loop);
        err = AH_ENONE;
        break;

    case S_STATE_RUNNING:
        loop->_state = S_STATE_TERMINATING;
        err = AH_ENONE;
        break;

    default:
        err = AH_ESTATE;
        break;
    }

    return err;
}

ah_err_t ah_i_loop_alloc_evt(struct ah_loop* loop, s_evt_t** evt)
{
    ah_assert_if_debug(loop != NULL);
    ah_assert_if_debug(evt != NULL);

    if ((loop->_state & (S_STATE_TERMINATING | S_STATE_TERMINATED)) != 0) {
        return AH_ESTATE;
    }

    if (loop->_evt_free_list == NULL) {
        ah_err_t err = s_alloc_evt_page(loop->_alloc_cb, &loop->_evt_page_list, &loop->_evt_free_list);
        if (err != AH_ENONE) {
            return err;
        }
    }

    s_evt_t* free_evt = loop->_evt_free_list;
    s_evt_t* next_free = free_evt->_next_free;

    loop->_evt_free_list = next_free;

#ifndef NDEBUG
    // Help detect double free in debug builds.
    free_evt->_next_free = NULL;
#endif

    *evt = free_evt;

    return AH_ENONE;
}

ah_err_t ah_i_loop_alloc_evt_and_req(struct ah_loop* loop, s_evt_t** evt, ah_i_loop_req_t** req)
{
    ah_assert_if_debug(loop != NULL);
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(req != NULL);

    ah_err_t err;

    s_evt_t* evt0;
    ah_i_loop_req_t* req0;

    err = ah_i_loop_alloc_evt(loop, &evt0);
    if (err != AH_ENONE) {
        return err;
    }

    err = ah_i_loop_alloc_req(loop, &req0);
    if (err != AH_ENONE) {
        ah_i_loop_dealloc_evt(loop, evt0);
        return err;
    }

    *evt = evt0;
    *req = req0;

    return AH_ENONE;
}

ah_err_t ah_i_loop_alloc_req(struct ah_loop* loop, ah_i_loop_req_t** req)
{
    ah_assert_if_debug(loop != NULL);
    ah_assert_if_debug(req != NULL);

    if ((loop->_state & (S_STATE_TERMINATING | S_STATE_TERMINATED)) != 0) {
        return AH_ESTATE;
    }

#if AH_USE_KQUEUE

    if (ah_unlikely(loop->_kqueue_nchanges == loop->_kqueue_capacity)) {
        int res = kevent(loop->_kqueue_fd, loop->_kqueue_changelist, loop->_kqueue_nchanges, NULL, 0,
            &(struct timespec) { 0 });

        if (ah_unlikely(res < 0)) {
            if (res != ENOMEM) {
                loop->_pending_err = errno;
                return AH_ENOMEM;
            }
            ah_err_t err = s_poll_no_longer_than_until(loop, NULL);
            if (err != AH_ENONE) {
                loop->_pending_err = err;
                return AH_ENOMEM;
            }
            if (ah_unlikely(loop->_kqueue_nchanges == loop->_kqueue_capacity)) {
                return AH_ENOMEM;
            }
        }
        else {
            loop->_kqueue_nchanges = 0;
        }
    }

    *req = &loop->_kqueue_changelist[loop->_kqueue_nchanges];

    loop->_kqueue_nchanges += 1;

    return AH_ENONE;

#elif AH_USE_URING

    struct io_uring_sqe* sqe = io_uring_get_sqe(&loop->_uring);
    if (ah_unlikely(sqe == NULL)) {
        int res = io_uring_submit(&loop->_uring);
        if (ah_unlikely(res < 0)) {
            if (res != -EAGAIN && res != -EBUSY) {
                loop->_pending_err = -res;
                return AH_ENOMEM;
            }
            ah_err_t err = s_poll_no_longer_than_until(loop, NULL);
            if (err != AH_ENONE) {
                loop->_pending_err = err;
                return AH_ENOMEM;
            }
        }
        sqe = io_uring_get_sqe(&loop->_uring);
        if (ah_unlikely(sqe == NULL)) {
            return AH_ENOMEM;
        }
    }

    *req = sqe;

    return AH_ENONE;

#endif
}

void ah_i_loop_dealloc_evt(struct ah_loop* loop, s_evt_t* evt)
{
    ah_assert_if_debug(loop != NULL);
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(evt->_next_free == NULL); // Detect double free in debug builds.

    evt->_next_free = loop->_evt_free_list;
    loop->_evt_free_list = evt;
}

bool ah_i_loop_try_set_pending_err(struct ah_loop* loop, ah_err_t err)
{
    if (ah_loop_is_term(loop)) {
        return false;
    }
    loop->_pending_err = err;
    return true;
}
