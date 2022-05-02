// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/loop.h"

#include "ah/assert.h"
#include "ah/err.h"

#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>

ah_extern ah_err_t ah_i_loop_init(ah_loop_t* loop, ah_loop_opts_t* opts)
{
    ah_assert_if_debug(loop != NULL);
    ah_assert_if_debug(opts != NULL);

    if (opts->alloc_cb == NULL) {
        opts->alloc_cb = realloc;
    }

    if (opts->capacity == 0u) {
        opts->capacity = 1024u;
    }

    if (opts->capacity > UINT_MAX) {
        return AH_EDOM;
    }

    int err = io_uring_queue_init((unsigned) opts->capacity, &loop->_uring, 0u);
    if (err != 0) {
        return -err;
    }

    err = io_uring_ring_dontfork(&loop->_uring);
    if (err != 0) {
        err = -err;
        goto exit_uring_and_return_err;
    }

    if (fcntl(loop->_uring.ring_fd, F_SETFD, FD_CLOEXEC) != 0) {
        err = errno;
        goto exit_uring_and_return_err;
    }

    return AH_ENONE;

exit_uring_and_return_err:
    io_uring_queue_exit(&loop->_uring);

    return err;
}

ah_extern ah_err_t ah_i_loop_poll_no_longer_than_until(ah_loop_t* loop, struct ah_time* time)
{
    ah_assert_if_debug(loop != NULL);

    ah_err_t err = ah_i_loop_get_pending_err(loop);
    if (err != AH_ENONE) {
        return err;
    }

    const int state = loop->_state;
    loop->_now = ah_time_now();

    struct io_uring_cqe* cqe;

    int res;

    if (time != NULL) {
        struct __kernel_timespec timeout;

        ah_timediff_t diff;
        err = ah_time_diff(*time, loop->_now, &diff);
        if (err != AH_ENONE) {
            return AH_EDOM;
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
    ah_i_loop_evt_t* evt = io_uring_cqe_get_data(cqe);

        if (evt != NULL && cqe->res != -ECANCELED) {
            if (evt->_cb != NULL) {
                evt->_cb(evt, cqe);
            }
            ah_i_loop_evt_dealloc(loop, evt);
        }

        io_uring_cqe_seen(&loop->_uring, cqe);

        err = ah_i_loop_get_pending_err(loop);
        if (err != AH_ENONE) {
            return err;
        }

        if (ah_unlikely(loop->_state != state)) {
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
}

ah_extern ah_err_t ah_i_loop_evt_alloc_with_sqe(ah_loop_t* loop, ah_i_loop_evt_t** evt, struct io_uring_sqe** sqe)
{
    ah_assert_if_debug(loop != NULL);
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(sqe != NULL);

    ah_err_t err;

    ah_i_loop_evt_t* evt0;
    struct io_uring_sqe* sqe0;

    err = ah_i_loop_evt_alloc(loop, &evt0);
    if (err != AH_ENONE) {
        return err;
    }

    err = ah_i_loop_alloc_sqe(loop, &sqe0);
    if (err != AH_ENONE) {
        ah_i_loop_evt_dealloc(loop, evt0);
        return err;
    }

    *evt = evt0;
    *sqe = sqe0;

    return AH_ENONE;
}

ah_extern ah_err_t ah_i_loop_alloc_sqe(ah_loop_t* loop, struct io_uring_sqe** sqe)
{
    ah_assert_if_debug(loop != NULL);
    ah_assert_if_debug(sqe != NULL);

    if (ah_loop_is_term(loop)) {
        return AH_ESTATE;
    }

    struct io_uring_sqe* sqe0 = io_uring_get_sqe(&loop->_uring);
    if (ah_unlikely(sqe0 == NULL)) {
        int res = io_uring_submit(&loop->_uring);
        if (ah_unlikely(res < 0)) {
            if (res != -EAGAIN && res != -EBUSY) {
                loop->_pending_err = -res;
                return AH_ENOBUFS;
            }
            ah_err_t err = ah_i_loop_poll_no_longer_than_until(loop, NULL);
            if (err != AH_ENONE) {
                loop->_pending_err = err;
                return AH_ENOBUFS;
            }
        }
        sqe0 = io_uring_get_sqe(&loop->_uring);
        if (ah_unlikely(sqe0 == NULL)) {
            return AH_ENOBUFS;
        }
    }

    *sqe = sqe0;

    return AH_ENONE;
}

ah_extern void ah_i_loop_term(ah_loop_t* loop)
{
    ah_assert_if_debug(loop != NULL);

    io_uring_queue_exit(&loop->_uring);
}
