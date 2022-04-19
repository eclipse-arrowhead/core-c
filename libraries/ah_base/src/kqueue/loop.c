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
#include <unistd.h>

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

    if (opts->capacity > INT_MAX) {
        return AH_EDOM;
    }

    int kqueue_fd = kqueue();
    if (kqueue_fd == -1) {
        return errno;
    }

    ah_err_t err;

    if (fcntl(kqueue_fd, F_SETFD, FD_CLOEXEC) != 0) {
        err = errno;
        goto close_fd_and_return_err;
    }

    struct kevent* kqueue_changelist = ah_malloc_array(opts->alloc_cb, opts->capacity, sizeof(struct kevent));
    if (kqueue_changelist == NULL) {
        err = errno;
        goto close_fd_and_return_err;
    }

    struct kevent* kqueue_eventlist = ah_malloc_array(opts->alloc_cb, opts->capacity, sizeof(struct kevent));
    if (kqueue_eventlist == NULL) {
        err = AH_ENOMEM;
        goto close_fd_free_changelist_and_return_err;
    }

    loop->_kqueue_capacity = (int) opts->capacity;
    loop->_kqueue_fd = kqueue_fd;
    loop->_kqueue_changelist = kqueue_changelist;
    loop->_kqueue_eventlist = kqueue_eventlist;

    return AH_ENONE;

close_fd_free_changelist_and_return_err:
    ah_dealloc(opts->alloc_cb, kqueue_changelist);

close_fd_and_return_err:
    (void) close(kqueue_fd);

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
        ah_i_loop_evt_t* evt = kev->udata;

        if (ah_likely(evt != NULL)) {
            if (ah_likely(evt->_cb != NULL)) {
                evt->_cb(evt, kev);
            }
            if ((kev->flags & (EV_DELETE | EV_ONESHOT | EV_ERROR)) != 0) {
                ah_i_loop_evt_dealloc(loop, evt);
            }
        }

        err = ah_i_loop_get_pending_err(loop);
        if (ah_unlikely(err != AH_ENONE)) {
            return err;
        }

        if (ah_unlikely(loop->_state != state)) {
            break;
        }
    }

    return AH_ENONE;
}

ah_extern ah_err_t ah_i_loop_alloc_evt_and_kev(ah_loop_t* loop, ah_i_loop_evt_t** evt, struct kevent** kev)
{
    ah_assert_if_debug(loop != NULL);
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(kev != NULL);

    ah_err_t err;

    ah_i_loop_evt_t* evt0;
    struct kevent* kev0;

    err = ah_i_loop_evt_alloc(loop, &evt0);
    if (err != AH_ENONE) {
        return err;
    }

    err = ah_i_loop_alloc_kev(loop, &kev0);
    if (err != AH_ENONE) {
        ah_i_loop_evt_dealloc(loop, evt0);
        return err;
    }

    *evt = evt0;
    *kev = kev0;

    return AH_ENONE;
}

ah_extern ah_err_t ah_i_loop_alloc_kev(ah_loop_t* loop, struct kevent** kev)
{
    ah_assert_if_debug(loop != NULL);
    ah_assert_if_debug(kev != NULL);

    if (ah_loop_is_term(loop)) {
        return AH_ESTATE;
    }

    if (ah_unlikely(loop->_kqueue_nchanges == loop->_kqueue_capacity)) {
        int res = kevent(loop->_kqueue_fd, loop->_kqueue_changelist, loop->_kqueue_nchanges, NULL, 0,
            &(struct timespec) { 0 });

        if (ah_unlikely(res < 0)) {
            if (res != ENOMEM) {
                loop->_pending_err = errno;
                return AH_ENOMEM;
            }
            ah_err_t err = ah_i_loop_poll_no_longer_than_until(loop, NULL);
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

    *kev = &loop->_kqueue_changelist[loop->_kqueue_nchanges];

    loop->_kqueue_nchanges += 1;

    return AH_ENONE;
}

ah_extern void ah_i_loop_term(ah_loop_t* loop)
{
    ah_assert_if_debug(loop != NULL);

    ah_dealloc(loop->_alloc_cb, loop->_kqueue_changelist);
    ah_dealloc(loop->_alloc_cb, loop->_kqueue_eventlist);

    (void) close(loop->_kqueue_fd);
}
