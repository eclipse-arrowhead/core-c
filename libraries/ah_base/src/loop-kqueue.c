// SPDX-License-Identifier: EPL-2.0

#include "ah/loop.h"

#include "ah/alloc.h"
#include "ah/assert.h"
#include "ah/conf.h"
#include "ah/err.h"

#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

ah_err_t ah_i_loop_init(ah_loop_t* loop, size_t* capacity)
{
    ah_assert_if_debug(loop != NULL);
    ah_assert_if_debug(capacity != NULL);

    if (*capacity == 0u) {
        *capacity = AH_CONF_KQUEUE_DEFAULT_CAPACITY;
    }

    if (*capacity > INT_MAX) {
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

    struct kevent* kqueue_changelist = ah_calloc(*capacity, sizeof(struct kevent));
    if (kqueue_changelist == NULL) {
        err = errno;
        goto close_fd_and_return_err;
    }

    struct kevent* kqueue_eventlist = ah_calloc(*capacity, sizeof(struct kevent));
    if (kqueue_eventlist == NULL) {
        err = AH_ENOMEM;
        goto close_fd_free_changelist_and_return_err;
    }

    loop->_kqueue_capacity = (int) *capacity;
    loop->_kqueue_fd = kqueue_fd;
    loop->_kqueue_changelist = kqueue_changelist;
    loop->_kqueue_eventlist = kqueue_eventlist;

    return AH_ENONE;

close_fd_free_changelist_and_return_err:
    ah_free(kqueue_changelist);

close_fd_and_return_err:
    (void) close(kqueue_fd);

    return err;
}

ah_err_t ah_i_loop_poll_no_longer_than_until(ah_loop_t* loop, ah_time_t* time)
{
    ah_assert_if_debug(loop != NULL);

    ah_err_t err = ah_i_loop_get_pending_err(loop);
    if (err != AH_ENONE) {
        return err;
    }

    loop->_now = ah_time_now();

    struct timespec timeout;
    if (time != NULL) {
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
            bool is_callable = ah_likely(evt->_cb != NULL);
            bool is_complete = !is_callable || (kev->flags & (EV_DELETE | EV_ONESHOT | EV_ERROR)) != 0;

            if (is_callable) {
                evt->_cb(evt, kev);
            }

            if (is_complete) {
                ah_i_loop_evt_dealloc(loop, evt);
            }
        }

        err = ah_i_loop_get_pending_err(loop);
        if (ah_unlikely(err != AH_ENONE)) {
            return err;
        }

        if (ah_unlikely(loop->_state != AH_I_LOOP_STATE_RUNNING)) {
            break;
        }
    }

    return AH_ENONE;
}

ah_err_t ah_i_loop_evt_alloc_with_kev(ah_loop_t* loop, ah_i_loop_evt_t** evt, struct kevent** kev)
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

ah_err_t ah_i_loop_alloc_kev(ah_loop_t* loop, struct kevent** kev)
{
    ah_assert_if_debug(loop != NULL);
    ah_assert_if_debug(kev != NULL);

    if (ah_loop_is_term(loop)) {
        return AH_ECANCELED;
    }

    if (ah_unlikely(loop->_kqueue_nchanges == loop->_kqueue_capacity)) {
        int res = kevent(loop->_kqueue_fd, loop->_kqueue_changelist, loop->_kqueue_nchanges, NULL, 0,
            &(struct timespec) { 0 });

        if (ah_unlikely(res < 0)) {
            if (res != ENOMEM) {
                loop->_pending_err = errno;
                return AH_ENOBUFS;
            }
            ah_err_t err = ah_i_loop_poll_no_longer_than_until(loop, NULL);
            if (err != AH_ENONE) {
                loop->_pending_err = err;
                return AH_ENOBUFS;
            }
            if (ah_unlikely(loop->_kqueue_nchanges == loop->_kqueue_capacity)) {
                return AH_ENOBUFS;
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

void ah_i_loop_term(ah_loop_t* loop)
{
    ah_assert_if_debug(loop != NULL);

    ah_free(loop->_kqueue_changelist);
    ah_free(loop->_kqueue_eventlist);

    (void) close(loop->_kqueue_fd);
}

void ah_i_loop_evt_call_as_canceled(ah_i_loop_evt_t* evt)
{
    ah_assert_if_debug(evt != NULL);

    struct kevent kev;
    EV_SET(&kev, 0u, 0u, EV_ERROR, 0u, ECANCELED, NULL);

    evt->_cb(evt, &kev);
}
