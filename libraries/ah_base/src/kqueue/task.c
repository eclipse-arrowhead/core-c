// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/task.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"
#include "ah/time.h"

#include <stddef.h>

static void s_on_execution(ah_i_loop_evt_t* evt, struct kevent* kev);

ah_extern void ah_i_task_cancel_scheduled(ah_task_t* task)
{
    ah_assert_if_debug(task != NULL);
    ah_assert_if_debug(task->_state == AH_TASK_STATE_SCHEDULED);

    struct kevent* kev;

    ah_err_t err = ah_i_loop_alloc_kev(task->_loop, &kev);
    if (ah_unlikely(err != AH_ENONE)) {
        ah_assert_if_debug(task->_evt != NULL);
        task->_evt->_cb = NULL;
        return;
    }

    if (ah_unlikely(task->_state == AH_TASK_STATE_CANCELED)) {
        return;
    }

    EV_SET(kev, (uintptr_t) task, EVFILT_TIMER, EV_DELETE, 0u, 0, 0u);
}

ah_extern ah_err_t ah_i_task_schedule_at(ah_task_t* task, struct ah_time baseline)
{
    ah_i_loop_evt_t* evt;
    struct kevent* kev;

    ah_err_t err = ah_i_loop_evt_alloc_with_kev(task->_loop, &evt, &kev);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_execution;
    evt->_body._task_schedule_at._task = task;

    uint32_t fflags;
    intptr_t data;

#if INTPTR_MAX >= INT64_MAX

    fflags = NOTE_ABSOLUTE | NOTE_MACHTIME;
    data = (intptr_t) baseline._mach_absolute_time;

#else

    fflags = 0; // Relative millisecond timeout.
    uint64_t a = baseline._mach_absolute_time / 1000000;
    uint64_t b = task->_loop->_now._mach_absolute_time / 1000000;
    if (a < b) {
        data = 0;
    }
    else if (ah_p_sub_overflow(a, b, &data)) {
        return AH_ERANGE;
    }

#endif

    EV_SET(kev, (uintptr_t) task, EVFILT_TIMER, EV_ADD | EV_ONESHOT, fflags, data, evt);

    task->_evt = evt;

    return AH_ENONE;
}

static void s_on_execution(ah_i_loop_evt_t* evt, struct kevent* kev)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(kev != NULL);

    ah_task_t* task = evt->_body._task_schedule_at._task;
    ah_assert_if_debug(task != NULL);

    if (task->_state == AH_TASK_STATE_CANCELED) {
        return;
    }

    ah_err_t err = (kev->flags & EV_ERROR) != 0 ? (kev->flags & EV_ERROR) : AH_ENONE;

    task->_state = AH_TASK_STATE_EXECUTED;
    task->_cb(task, err);
}
