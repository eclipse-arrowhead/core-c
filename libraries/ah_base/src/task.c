// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/task.h"

#include "ah/assert.h"
#include "ah/loop-internal.h"

#if AH_USE_KQUEUE
#    include <sys/event.h>
#elif AH_USE_URING
#    include <liburing.h>
#endif

#define S_STATE_MASK (AH_TASK_STATE_INITIAL | AH_TASK_STATE_SCHEDULED | AH_TASK_STATE_EXECUTED | AH_TASK_STATE_CANCELED)

static void s_cancel(struct ah_task* task);
static void s_on_execution(struct ah_i_loop_evt* evt, ah_i_loop_res_t* res);

ah_extern ah_err_t ah_task_init(struct ah_task* task, const struct ah_task_opts* opts)
{
    if (task == NULL || opts == NULL || opts->loop == NULL || opts->cb == NULL) {
        return AH_EINVAL;
    }

    *task = (struct ah_task) {
        ._loop = opts->loop,
        ._cb = opts->cb,
        ._data = opts->data,
        ._state = AH_TASK_STATE_INITIAL,
    };

    return AH_ENONE;
}

ah_extern ah_err_t ah_task_cancel(struct ah_task* task)
{
    if (task == NULL) {
        return AH_EINVAL;
    }
    if ((task->_state & S_STATE_MASK) == 0) {
        return AH_ESTATE;
    }

    s_cancel(task);

    task->_cb(task, AH_ECANCELED);

    return AH_ENONE;
}

static void s_cancel(struct ah_task* task)
{
    ah_assert_if_debug(task != NULL);

    ah_err_t err;
    ah_i_loop_req_t* req;

    switch (task->_state) {
    case AH_TASK_STATE_INITIAL:
        break;

    case AH_TASK_STATE_SCHEDULED:
        err = ah_i_loop_alloc_req(task->_loop, &req);
        if (ah_unlikely(err != AH_ENONE)) {
            ah_assert_if_debug(task->_evt != NULL);
            task->_evt->_cb = NULL;
            break;
        }

        if (ah_unlikely(task->_state == AH_TASK_STATE_CANCELED)) {
            return;
        }

#if AH_USE_KQUEUE

        EV_SET(req, (uintptr_t) task, EVFILT_TIMER, EV_DELETE, 0u, 0, 0u);

#elif AH_USE_URING

        io_uring_prep_timeout_remove(req, (uint64_t) task->_evt, 0u);
        io_uring_sqe_set_data(req, NULL);

#endif
        break;

    case AH_TASK_STATE_EXECUTED:
    case AH_TASK_STATE_CANCELED:
        break;

    default:
        ah_unreachable();
    }

    task->_state = AH_TASK_STATE_CANCELED;
}

ah_extern ah_err_t ah_task_schedule_at(struct ah_task* task, struct ah_time baseline)
{
    if (task == NULL) {
        return AH_EINVAL;
    }
    if (task->_state != AH_TASK_STATE_INITIAL) {
        return AH_ESTATE;
    }

    ah_err_t err;

    struct ah_i_loop_evt* evt;
    ah_i_loop_req_t* req;

    err = ah_i_loop_alloc_evt_and_req(task->_loop, &evt, &req);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_execution;
    evt->_body._task_schedule_at._task = task;

#if AH_USE_KQUEUE

    uint32_t fflags;
    intptr_t data;

#    if INTPTR_MAX >= INT64_MAX
    fflags = NOTE_ABSOLUTE | NOTE_MACHTIME;
    data = (intptr_t) baseline._mach_absolute_time;
#    else
    fflags = 0; // Relative millisecond timeout.
    uint64_t a = baseline._mach_absolute_time / 1000000;
    uint64_t b = task->_loop->_now._mach_absolute_time / 1000000;
    if (a < b) {
        data = 0;
    }
    else if (ah_i_sub_overflow(a, b, &data)) {
        return AH_ERANGE;
    }
#    endif

    EV_SET(req, (uintptr_t) task, EVFILT_TIMER, EV_ADD | EV_ONESHOT, fflags, data, evt);

#elif AH_USE_URING

    evt->_body._task_schedule_at._baseline = baseline;

    io_uring_prep_timeout(req, &evt->_body._task_schedule_at._baseline._timespec, 0u, IORING_TIMEOUT_ABS);
    io_uring_sqe_set_data(req, evt);

#endif

    task->_evt = evt;
    task->_state = AH_TASK_STATE_SCHEDULED;

    return AH_ENONE;
}

static void s_on_execution(struct ah_i_loop_evt* evt, ah_i_loop_res_t* res)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(res != NULL);

    struct ah_task* task = evt->_body._task_schedule_at._task;
    ah_assert_if_debug(task != NULL);

    if (task->_state == AH_TASK_STATE_CANCELED) {
        return;
    }

    ah_err_t err;

#if AH_USE_KQUEUE

    err = (res->flags & EV_ERROR) != 0 ? (res->flags & EV_ERROR) : AH_ENONE;

#elif AH_USE_URING

    err = (res->res != 0 && res->res != -ETIME) ? -res->res : AH_ENONE;

#else

    err = AH_ENOIMPL;

#endif

    task->_state = AH_TASK_STATE_EXECUTED;
    task->_cb(task, err);
}

ah_extern ah_err_t ah_task_term(struct ah_task* task)
{
    if (task == NULL) {
        return AH_EINVAL;
    }
    if (task->_state == AH_TASK_STATE_SCHEDULED) {
        s_cancel(task);
    }
#ifndef NDEBUG
    *task = (struct ah_task) { 0 };
#endif
    return AH_ENONE;
}
