// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/task.h"

#include "ah/err.h"
#include "ah/loop.h"

#define S_STATE_MASK (AH_TASK_STATE_INITIAL | AH_TASK_STATE_SCHEDULED | AH_TASK_STATE_EXECUTED | AH_TASK_STATE_CANCELED)

static void s_cancel(ah_task_t* task);

ah_extern ah_err_t ah_task_init(ah_task_t* task, const ah_task_opts_t* opts)
{
    if (task == NULL || opts == NULL || opts->loop == NULL || opts->cb == NULL) {
        return AH_EINVAL;
    }

    *task = (ah_task_t) {
        ._loop = opts->loop,
        ._cb = opts->cb,
        ._user_data = opts->data,
        ._state = AH_TASK_STATE_INITIAL,
    };

    return AH_ENONE;
}

ah_extern ah_err_t ah_task_cancel(ah_task_t* task)
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

static void s_cancel(ah_task_t* task)
{
    ah_assert_if_debug(task != NULL);

    switch (task->_state) {
    case AH_TASK_STATE_INITIAL:
        break;

    case AH_TASK_STATE_SCHEDULED:
        ah_i_task_cancel_scheduled(task);
        break;

    case AH_TASK_STATE_EXECUTED:
    case AH_TASK_STATE_CANCELED:
        break;

    default:
        ah_unreachable();
    }

    task->_state = AH_TASK_STATE_CANCELED;
}

ah_extern ah_err_t ah_task_schedule_at(ah_task_t* task, struct ah_time baseline)
{
    if (task == NULL) {
        return AH_EINVAL;
    }
    if (task->_state != AH_TASK_STATE_INITIAL) {
        return AH_ESTATE;
    }

    ah_err_t err = ah_i_task_schedule_at(task, baseline);
    if (err != AH_ENONE) {
        return err;
    }

    task->_state = AH_TASK_STATE_SCHEDULED;

    return AH_ENONE;
}

ah_extern ah_err_t ah_task_term(ah_task_t* task)
{
    if (task == NULL) {
        return AH_EINVAL;
    }
    if (task->_state == AH_TASK_STATE_SCHEDULED) {
        s_cancel(task);
    }
#ifndef NDEBUG
    *task = (ah_task_t) { 0 };
#endif
    return AH_ENONE;
}
