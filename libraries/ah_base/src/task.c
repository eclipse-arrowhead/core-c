// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/task.h"

#include "ah/err.h"
#include "ah/loop.h"

ah_extern void ah_task_init(ah_task_t* task, ah_loop_t* loop, ah_task_cb cb)
{
    ah_assert_if_debug(task != NULL);
    ah_assert_if_debug(loop != NULL);
    ah_assert_if_debug(cb != NULL);

    *task = (ah_task_t) {
        ._loop = loop,
        ._cb = cb,
        ._state = AH_TASK_STATE_INITIAL,
    };
}

ah_extern void ah_task_cancel(ah_task_t* task)
{
    ah_assert_if_debug(task != NULL);

    if (task->_state == AH_TASK_STATE_SCHEDULED) {
        ah_i_task_cancel_scheduled(task);
        task->_state = AH_TASK_STATE_CANCELED;
        task->_cb(task, AH_ECANCELED);
    }
}

ah_extern ah_err_t ah_task_schedule_at(ah_task_t* task, struct ah_time baseline)
{
    if (task == NULL) {
        return AH_EINVAL;
    }
    if (task->_state == AH_TASK_STATE_SCHEDULED) {
        return AH_ESTATE;
    }

    ah_err_t err = ah_i_task_schedule_at(task, baseline);
    if (err != AH_ENONE) {
        return err;
    }

    task->_state = AH_TASK_STATE_SCHEDULED;

    return AH_ENONE;
}

ah_extern void ah_task_term(ah_task_t* task)
{
    ah_assert_if_debug(task != NULL);

    if (task->_state == AH_TASK_STATE_SCHEDULED) {
        ah_i_task_cancel_scheduled(task);
        task->_state = AH_TASK_STATE_CANCELED;
    }
#ifndef NDEBUG
    *task = (ah_task_t) { 0 };
#endif
}
