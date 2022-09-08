// SPDX-License-Identifier: EPL-2.0

#include "ah/task.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"

ah_extern ah_err_t ah_task_init(ah_task_t* task, ah_loop_t* loop, ah_task_cb cb)
{
    if (task == NULL || loop == NULL || cb == NULL) {
        return AH_EINVAL;
    }

    *task = (ah_task_t) {
        ._loop = loop,
        ._cb = cb,
        ._state = AH_I_TASK_STATE_INITIAL,
    };

    return AH_ENONE;
}

ah_extern void* ah_task_get_user_data(const ah_task_t* task)
{
    if (task == NULL) {
        return NULL;
    }
    return task->_user_data;
}

ah_extern ah_loop_t* ah_task_get_loop(const ah_task_t* task)
{
    if (task == NULL) {
        return NULL;
    }
    return task->_loop;
}

ah_extern void ah_task_set_user_data(ah_task_t* task, void* user_data)
{
    if (task != NULL) {
        task->_user_data = user_data;
    }
}

ah_extern bool ah_task_cancel(ah_task_t* task)
{
    if (task != NULL && task->_state == AH_I_TASK_STATE_SCHEDULED) {
        ah_i_task_cancel_scheduled(task);
        task->_state = AH_I_TASK_STATE_CANCELED;
        task->_cb(task, AH_ECANCELED);
        return true;
    }

    return false;
}

ah_extern ah_err_t ah_task_schedule_at(ah_task_t* task, ah_time_t baseline)
{
    if (task == NULL) {
        return AH_EINVAL;
    }
    if (task->_state == AH_I_TASK_STATE_SCHEDULED) {
        return AH_ESTATE;
    }

    ah_err_t err = ah_i_task_schedule_at(task, baseline);
    if (err != AH_ENONE) {
        return err;
    }

    task->_state = AH_I_TASK_STATE_SCHEDULED;

    return AH_ENONE;
}

ah_extern void ah_task_term(ah_task_t* task)
{
    if (task == NULL) {
        return;
    }

    if (task->_state == AH_I_TASK_STATE_SCHEDULED) {
        ah_i_task_cancel_scheduled(task);
        task->_state = AH_I_TASK_STATE_CANCELED;
    }

#ifndef NDEBUG
    *task = (ah_task_t) { 0 };
#endif
}
