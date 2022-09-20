// SPDX-License-Identifier: EPL-2.0

#include "ah/task.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"
#include "ah/time.h"

void ah_i_task_cancel_scheduled(ah_task_t* task)
{
    ah_assert_if_debug(task != NULL);
    ah_assert_if_debug(task->_state == AH_I_TASK_STATE_SCHEDULED);

    if (ah_i_loop_try_cancel_task(task->_loop, task)) {
        task->_state = AH_I_TASK_STATE_CANCELED;
    }
}

ah_err_t ah_i_task_schedule_at(ah_task_t* task, ah_time_t baseline)
{
    ah_assert_if_debug(task != NULL);

    return ah_i_loop_schedule_task(task->_loop, baseline, task);
}

void ah_i_task_execute_scheduled(ah_task_t* task)
{
    ah_assert_if_debug(task != NULL);
    ah_assert_if_debug(task->_state == AH_I_TASK_STATE_SCHEDULED);

    task->_cb(task, AH_ENONE);
    task->_state = AH_I_TASK_STATE_EXECUTED;
}
