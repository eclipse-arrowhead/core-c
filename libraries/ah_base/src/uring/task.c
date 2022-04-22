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

static void s_on_execution(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe);

ah_extern void ah_i_task_cancel_scheduled(ah_task_t* task)
{
    ah_assert_if_debug(task != NULL);
    ah_assert_if_debug(task->_state == AH_TASK_STATE_SCHEDULED);

    struct io_uring_sqe* sqe;

    ah_err_t err = ah_i_loop_alloc_sqe(task->_loop, &sqe);
    if (ah_unlikely(err != AH_ENONE)) {
        ah_assert_if_debug(task->_evt != NULL);
        task->_evt->_cb = NULL;
        return;
    }

    if (ah_unlikely(task->_state == AH_TASK_STATE_CANCELED)) {
        return;
    }

    io_uring_prep_timeout_remove(sqe, (uint64_t) task->_evt, 0u);
    io_uring_sqe_set_data(sqe, NULL);
}

ah_extern ah_err_t ah_i_task_schedule_at(ah_task_t* task, struct ah_time baseline)
{
    ah_i_loop_evt_t* evt;
    struct io_uring_sqe* sqe;

    ah_err_t err = ah_i_loop_evt_alloc_with_sqe(task->_loop, &evt, &sqe);
    if (err != AH_ENONE) {
        return err;
    }

    evt->_cb = s_on_execution;
    evt->_body._as_task_schedule_at._task = task;

    evt->_body._as_task_schedule_at._baseline = baseline;

    io_uring_prep_timeout(sqe, &evt->_body._as_task_schedule_at._baseline._timespec, 0u, IORING_TIMEOUT_ABS);
    io_uring_sqe_set_data(sqe, evt);

    task->_evt = evt;

    return AH_ENONE;
}

static void s_on_execution(ah_i_loop_evt_t* evt, struct io_uring_cqe* cqe)
{
    ah_assert_if_debug(evt != NULL);
    ah_assert_if_debug(cqe != NULL);

    ah_task_t* task = evt->_body._as_task_schedule_at._task;
    ah_assert_if_debug(task != NULL);

    if (task->_state == AH_TASK_STATE_CANCELED) {
        return;
    }

    ah_err_t err = (cqe->res != 0 && cqe->res != -ETIME) ? -cqe->res : AH_ENONE;

    task->_state = AH_TASK_STATE_EXECUTED;
    task->_cb(task, err);
}
