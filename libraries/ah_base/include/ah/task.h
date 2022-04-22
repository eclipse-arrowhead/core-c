// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_TASK_H_
#define AH_TASK_H_

#include "assert.h"
#include "internal/task.h"

#include <stddef.h>

#define AH_TASK_STATE_INITIAL   0u
#define AH_TASK_STATE_SCHEDULED 1u
#define AH_TASK_STATE_EXECUTED  2u
#define AH_TASK_STATE_CANCELED  3u

typedef unsigned ah_task_state_t;

typedef void (*ah_task_cb)(ah_task_t* task, ah_err_t err);

struct ah_task {
    AH_I_TASK_FIELDS
};

// All arguments must be non-NULL.
ah_extern void ah_task_init(ah_task_t* task, ah_loop_t* loop, ah_task_cb cb);

ah_extern_inline void* ah_task_get_user_data(const ah_task_t* task)
{
    ah_assert_if_debug(task != NULL);
    return task->_user_data;
}

ah_extern_inline ah_loop_t* ah_task_get_loop(const ah_task_t* task)
{
    ah_assert_if_debug(task != NULL);
    return task->_loop;
}

ah_extern_inline ah_task_state_t ah_task_get_state(const ah_task_t* task)
{
    ah_assert_if_debug(task != NULL);
    return task->_state;
}

ah_extern_inline void ah_task_set_user_data(ah_task_t* task, void* user_data)
{
    ah_assert_if_debug(task != NULL);
    task->_user_data = user_data;
}

ah_extern void ah_task_cancel(ah_task_t* task);

// Error codes:
// * AH_EDOM    - [Darwin] `baseline` is too for into the future to be representable by the underlying event queue.
// * AH_EINVAL  - `task` is NULL.
// * AH_ENOBUFS - [Darwin, Linux] `task` event loop has no more slots available in its event queue and could not flush it to make more slots available.
// * AH_ENOMEM  - [Darwin, Linux, Win32] `task` event loop failed to allocate heap memory via its configured allocator callback.
// * AH_ESTATE  - `task` is already scheduled and has not yet been cancelled or executed.
ah_extern ah_err_t ah_task_schedule_at(ah_task_t* task, struct ah_time baseline);

ah_extern void ah_task_term(ah_task_t* task);

#endif
