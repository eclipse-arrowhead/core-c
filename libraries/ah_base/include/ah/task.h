// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_TASK_H_
#define AH_TASK_H_

/// \brief Task scheduling.
/// \file
///
/// A \e task, is a pointer to a function that is to be executed after a certain
/// \e baseline, which is a future point in time. This file provides the
/// utilities require to formulate and schedule such tasks.

#include "internal/_task.h"

#include <stddef.h>

/// \brief A pointer to a task function, or \e callback.
///
/// \param task Pointer to the ah_task containing this function pointer.
/// \param err  <ul>
///   <li><b>AH_ENONE</b>     - \a task was executed after its \c baseline.
///   <li><b>AH_ECANCELED</b> - \a task is being cancelled due to its event loop
///                             shutting down.
/// </ul>
typedef void (*ah_task_cb)(ah_task_t* task, ah_err_t err);

struct ah_task {
    AH_I_TASK_FIELDS
};

ah_extern ah_err_t ah_task_init(ah_task_t* task, ah_loop_t* loop, ah_task_cb cb);
ah_extern void* ah_task_get_user_data(const ah_task_t* task);
ah_extern ah_loop_t* ah_task_get_loop(const ah_task_t* task);
ah_extern void ah_task_set_user_data(ah_task_t* task, void* user_data);
ah_extern void ah_task_cancel(ah_task_t* task);

// Error codes:
// * AH_EDOM    - [Darwin] `baseline` is too far into the future to be representable by the underlying event queue.
// * AH_EINVAL  - `task` is NULL.
// * AH_ENOBUFS - [Darwin, Linux] `task` event loop has no more slots available in its event queue and could not flush it to make more slots available.
// * AH_ENOMEM  - [Darwin, Linux, Win32] `task` event loop failed to allocate heap memory via its configured allocator callback.
// * AH_ESTATE  - `task` is already scheduled and has not yet been cancelled or executed.
ah_extern ah_err_t ah_task_schedule_at(ah_task_t* task, struct ah_time baseline);

ah_extern void ah_task_term(ah_task_t* task);

#endif
