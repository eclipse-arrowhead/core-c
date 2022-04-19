// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_TASK_H_
#define AH_INTERNAL_TASK_H_

#include "../defs.h"

#if AH_USE_IOCP
#    include "iocp/task.h"
#elif AH_USE_KQUEUE
#    include "kqueue/task.h"
#elif AH_USE_URING
#    include "uring/task.h"
#endif

#define AH_I_TASK_FIELDS                                                                                               \
    ah_task_state_t _state;                                                                                            \
    ah_task_cb _cb;                                                                                                    \
    ah_loop_t* _loop;                                                                                                  \
    void* _data;                                                                                                       \
    AH_I_TASK_PLATFORM_FIELDS

ah_extern void ah_i_task_cancel_scheduled(ah_task_t* task);
ah_extern ah_err_t ah_i_task_schedule_at(ah_task_t* task, struct ah_time baseline);

#endif
