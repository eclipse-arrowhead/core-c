// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/task.h"

#include "ah/abort.h"
#include "ah/err.h"
#include "ah/time.h"

ah_extern void ah_i_task_cancel_scheduled(ah_task_t* task)
{
    (void) task;
    ah_abort();
}

ah_extern ah_err_t ah_i_task_schedule_at(ah_task_t* task, struct ah_time baseline)
{
    (void) task;
    (void) baseline;

    return AH_EOPNOTSUPP;
}
