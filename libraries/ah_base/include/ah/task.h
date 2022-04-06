// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_TASK_H_
#define AH_TASK_H_

#include "defs.h"
#include "err.h"

#define AH_TASK_STATE_INITIAL   0
#define AH_TASK_STATE_SCHEDULED 1
#define AH_TASK_STATE_EXECUTED  2
#define AH_TASK_STATE_CANCELED  3

typedef unsigned ah_task_state_t;

typedef void (*ah_task_cb)(struct ah_task* task, ah_err_t err);

struct ah_task {
    // INTERNAL START

    ah_task_state_t _state;
    ah_task_cb _cb;
    struct ah_loop* _loop;
    struct ah_i_loop_evt* _evt;
    void* _data;

    // INTERNAL STOP
};

struct ah_task_opts {
    struct ah_loop* loop;
    ah_task_cb cb;
    void* data;
};

ah_extern ah_err_t ah_task_init(struct ah_task* task, const struct ah_task_opts* opts);
ah_extern ah_err_t ah_task_term(struct ah_task* task);

ah_extern void* ah_task_get_data(const struct ah_task* task);
ah_extern struct ah_loop* ah_task_get_loop(const struct ah_task* task);
ah_extern ah_task_state_t ah_task_get_state(const struct ah_task* task);

ah_extern void ah_task_set_data(struct ah_task* task, void* data);

ah_extern ah_err_t ah_task_cancel(struct ah_task* task);
ah_extern ah_err_t ah_task_schedule_at(struct ah_task* task, struct ah_time baseline);

#endif
