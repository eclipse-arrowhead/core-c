// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/err.h"
#include "ah/loop.h"
#include "ah/task.h"
#include "ah/unit.h"

struct s_task_data {
    size_t* call_counter;
    size_t call_count;
    ah_err_t call_err;

    ah_unit_t* unit;
};

static void s_should_execute_task_with_no_err(ah_unit_t* unit);
static void s_should_execute_cancelled_task_with_correct_err(ah_unit_t* unit);

void test_task(ah_unit_t* unit)
{
    s_should_execute_task_with_no_err(unit);
    s_should_execute_cancelled_task_with_correct_err(unit);
}

static void s_on_execution(struct ah_task* task, ah_err_t err)
{
    if (task == NULL) {
        return;
    }

    struct s_task_data* task_data = ah_task_get_user_data(task);

    task_data->call_count += 1u;
    task_data->call_err = err;

    *task_data->call_counter += 1u;
}

static void s_should_execute_task_with_no_err(ah_unit_t* unit)
{
    ah_err_t err;

    struct ah_loop loop;
    err = ah_loop_init(&loop, &(struct ah_loop_opts) { .capacity = 4u });
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    size_t call_counter = 0u;

    struct ah_task task;
    struct s_task_data task_data = {
        .call_counter = &call_counter,
        .unit = unit,
    };
    ah_task_init(&task, &loop, s_on_execution);
    ah_task_set_user_data(&task, &task_data);

    err = ah_task_schedule_at(&task, (struct ah_time) { 0u });
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    err = ah_loop_run_until(&loop, &(struct ah_time) { 0u });
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    (void) ah_unit_assert_unsigned_eq(unit, call_counter, 1u);
    (void) ah_unit_assert_err_eq(unit, AH_ENONE, task_data.call_err);

    err = ah_loop_term(&loop);
    (void) ah_unit_assert_err_eq(unit, AH_ENONE, err);
}

static void s_should_execute_cancelled_task_with_correct_err(ah_unit_t* unit)
{
    ah_err_t err;

    struct ah_loop loop;
    err = ah_loop_init(&loop, &(struct ah_loop_opts) { .capacity = 4u });
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    size_t call_counter = 0u;

    struct ah_task task;
    struct s_task_data task_data = {
        .call_counter = &call_counter,
        .unit = unit,
    };
    ah_task_init(&task, &loop, s_on_execution);
    ah_task_set_user_data(&task, &task_data);

    err = ah_task_schedule_at(&task, (struct ah_time) { 0u });
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    ah_task_cancel(&task);

    err = ah_loop_run_until(&loop, &(struct ah_time) { 0u });
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    (void) ah_unit_assert_unsigned_eq(unit, call_counter, 1u);
    (void) ah_unit_assert_err_eq(unit, AH_ECANCELED, task_data.call_err);

    err = ah_loop_term(&loop);
    (void) ah_unit_assert_err_eq(unit, AH_ENONE, err);
}
