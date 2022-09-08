// SPDX-License-Identifier: EPL-2.0

#include "ah/err.h"
#include "ah/loop.h"
#include "ah/task.h"

#include <ah/unit.h>

struct s_task_data {
    size_t* call_counter;
    size_t call_count;
    ah_err_t call_err;

    ah_unit_res_t* res;
};

static void s_should_execute_task_with_no_err(ah_unit_res_t* res);
static void s_should_execute_cancelled_task_with_correct_err(ah_unit_res_t* res);

void test_task(ah_unit_res_t* res)
{
    s_should_execute_task_with_no_err(res);
    s_should_execute_cancelled_task_with_correct_err(res);
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

static void s_should_execute_task_with_no_err(ah_unit_res_t* res)
{
    ah_err_t err;

    struct ah_loop loop;
    err = ah_loop_init(&loop, 4u);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    size_t call_counter = 0u;

    struct ah_task task;
    struct s_task_data task_data = {
        .call_counter = &call_counter,
        .res = res,
    };
    ah_task_init(&task, &loop, s_on_execution);
    ah_task_set_user_data(&task, &task_data);

    err = ah_task_schedule_at(&task, (ah_time_t) { 0u });
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    ah_time_t deadline;
    err = ah_time_add(ah_time_now(), 100 * AH_TIMEDIFF_MS, &deadline);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }
    err = ah_loop_run_until(&loop, &deadline);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, call_counter, 1u);
    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, task_data.call_err, AH_ENONE);

    err = ah_loop_term(&loop);
    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
}

static void s_should_execute_cancelled_task_with_correct_err(ah_unit_res_t* res)
{
    ah_err_t err;

    struct ah_loop loop;
    err = ah_loop_init(&loop, 4u);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    size_t call_counter = 0u;

    struct ah_task task;
    struct s_task_data task_data = {
        .call_counter = &call_counter,
        .res = res,
    };
    ah_task_init(&task, &loop, s_on_execution);
    ah_task_set_user_data(&task, &task_data);

    err = ah_task_schedule_at(&task, (ah_time_t) { 0u });
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    ah_task_cancel(&task);

    err = ah_loop_run_until(&loop, &(ah_time_t) { 0u });
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, call_counter, 1u);
    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, task_data.call_err, AH_ECANCELED);

    err = ah_loop_term(&loop);
    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
}
