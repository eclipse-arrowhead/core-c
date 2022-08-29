// SPDX-License-Identifier: EPL-2.0

#ifndef AH_TASK_H_
#define AH_TASK_H_

/**
 * @file
 * Task scheduling.
 *
 * In this file, a data structure and a set of functions are provided for
 * formulating and scheduling @e tasks, which are functions to be executed
 * after certain @e baselines, which are specific points in time. No guarantees
 * are given about how close to its baseline any given task will execute, only
 * that it will execute at or after that baseline, as reported by the platform
 * clock (see ah_time_now()). Additionally, the event loop used to schedule any
 * task in question must be executing at or after the baseline until the task
 * is executed.
 */

#include "internal/_task.h"

#include <stdbool.h>
#include <stddef.h>

/**
 * A pointer to a task function, or @e callback.
 *
 * @param task Pointer to the ah_task containing this function pointer.
 * @param err  <ul>
 *   <li>@ref AH_ENONE     - @a task was executed after its @c baseline.
 *   <li>@ref AH_ECANCELED - @a task is being cancelled due to its event loop shutting down or
 *                           ah_task_cancel() being called with @a task as argument.
 * </ul>
 */
typedef void (*ah_task_cb)(ah_task_t* task, ah_err_t err);

/**
 * Task that can be scheduled for execution in the future.
 *
 * @note All fields of this data structure are @e private in the sense that a
 *       user of this API should not access them directly.
 */
struct ah_task {
    AH_I_TASK_FIELDS
};

/**
 * Initializes @a task with given @a loop and task callback @a cb.
 *
 * @param task Pointer to task.
 * @param loop Pointer to event loop.
 * @param cb   Task function pointer.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE  - Initialization of @a task was successful.
 *   <li>@ref AH_EINVAL - @a task, @a loop or @a cb is @c NULL.
 * </ul>
 *
 * @note If you want to associate arbitrary user data with an initialized task,
 *       you may call ah_task_set_user_data() with the same @a task after this
 *       function has returned successfully.
 * @warning No other functions operating on @a task are safe to call until
 *          after this function has returned successfully.
 */
ah_extern ah_err_t ah_task_init(ah_task_t* task, ah_loop_t* loop, ah_task_cb cb);

/**
 * Gets user data pointer associated with @a task.
 *
 * @param task Pointer to task.
 * @return Any user data pointer previously set via ah_task_set_user_data(), or
 *         @c NULL if no such has been set or if @a task is @c NULL.
 */
ah_extern void* ah_task_get_user_data(const ah_task_t* task);

/**
 * Gets pointer to event loop associated with @a task.
 *
 * @param task Pointer to task.
 * @return Pointer to @a task event loop, or @c NULL if @a task is @c NULL.
 */
ah_extern ah_loop_t* ah_task_get_loop(const ah_task_t* task);

/**
 * Sets user data pointer of @a task.
 *
 * @param task Pointer to task.
 * @param user_data User data pointer.
 *
 * @note If @a task is @c NULL, this function does nothing.
 */
ah_extern void ah_task_set_user_data(ah_task_t* task, void* user_data);

/**
 * Cancels @a task, if currently scheduled for execution.
 *
 * @param task Pointer to task.
 * @return @c true only if @a task was scheduled for execution and has now been
 *         cancelled. @c false otherwise.
 *
 * @note Cancelling a task causes its task callback to be invoked with an
 *       argument of @ref AH_ECANCELED.
 */
ah_extern bool ah_task_cancel(ah_task_t* task);

/**
 * Schedules @a task for execution at or after @a baseline.
 *
 * @param task     Pointer to task.
 * @param baseline Target baseline.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE                         - @a task scheduled.
 *   <li>@ref AH_EDOM [Darwin]                 - @a baseline is too far into the future to be
 *                                               acceptable to the platform event queue.
 *   <li>@ref AH_EINVAL                        - @a task is @c NULL.
 *   <li>@ref AH_ENOBUFS [Darwin, Linux]       - @a task event loop has no more slots available
 *                                               in its event queue and could not flush it to make
 *                                               more slots available.
 *   <li>@ref AH_ENOMEM [Darwin, Linux, Win32] - @a task event loop failed to allocate heap memory.
 *   <li>@ref AH_ESTATE                        - @a task is already scheduled and has not yet been
 *                                               cancelled or executed.
 * </ul>
 */
ah_extern ah_err_t ah_task_schedule_at(ah_task_t* task, ah_time_t baseline);

/**
 * Terminates @a task, releasing any resources associated with it.
 *
 * @param task Pointer to task.
 *
 * @note In contrast to ah_task_cancel(), calling this function will @e not
 *       trigger the callback of @a task.
 */
ah_extern void ah_task_term(ah_task_t* task);

#endif
