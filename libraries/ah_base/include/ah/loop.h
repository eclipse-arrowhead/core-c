// SPDX-License-Identifier: EPL-2.0

#ifndef AH_LOOP_H_
#define AH_LOOP_H_

/**
 * @file
 * Event scheduling.
 *
 * This file exposes the <em>event loop</em>, which is a data structure used to
 * subscribe to and schedule platform events. Examples of events can be a
 * received network message, a file finished being copied, or a certain task
 * having been executed until completion.
 *
 * While the API provided here only allows for operations directly on event
 * loops, other features of this library make use of event loops internally in
 * order to handle event scheduling, such as those in task.h, tcp.h and udp.h.
 *
 * The event loop data structure is typically implemented on top of an API that
 * is provided by the platform for which this library is compiled. The
 * following table show what platform APIs are used on the respective platforms
 * supported by this library:
 *
 * <table>
 *   <caption id="event-loop-implementations">Event loop implementations</caption>
 *   <tr>
 *     <th>Platform
 *     <th>API
 *   <tr>
 *     <td>Darwin
 *     <td><a href="https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/FSEvents_ProgGuide/KernelQueues/KernelQueues.html">Kernel Queues (KQueue)</a>
 *   <tr>
 *     <td>Linux
 *     <td><a href="https://unixism.net/loti/what_is_io_uring.html">io_uring</a>
 *   <tr>
 *     <td>Win32
 *     <td><a href="https://docs.microsoft.com/en-us/windows/win32/fileio/i-o-completion-ports">I/O Completion Ports (IOCP)</a>
 * </table>
 *
 * \warning Event loops are \e not thread safe, and, as a consequence, neither
 *          are any functions that depend on event loops throughout this
 *          library.
 */

#include "internal/_loop.h"

/**
 * Event loop.
 *
 * @note All fields of this data structure are @e private in the sense that a
 *       user of this API should not access them directly.
 */
struct ah_loop {
    AH_I_LOOP_FIELDS
};

/**
 * Initializes @a loop with a certain event @a capacity.
 *
 * The exact implications of the @a capacity argument varies with the targeted
 * platform. As a consequence, what value yields optimal performance will vary
 * with the targeted platform. A value of zero, which indicates that a platform
 * default capacity is desired, should be sufficient for most use cases.
 *
 * The platform default capacities can be configured as described in conf.h.
 *
 * @param loop     Pointer to event loop.
 * @param capacity Desired event capacity, or @c 0 if a default capacity is to
 *                 be used.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE                  - @a loop was successfully initialized.
 *   <li>@ref AH_EINVAL                 - @a loop is @c NULL.
 *   <li>@ref AH_EMFILE [Darwin, Linux] - Per-process file descriptor table is full.
 *   <li>@ref AH_ENFILE [Darwin, Linux] - Platform file table is full.
 *   <li>@ref AH_ENOMEM [Darwin, Linux] - Failed to allocate kernel memory for event queue.
 *   <li>@ref AH_EOVERFLOW [Linux]      - More than 32-bits of heap memory was requested on a 32-bit system.
 *   <li>@ref AH_EPERM [Linux]          - Permission denied to set up required kernel resource.
 *   <li>@ref AH_EPROCLIM_W [Win32]     - Windows task limit reached.
 *   <li>@ref AH_ESYSNOTREADY [Win32]   - Network subsystem not ready.
 * </ul>
 *
 * @warning No other functions operating on @a loop are safe to call until
 *          after this function has returned successfully, unless something
 *          else is stated in their respective documentations.
 */
ah_extern ah_err_t ah_loop_init(ah_loop_t* loop, size_t capacity);

/**
 * Checks if @a loop is currently running.
 *
 * A loop is running if and only if (1) ah_loop_run() is currently being
 * invoked with a pointer to that loop as argument, and (2) no call has been
 * made to ah_loop_stop() or ah_loop_term() with that loop since ah_loop_run()
 * was first invoked.
 *
 * @param loop Pointer to event loop.
 * @return @c true only if @a loop is currently running. @c false otherwise.
 *
 * @note The function returns @c false if @a loop is @c NULL.
 */
ah_extern bool ah_loop_is_running(const ah_loop_t* loop);

/**
 * Checks if @a loop is currently being or has been terminated.
 *
 * A loop is being or has been terminated if ah_loop_term() has been invoked
 * with a pointer to it.
 *
 * @param loop Pointer to event loop.
 * @return @c true only if @a loop is currently being or has been terminated.
 *         @c false otherwise.
 *
 * @note The function returns @c true if @a loop is @c NULL.
 *
 * @warning This function is only safe to use if (1) the memory of @a loop is
 *         zeroed, (2) @a loop has been initialized using ah_loop_init() and is
 *         currently in a non-terminated state, or (3) @a loop has been
 *         terminated using ah_loop_term().
 */
ah_extern bool ah_loop_is_term(const ah_loop_t* loop);

/**
 * Gets current time, as keep track of by @a loop.
 *
 * This function exists solely as a way of getting a relatively accurate
 * estimate of the current time without having to use ah_time_now(), which uses
 * a relatively costly system call on some platforms.
 *
 * @param loop Pointer to event loop.
 * @return Time at which @a loop last updated its internal clock.
 *
 * @note The function returns <code>(ah_time_t) { 0u }</code> if @a loop is
 *       @c NULL.
 */
ah_extern ah_time_t ah_loop_now(const ah_loop_t* loop);

/**
 * Runs event @a loop, making it await and handle event completions.
 *
 * If the @a loop has been given no events to await prior to this function
 * being called, it will block indefinitely. As event loops are not thread safe
 * by design, this leaves no safe way of ever stopping the loop other than by
 * terminating or interrupting the application from another thread or process.
 *
 * The operation blocks until ah_loop_stop() or ah_loop_term() is called with
 * @a loop as argument, after which the call eventually returns.
 *
 * Calling this function is equivalent to invoking ah_loop_run_until() with a
 * @c NULL time.
 *
 * @param loop Pointer to event loop.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE                  - @a loop ran until stopped or terminated.
 *   <li>@ref AH_EINVAL                 - @a loop is @c NULL.
 *   <li>@ref AH_ESTATE                 - @a loop is already running or has been terminated.
 *   <li>@ref AH_EACCES [Darwin]        - Process lacks permission to register KQueue filter.
 *   <li>@ref AH_EINTR [Darwin, Linux]  - The process was interrupted by a signal.
 *   <li>@ref AH_ENOMEM [Darwin, Linux] - Failed to submit pending events due to no memory being
 *                                        available to the kernel.
 * </ul>
 */
ah_extern ah_err_t ah_loop_run(ah_loop_t* loop);

/**
 * Runs event @a loop at least until @a time, making it await and handle
 * event completions for that duration.
 *
 * If @a time is @c NULL, the function will block indefinitely. If no events
 * were registered prior to such a call, no opportunity will be given to call
 * ah_loop_stop() or ah_loop_term() from the blocked thread. As event loops
 * are not thread safe by design, this leaves no safe way of ever stopping the
 * loop other than by terminating or interrupting the application from another
 * thread or process.
 *
 * The operation blocks until some time after (1) ah_loop_stop() or
 * ah_loop_term() is called with @a loop as argument, or (2) @a time is passed.
 *
 * @param loop Pointer to event loop.
 * @param time Point after which @a loop execution is to stop.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE                  - @a loop ran until @a time expired, it was stopped or it
 *                                        was terminated.
 *   <li>@ref AH_EDOM                   - @a time is too far into the future for it to be
 *                                        representable by the kernel event queue system.
 *   <li>@ref AH_EINVAL                 - @a loop is @c NULL.
 *   <li>@ref AH_ESTATE                 - @a loop is already running or has been terminated.
 *   <li>@ref AH_EACCES [Darwin]        - Process lacks permission to register KQueue filter.
 *   <li>@ref AH_EINTR [Darwin, Linux]  - The process was interrupted by a signal.
 *   <li>@ref AH_ENOMEM [Darwin, Linux] - Failed to submit pending events due to no memory being
 *                                        available to the kernel.
 * </ul>
 */
ah_extern ah_err_t ah_loop_run_until(ah_loop_t* loop, ah_time_t* time);

/**
 * Stops @a loop, preventing it from processing any further events.
 *
 * @param loop Pointer to event loop.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE  - @a loop was stopped.
 *   <li>@ref AH_EINVAL - @a loop is @c NULL.
 *   <li>@ref AH_ESTATE - @a loop is not running.
 * </ul>
 */
ah_extern ah_err_t ah_loop_stop(ah_loop_t* loop);

/**
 * Terminates @a loop, cancelling all of its pending events and releases
 *        all of its resources.
 *
 * All pending events of @a loop will be invoked with @ref AH_ECANCELED before
 * termination completes.
 *
 * If this function is called from an event handler while ah_loop_run() or
 * ah_loop_run_until() is executing on the same @a loop, termination is
 * scheduled before either of the mentioned functions return. If @a loop is not
 * currently running, the termination procedure is executed before this
 * function returns.
 *
 * @param loop Pointer to event loop.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE  - @a loop was terminated or is scheduled for termination.
 *   <li>@ref AH_EINVAL - @a loop is @c NULL.
 *   <li>@ref AH_ESTATE - @a loop is already terminating or terminated.
 * </ul>
 */
ah_extern ah_err_t ah_loop_term(ah_loop_t* loop);

#endif
