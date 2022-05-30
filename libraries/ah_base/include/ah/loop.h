// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_LOOP_H_
#define AH_LOOP_H_

#include "internal/_loop.h"

struct ah_loop {
    AH_I_LOOP_FIELDS
};

struct ah_loop_opts {
    size_t capacity;
};

// Error codes:
// * AH_EINVAL       - `loop` or `opts` is NULL.
// * AH_EMFILE       - [Darwin, Linux] Per-process file descriptor table is full.
// * AH_ENFILE       - [Darwin, Linux] Platform file table is full.
// * AH_ENOMEM       - [Darwin, Linux] Failed to allocate kernel memory for event queue.
// * AH_ENOMEM       - `opts->alloc_cb` failed to allocate required memory.
// * AH_EOVERFLOW    - [Linux] More than 32-bits of heap memory was requested on a 32-bit system.
// * AH_EPERM        - [Linux] Permission denied to set up required kernel resource.
// * AH_EPROCLIM     - [Win32] Windows task limit reached.
// * AH_ESYSNOTREADY - [Win32] Network subsystem not ready.
ah_extern ah_err_t ah_loop_init(ah_loop_t* loop, ah_loop_opts_t* opts);

ah_extern bool ah_loop_is_running(const ah_loop_t* loop);
ah_extern bool ah_loop_is_term(const ah_loop_t* loop);
ah_extern ah_time_t ah_loop_now(const ah_loop_t* loop);

// Error codes:
// * AH_EINVAL - `loop` is NULL.
// * AH_ESTATE - `loop` is already running or has been terminated.
// * AH_EACCES - [Darwin] Process lacks permission to register KQueue filter.
// * AH_EINTR  - [Darwin, Linux] The process was interrupted by a signal.
// * AH_ENOMEM - [Darwin, Linux] Failed to submit pending events due to no memory being available to the kernel.
ah_extern ah_err_t ah_loop_run(ah_loop_t* loop);

// Error codes:
// * AH_EDOM   - `time` is too far into the future for it to be representable by the kernel event queue system.
// * AH_EINVAL - `loop` is NULL.
// * AH_ESTATE - `loop` is already running or has been terminated.
// * AH_EACCES - [Darwin] Process lacks permission to register KQueue filter.
// * AH_EINTR  - [Darwin, Linux] The process was interrupted by a signal.
// * AH_ENOMEM - [Darwin, Linux] Failed to submit pending events due to no memory being available to the kernel.
ah_extern ah_err_t ah_loop_run_until(ah_loop_t* loop, ah_time_t* time);

// Error codes:
// * AH_EINVAL - `loop` is NULL.
// * AH_ESTATE - `loop` is not running.
ah_extern ah_err_t ah_loop_stop(ah_loop_t* loop);

// Error codes:
// * AH_EINVAL - `loop` is NULL.
// * AH_ESTATE - `loop` is already terminated.
ah_extern ah_err_t ah_loop_term(ah_loop_t* loop);

#endif
