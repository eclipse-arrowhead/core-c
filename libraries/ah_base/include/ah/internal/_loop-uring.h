// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_LOOP_URING_H_
#define AH_INTERNAL_LOOP_URING_H_

#include "../defs.h"

#include <liburing.h>

#define AH_I_LOOP_PLATFORM_FIELDS \
 struct io_uring _uring;

#define AH_I_LOOP_EVT_PLATFORM_FIELDS \
 void (*_cb)(ah_i_loop_evt_t*, struct io_uring_cqe*);

struct ah_i_loop_evt;

// All error codes returned by this function are safe to ignore.
//
// Error codes:
// * AH_ECANCELED  - `loop` is shutting down or is already shut down.
// * AH_ENOMEM  - `loop` allocator failed to allocate memory for additional ah_i_loop_evt_t values.
// * AH_ENOBUFS - `loop` out of io_uring SQEs and could not make more available.
ah_err_t ah_i_loop_evt_alloc_with_sqe(ah_loop_t* loop, struct ah_i_loop_evt** evt, struct io_uring_sqe** sqe);

// All error codes returned by this function are safe to ignore.
//
// Error codes:
// * AH_ENOBUFS - `loop` out of io_uring SQEs and could not make more available.
ah_err_t ah_i_loop_alloc_sqe(ah_loop_t* loop, struct io_uring_sqe** sqe);

#endif
