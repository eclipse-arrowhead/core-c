// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_URING_LOOP_H_
#define AH_INTERNAL_URING_LOOP_H_

#include "../../defs.h"

#include <liburing.h>

#define AH_I_LOOP_PLATFORM_FIELDS struct io_uring _uring;

#define AH_I_LOOP_EVT_BODY_HAS_TASK_SCHEDULE_AT 1
#define AH_I_LOOP_EVT_BODY_HAS_TCP_CLOSE        1
#define AH_I_LOOP_EVT_BODY_HAS_TCP_CONNECT      1
#define AH_I_LOOP_EVT_BODY_HAS_TCP_LISTEN       1
#define AH_I_LOOP_EVT_BODY_HAS_TCP_OPEN         0
#define AH_I_LOOP_EVT_BODY_HAS_TCP_READ         1
#define AH_I_LOOP_EVT_BODY_HAS_TCP_WRITE        1
#define AH_I_LOOP_EVT_BODY_HAS_UDP_CLOSE        1
#define AH_I_LOOP_EVT_BODY_HAS_UDP_OPEN         0
#define AH_I_LOOP_EVT_BODY_HAS_UDP_RECV         1
#define AH_I_LOOP_EVT_BODY_HAS_UDP_SEND         1

#define AH_I_LOOP_EVT_BODY_TASK_SCHEDULE_AT_PLATFORM_FIELDS struct ah_time _baseline;
#define AH_I_LOOP_EVT_PLATFORM_FIELDS

typedef struct io_uring_cqe ah_i_loop_res_t;

ah_err_t ah_i_loop_alloc_evt_and_sqe(ah_loop_t* loop, ah_i_loop_evt_t** evt, struct io_uring_sqe** sqe);
ah_err_t ah_i_loop_alloc_sqe(ah_loop_t* loop, struct io_uring_sqe** sqe);

#endif
