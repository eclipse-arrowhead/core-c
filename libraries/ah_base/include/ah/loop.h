// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_LOOP_H_
#define AH_LOOP_H_

#include "internal/loop.h"

struct ah_loop {
    AH_I_LOOP_FIELDS
};

struct ah_loop_opts {
    ah_alloc_cb alloc_cb;
    size_t capacity;
};

ah_extern ah_err_t ah_loop_init(ah_loop_t* loop, ah_loop_opts_t* opts);
ah_extern bool ah_loop_is_running(const ah_loop_t* loop);
ah_extern bool ah_loop_is_term(const ah_loop_t* loop);
ah_extern ah_time_t ah_loop_now(const ah_loop_t* loop);
ah_extern ah_err_t ah_loop_run(ah_loop_t* loop);
ah_extern ah_err_t ah_loop_run_until(ah_loop_t* loop, ah_time_t* time);
ah_extern ah_err_t ah_loop_stop(ah_loop_t* loop);
ah_extern ah_err_t ah_loop_term(ah_loop_t* loop);

#endif
