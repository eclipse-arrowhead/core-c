// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_TIME_H_
#define AH_TIME_H_

#include "defs.h"
#include "err.h"

#include <stdbool.h>
#include <stdint.h>

#if AH_USE_URING
#    include <linux/time_types.h>
#endif

#define AH_TIMEDIFF_C(V) INT64_C(V)

#define AH_TIMEDIFF_NS AH_TIMEDIFF_C(1)              ///< \brief Nanosecond multiplier.
#define AH_TIMEDIFF_US AH_TIMEDIFF_C(1000)           ///< \brief Microsecond multiplier.
#define AH_TIMEDIFF_MS AH_TIMEDIFF_C(1000000)        ///< \brief Millisecond multiplier.
#define AH_TIMEDIFF_S  AH_TIMEDIFF_C(1000000000)     ///< \brief Second multiplier.
#define AH_TIMEDIFF_M  AH_TIMEDIFF_C(60000000000)    ///< \brief Minute multiplier.
#define AH_TIMEDIFF_H  AH_TIMEDIFF_C(3600000000000)  ///< \brief Hour multiplier.
#define AH_TIMEDIFF_D  AH_TIMEDIFF_C(86400000000000) ///< \brief 24-hour day multiplier.

#define AH_TIMEDIFF_MIN INT64_MIN
#define AH_TIMEDIFF_MAX INT64_MAX

struct ah_time {
    // INTERNAL START

#if AH_USE_KQUEUE && AH_IS_DARWIN
    uint64_t _mach_absolute_time;
#elif AH_USE_URING
    struct __kernel_timespec _timespec;
#endif

    // INTERNAL STOP
};

typedef int64_t ah_timediff_t; // Nanoseconds.

ah_extern struct ah_time ah_time_now();
ah_extern ah_err_t ah_time_diff(struct ah_time a, struct ah_time b, ah_timediff_t* diff);
ah_extern bool ah_time_eq(struct ah_time a, struct ah_time b);
ah_extern int ah_time_cmp(struct ah_time a, struct ah_time b);
ah_extern ah_err_t ah_time_add(struct ah_time time, ah_timediff_t diff, struct ah_time* result);
ah_extern ah_err_t ah_time_sub(struct ah_time time, ah_timediff_t diff, struct ah_time* result);
ah_extern bool ah_time_is_after(struct ah_time a, struct ah_time b);
ah_extern bool ah_time_is_before(struct ah_time a, struct ah_time b);
ah_extern bool ah_time_is_zero(struct ah_time time);

ah_extern ah_err_t ah_timediff_add(ah_timediff_t a, ah_timediff_t b, ah_timediff_t* result);
ah_extern ah_err_t ah_timediff_div(ah_timediff_t a, ah_timediff_t b, ah_timediff_t* result);
ah_extern ah_err_t ah_timediff_mul(ah_timediff_t a, ah_timediff_t b, ah_timediff_t* result);
ah_extern ah_err_t ah_timediff_sub(ah_timediff_t a, ah_timediff_t b, ah_timediff_t* result);

#endif
