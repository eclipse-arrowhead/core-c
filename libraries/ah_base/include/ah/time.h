// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_TIME_H_
#define AH_TIME_H_

#include "defs.h"

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
#if AH_USE_KQUEUE && AH_IS_DARWIN
    uint64_t _mach_absolute_time;
#elif AH_USE_URING
    struct __kernel_timespec _timespec;
#endif
};

typedef int64_t ah_timediff_t; // Nanoseconds.

ah_extern ah_time_t ah_time_now(void);
ah_extern ah_err_t ah_time_diff(ah_time_t a, ah_time_t b, ah_timediff_t* diff);
ah_extern bool ah_time_eq(ah_time_t a, ah_time_t b);
ah_extern int ah_time_cmp(ah_time_t a, ah_time_t b);
ah_extern ah_err_t ah_time_add(ah_time_t time, ah_timediff_t diff, ah_time_t* result);
ah_extern ah_err_t ah_time_sub(ah_time_t time, ah_timediff_t diff, ah_time_t* result);
ah_extern bool ah_time_is_after(ah_time_t a, ah_time_t b);
ah_extern bool ah_time_is_before(ah_time_t a, ah_time_t b);
ah_extern bool ah_time_is_zero(ah_time_t time);

ah_extern ah_err_t ah_timediff_add(ah_timediff_t a, ah_timediff_t b, ah_timediff_t* result);
ah_extern ah_err_t ah_timediff_div(ah_timediff_t a, ah_timediff_t b, ah_timediff_t* result);
ah_extern ah_err_t ah_timediff_mul(ah_timediff_t a, ah_timediff_t b, ah_timediff_t* result);
ah_extern ah_err_t ah_timediff_sub(ah_timediff_t a, ah_timediff_t b, ah_timediff_t* result);

#endif
