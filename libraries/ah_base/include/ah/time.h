// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_TIME_H_
#define AH_TIME_H_

#include "internal/_time.h"
#include "math.h"

#include <stdbool.h>
#include <stdint.h>

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
    AH_I_TIME_FIELDS
};

typedef int64_t ah_timediff_t; // Nanoseconds.

ah_extern ah_time_t ah_time_now(void);

// Error codes:
// * AH_EINVAL - `diff` is NULL.
// * AH_ERANGE - Subtracting `b` from `a` produced an unrepresentable result.
ah_extern ah_err_t ah_time_diff(ah_time_t a, ah_time_t b, ah_timediff_t* diff);

ah_extern bool ah_time_eq(ah_time_t a, ah_time_t b);
ah_extern int ah_time_cmp(ah_time_t a, ah_time_t b);

// Error codes:
// * AH_EINVAL - `result` is NULL.
// * AH_ERANGE - Adding `diff` to `time` produced an unrepresentable result.
ah_extern ah_err_t ah_time_add(ah_time_t time, ah_timediff_t diff, ah_time_t* result);

// Error codes:
// * AH_EINVAL - `result` is NULL.
// * AH_ERANGE - Subtracting `diff` from `time` produced an unrepresentable result.
ah_extern ah_err_t ah_time_sub(ah_time_t time, ah_timediff_t diff, ah_time_t* result);

ah_extern bool ah_time_is_after(ah_time_t a, ah_time_t b);
ah_extern bool ah_time_is_before(ah_time_t a, ah_time_t b);
ah_extern bool ah_time_is_zero(ah_time_t time);

// Error codes:
// * AH_EINVAL - `result` is NULL.
// * AH_ERANGE - Adding `a` and `b` produced an unrepresentable result.
ah_inline ah_err_t ah_timediff_add(ah_timediff_t a, ah_timediff_t b, ah_timediff_t* result)
{
    return ah_add_int64(a, b, result);
}

// Error codes:
// * AH_EDOM   - `b` is 0.
// * AH_EINVAL - `result` is NULL.
// * AH_ERANGE - Dividing `a` with `b` produced an unrepresentable result.
ah_inline ah_err_t ah_timediff_div(ah_timediff_t a, ah_timediff_t b, ah_timediff_t* result)
{
    return ah_div_int64(a, b, result);
}

// Error codes:
// * AH_EINVAL - `result` is NULL.
// * AH_ERANGE - Multiplying `a` with `b` produced an unrepresentable result.
ah_inline ah_err_t ah_timediff_mul(ah_timediff_t a, ah_timediff_t b, ah_timediff_t* result)
{
    return ah_mul_int64(a, b, result);
}

// Error codes:
// * AH_EINVAL - `result` is NULL.
// * AH_ERANGE - Subtracting `a` and `b` produced an unrepresentable result.
ah_inline ah_err_t ah_timediff_sub(ah_timediff_t a, ah_timediff_t b, ah_timediff_t* result)
{
    return ah_sub_int64(a, b, result);
}

#endif
