// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/abort.h"
#include "ah/err.h"
#include "ah/intrin.h"
#include "ah/time.h"

#include <mach/mach_time.h>
#include <string.h>

static mach_timebase_info_data_t s_get_mach_timebase_info_data(void);

ah_extern ah_time_t ah_time_now()
{
    return (ah_time_t) { ._mach_absolute_time = mach_absolute_time() };
}

ah_extern ah_err_t ah_time_diff(const ah_time_t a, const ah_time_t b, ah_timediff_t* diff)
{
    if (diff == NULL) {
        return AH_EINVAL;
    }

    ah_timediff_t tmp_td;
    if (ah_p_sub_overflow(a._mach_absolute_time, b._mach_absolute_time, &tmp_td)) {
        return AH_ERANGE;
    }

    mach_timebase_info_data_t info = s_get_mach_timebase_info_data();

    if (ah_p_mul_overflow(tmp_td, info.numer, &tmp_td)) {
        return AH_ERANGE;
    }
    tmp_td /= info.denom;

    *diff = tmp_td;

    return AH_ENONE;
}

static mach_timebase_info_data_t s_get_mach_timebase_info_data(void)
{
    mach_timebase_info_data_t info;

    if (mach_timebase_info(&info) != 0) {
        ah_abortf("failed to get Mach time-base information; %s", strerror(errno));
    }

    return info;
}

ah_extern bool ah_time_eq(const ah_time_t a, const ah_time_t b)
{
    return a._mach_absolute_time == b._mach_absolute_time;
}

ah_extern int ah_time_cmp(const ah_time_t a, const ah_time_t b)
{
    if (a._mach_absolute_time < b._mach_absolute_time) {
        return -1;
    }
    else if (a._mach_absolute_time == b._mach_absolute_time) {
        return 0;
    }
    else {
        return 1;
    }
}

ah_extern ah_err_t ah_time_add(const ah_time_t time, const ah_timediff_t diff, ah_time_t* result)
{
    if (result == NULL) {
        return AH_EINVAL;
    }

    mach_timebase_info_data_t info = s_get_mach_timebase_info_data();

    uint64_t tmp = diff / info.numer;
    if (ah_p_mul_overflow(tmp, info.denom, &tmp)) {
        return AH_ERANGE;
    }
    if (ah_p_add_overflow(time._mach_absolute_time, tmp, &tmp)) {
        return AH_ERANGE;
    }

    *result = (ah_time_t) { ._mach_absolute_time = tmp };

    return AH_ENONE;
}

ah_extern ah_err_t ah_time_sub(const ah_time_t time, const ah_timediff_t diff, ah_time_t* result)
{
    if (result == NULL) {
        return AH_EINVAL;
    }

    mach_timebase_info_data_t info = s_get_mach_timebase_info_data();

    uint64_t tmp = diff / info.numer;
    if (ah_p_mul_overflow(tmp, info.denom, &tmp)) {
        return AH_ERANGE;
    }
    if (ah_p_sub_overflow(time._mach_absolute_time, tmp, &tmp)) {
        return AH_ERANGE;
    }

    *result = (ah_time_t) { ._mach_absolute_time = tmp };

    return AH_ENONE;
}

ah_extern bool ah_time_is_after(const ah_time_t a, const ah_time_t b)
{
    return a._mach_absolute_time > b._mach_absolute_time;
}

ah_extern bool ah_time_is_before(const ah_time_t a, const ah_time_t b)
{
    return a._mach_absolute_time < b._mach_absolute_time;
}

ah_extern bool ah_time_is_zero(const ah_time_t time)
{
    return time._mach_absolute_time == UINT64_C(0);
}
