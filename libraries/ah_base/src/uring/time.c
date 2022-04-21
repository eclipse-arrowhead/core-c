// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/time.h"

#include "ah/abort.h"
#include "ah/assert.h"
#include "ah/err.h"

#include <string.h>
#include <time.h>

ah_extern ah_time_t ah_time_now()
{
    struct timespec timespec;
    if (clock_gettime(CLOCK_MONOTONIC, &timespec) != 0) {
        ah_abortf("failed to get monotonic system time; %s", strerror(errno));
    }

    ah_assert_if_debug(sizeof(__kernel_time64_t) >= sizeof(timespec.tv_sec));

    return (ah_time_t) {
        ._timespec.tv_sec = (__kernel_time64_t) timespec.tv_sec,
        ._timespec.tv_nsec = (long long) timespec.tv_nsec,
    };
}

ah_extern ah_err_t ah_time_diff(const ah_time_t a, const ah_time_t b, ah_timediff_t* diff)
{
    if (diff == NULL) {
        return AH_EINVAL;
    }

    struct __kernel_timespec tmp_ts;
    if (ah_p_sub_overflow(a._timespec.tv_sec, b._timespec.tv_sec, &tmp_ts.tv_sec)) {
        return AH_ERANGE;
    }

    tmp_ts.tv_nsec = a._timespec.tv_nsec - b._timespec.tv_nsec;
    if (tmp_ts.tv_nsec < 0) {
        if (ah_p_sub_overflow(tmp_ts.tv_sec, 1, &tmp_ts.tv_sec)) {
            return AH_ERANGE;
        }
        tmp_ts.tv_nsec += 1000000000;
    }

    ah_timediff_t tmp_td;
    if (ah_p_mul_overflow(tmp_ts.tv_sec, 1000000000, &tmp_td)) {
        return AH_ERANGE;
    }
    if (ah_p_add_overflow(tmp_ts.tv_nsec, tmp_td, &tmp_td)) {
        return AH_ERANGE;
    }

    *diff = tmp_td;

    return AH_ENONE;
}

ah_extern bool ah_time_eq(const ah_time_t a, const ah_time_t b)
{
    return a._timespec.tv_sec == b._timespec.tv_sec && a._timespec.tv_nsec == b._timespec.tv_nsec;
}

ah_extern int ah_time_cmp(const ah_time_t a, const ah_time_t b)
{
    if (a._timespec.tv_sec < b._timespec.tv_sec) {
        return -1;
    }
    else if (a._timespec.tv_sec == b._timespec.tv_sec) {
        if (a._timespec.tv_nsec < b._timespec.tv_nsec) {
            return -1;
        }
        else if (a._timespec.tv_nsec == b._timespec.tv_nsec) {
            return 0;
        }
        else {
            return 1;
        }
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

    struct __kernel_timespec tmp;
    if (ah_p_add_overflow(time._timespec.tv_sec, diff / 1000000000, &tmp.tv_sec)) {
        return AH_ERANGE;
    }
    tmp.tv_nsec = time._timespec.tv_nsec + (diff % 1000000000);
    if (tmp.tv_nsec < 0) {
        tmp.tv_nsec += 1000000000;
        if (ah_p_sub_overflow(tmp.tv_sec, 1, &tmp.tv_sec)) {
            return AH_ERANGE;
        }
    }
    else if (tmp.tv_nsec >= 1000000000) {
        tmp.tv_nsec -= 1000000000;
        if (ah_p_add_overflow(tmp.tv_sec, 1, &tmp.tv_sec)) {
            return AH_ERANGE;
        }
    }

    *result = (ah_time_t) { ._timespec = tmp };

    return AH_ENONE;
}

ah_extern ah_err_t ah_time_sub(const ah_time_t time, const ah_timediff_t diff, ah_time_t* result)
{
    if (result == NULL) {
        return AH_EINVAL;
    }

    struct __kernel_timespec tmp;
    if (ah_p_sub_overflow(time._timespec.tv_sec, diff / 1000000000, &tmp.tv_sec)) {
        return AH_ERANGE;
    }
    tmp.tv_nsec = time._timespec.tv_nsec - (diff % 1000000000);
    if (tmp.tv_nsec < 0) {
        tmp.tv_nsec += 1000000000;
        if (ah_p_sub_overflow(tmp.tv_sec, 1, &tmp.tv_sec)) {
            return AH_ERANGE;
        }
    }
    else if (tmp.tv_nsec >= 1000000000) {
        tmp.tv_nsec -= 1000000000;
        if (ah_p_add_overflow(tmp.tv_sec, 1, &tmp.tv_sec)) {
            return AH_ERANGE;
        }
    }

    *result = (ah_time_t) { ._timespec = tmp };

    return AH_ENONE;
}

ah_extern bool ah_time_is_after(const ah_time_t a, const ah_time_t b)
{
    return (a._timespec.tv_sec > b._timespec.tv_sec)
        || (a._timespec.tv_sec == b._timespec.tv_sec && a._timespec.tv_nsec > b._timespec.tv_nsec);
}

ah_extern bool ah_time_is_before(const ah_time_t a, const ah_time_t b)
{
    return (a._timespec.tv_sec < b._timespec.tv_sec)
        || (a._timespec.tv_sec == b._timespec.tv_sec && a._timespec.tv_nsec < b._timespec.tv_nsec);
}

ah_extern bool ah_time_is_zero(const ah_time_t time)
{
    return time._timespec.tv_sec == INT64_C(0) && time._timespec.tv_nsec == INT64_C(0);
}
