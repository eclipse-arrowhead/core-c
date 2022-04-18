// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/time.h"

#include "ah/abort.h"
#include "ah/err.h"
#include "ah/math.h"

#if AH_IS_DARWIN
#    include <mach/mach_time.h>
#elif AH_IS_LINUX && AH_USE_URING
#    include "ah/assert.h"

#    include <time.h>
#elif AH_IS_WIN32
#    define WIN32_LEAN_AND_MEAN
#    include <windows.h>
#endif

#include <string.h>

#if AH_IS_DARWIN
static mach_timebase_info_data_t s_get_mach_timebase_info_data(void);
#elif AH_IS_WIN32
static double s_get_ns_per_performance_tick(void);
#endif

ah_extern ah_time_t ah_time_now()
{
#if AH_IS_DARWIN

    return (ah_time_t) { ._mach_absolute_time = mach_absolute_time() };

#elif AH_IS_LINUX && AH_USE_URING

    struct timespec timespec;
    if (clock_gettime(CLOCK_MONOTONIC, &timespec) != 0) {
        ah_abortf("failed to get monotonic system time; %s", strerror(errno));
    }

    ah_assert_if_debug(sizeof(__kernel_time64_t) >= sizeof(timespec.tv_sec));

    return (ah_time_t) {
        ._timespec.tv_sec = (__kernel_time64_t) timespec.tv_sec,
        ._timespec.tv_nsec = (long long) timespec.tv_nsec,
    };

#elif AH_IS_WIN32

    LARGE_INTEGER time_lt = { 0 };
    if (!QueryPerformanceCounter(&time_lt)) {
        ah_abort_with_last_win32_error("failed to query WIN32 performance counter");
    }

    return (ah_time_t) { ._performance_count = time_lt.QuadPart };

#endif
}

ah_extern ah_err_t ah_time_diff(const ah_time_t a, const ah_time_t b, ah_timediff_t* diff)
{
    if (diff == NULL) {
        return AH_EINVAL;
    }

#if AH_IS_DARWIN

    ah_timediff_t tmp_td;
    if (ah_i_sub_overflow(a._mach_absolute_time, b._mach_absolute_time, &tmp_td)) {
        return AH_ERANGE;
    }

    mach_timebase_info_data_t info = s_get_mach_timebase_info_data();

    if (ah_i_mul_overflow(tmp_td, info.numer, &tmp_td)) {
        return AH_ERANGE;
    }
    tmp_td /= info.denom;

    *diff = tmp_td;

    return AH_ENONE;

#elif AH_IS_LINUX && AH_USE_URING

    struct __kernel_timespec tmp_ts;
    if (ah_i_sub_overflow(a._timespec.tv_sec, b._timespec.tv_sec, &tmp_ts.tv_sec)) {
        return AH_ERANGE;
    }

    tmp_ts.tv_nsec = a._timespec.tv_nsec - b._timespec.tv_nsec;
    if (tmp_ts.tv_nsec < 0) {
        if (ah_i_sub_overflow(tmp_ts.tv_sec, 1, &tmp_ts.tv_sec)) {
            return AH_ERANGE;
        }
        tmp_ts.tv_nsec += 1000000000;
    }

    ah_timediff_t tmp_td;
    if (ah_i_mul_overflow(tmp_ts.tv_sec, 1000000000, &tmp_td)) {
        return AH_ERANGE;
    }
    if (ah_i_add_overflow(tmp_ts.tv_nsec, tmp_td, &tmp_td)) {
        return AH_ERANGE;
    }

    *diff = tmp_td;

    return AH_ENONE;

#elif AH_IS_WIN32

    ah_timediff_t tmp_td;
    if (!ah_sub_int64(a._performance_count, b._performance_count, &tmp_td)) {
        return AH_ERANGE;
    }

    *diff = (ah_timediff_t) (((double) tmp_td) * s_get_ns_per_performance_tick());

    return AH_ENONE;

#endif
}

#if AH_IS_DARWIN

static mach_timebase_info_data_t s_get_mach_timebase_info_data(void)
{
    mach_timebase_info_data_t info;

    if (mach_timebase_info(&info) != 0) {
        ah_abortf("failed to get Mach time-base information; %s", strerror(errno));
    }

    return info;
}

#elif AH_IS_WIN32

static double s_get_ns_per_performance_tick(void)
{
    static double s_ns_per_performance_tick = 0.0;

    static volatile LONG s_is_set = 0u;
    if (ah_unlikely(InterlockedCompareExchangeNoFence(&s_is_set, 1u, 0u) == 0u)) {
        LARGE_INTEGER performance_frequency = { .QuadPart = INT64_C(0) };
        if (!QueryPerformanceFrequency(&performance_frequency)) {
            ah_abort_with_last_win32_error("failed to query WIN32 performance frequency");
        }
        s_ns_per_performance_tick = 1e9 / ((double) performance_frequency.QuadPart);
    }

    return s_ns_per_performance_tick;
}

#endif

ah_extern bool ah_time_eq(const ah_time_t a, const ah_time_t b)
{
#if AH_IS_DARWIN

    return a._mach_absolute_time == b._mach_absolute_time;

#elif AH_IS_LINUX && AH_USE_URING

    return a._timespec.tv_sec == b._timespec.tv_sec && a._timespec.tv_nsec == b._timespec.tv_nsec;

#elif AH_IS_WIN32

    return a._performance_count == b._performance_count;

#endif
}

ah_extern int ah_time_cmp(const ah_time_t a, const ah_time_t b)
{
#if AH_IS_DARWIN

    if (a._mach_absolute_time < b._mach_absolute_time) {
        return -1;
    }
    else if (a._mach_absolute_time == b._mach_absolute_time) {
        return 0;
    }
    else {
        return 1;
    }

#elif AH_IS_LINUX && AH_USE_URING

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

#elif AH_IS_WIN32

    if (a._performance_count < b._performance_count) {
        return -1;
    }
    else if (a._performance_count == b._performance_count) {
        return 0;
    }
    else {
        return 1;
    }

#endif
}

ah_extern ah_err_t ah_time_add(const ah_time_t time, const ah_timediff_t diff, ah_time_t* result)
{
    if (result == NULL) {
        return AH_EINVAL;
    }

#if AH_IS_DARWIN

    mach_timebase_info_data_t info = s_get_mach_timebase_info_data();

    uint64_t tmp = diff / info.numer;
    if (ah_i_mul_overflow(tmp, info.denom, &tmp)) {
        return AH_ERANGE;
    }
    if (ah_i_add_overflow(time._mach_absolute_time, tmp, &tmp)) {
        return AH_ERANGE;
    }

    *result = (ah_time_t) { ._mach_absolute_time = tmp };

    return AH_ENONE;

#elif AH_IS_LINUX && AH_USE_URING

    struct __kernel_timespec tmp;
    if (ah_i_add_overflow(time._timespec.tv_sec, diff / 1000000000, &tmp.tv_sec)) {
        return AH_ERANGE;
    }
    tmp.tv_nsec = time._timespec.tv_nsec + (diff % 1000000000);
    if (tmp.tv_nsec < 0) {
        tmp.tv_nsec += 1000000000;
        if (ah_i_sub_overflow(tmp.tv_sec, 1, &tmp.tv_sec)) {
            return AH_ERANGE;
        }
    }
    else if (tmp.tv_nsec >= 1000000000) {
        tmp.tv_nsec -= 1000000000;
        if (ah_i_add_overflow(tmp.tv_sec, 1, &tmp.tv_sec)) {
            return AH_ERANGE;
        }
    }

    *result = (ah_time_t) { ._timespec = tmp };

    return AH_ENONE;

#elif AH_IS_WIN32

    const int64_t tmp = (int64_t) (((double) diff) / s_get_ns_per_performance_tick());

    if (!ah_add_int64(time._performance_count, tmp, &result->_performance_count)) {
        return AH_ERANGE;
    }

    return AH_ENONE;

#endif
}

ah_extern ah_err_t ah_time_sub(const ah_time_t time, const ah_timediff_t diff, ah_time_t* result)
{
    if (result == NULL) {
        return AH_EINVAL;
    }

#if AH_IS_DARWIN

    mach_timebase_info_data_t info = s_get_mach_timebase_info_data();

    uint64_t tmp = diff / info.numer;
    if (ah_i_mul_overflow(tmp, info.denom, &tmp)) {
        return AH_ERANGE;
    }
    if (ah_i_sub_overflow(time._mach_absolute_time, tmp, &tmp)) {
        return AH_ERANGE;
    }

    *result = (ah_time_t) { ._mach_absolute_time = tmp };

    return AH_ENONE;

#elif AH_IS_LINUX && AH_USE_URING

    struct __kernel_timespec tmp;
    if (ah_i_sub_overflow(time._timespec.tv_sec, diff / 1000000000, &tmp.tv_sec)) {
        return AH_ERANGE;
    }
    tmp.tv_nsec = time._timespec.tv_nsec - (diff % 1000000000);
    if (tmp.tv_nsec < 0) {
        tmp.tv_nsec += 1000000000;
        if (ah_i_sub_overflow(tmp.tv_sec, 1, &tmp.tv_sec)) {
            return AH_ERANGE;
        }
    }
    else if (tmp.tv_nsec >= 1000000000) {
        tmp.tv_nsec -= 1000000000;
        if (ah_i_add_overflow(tmp.tv_sec, 1, &tmp.tv_sec)) {
            return AH_ERANGE;
        }
    }

    *result = (ah_time_t) { ._timespec = tmp };

    return AH_ENONE;

#elif AH_IS_WIN32

    const int64_t tmp = (int64_t) (((double) diff) / s_get_ns_per_performance_tick());

    if (!ah_sub_int64(time._performance_count, tmp, &result->_performance_count)) {
        return AH_ERANGE;
    }

    return AH_ENONE;

#endif
}

ah_extern bool ah_time_is_after(const ah_time_t a, const ah_time_t b)
{
#if AH_IS_DARWIN

    return a._mach_absolute_time > b._mach_absolute_time;

#elif AH_IS_LINUX && AH_USE_URING

    return (a._timespec.tv_sec > b._timespec.tv_sec)
        || (a._timespec.tv_sec == b._timespec.tv_sec && a._timespec.tv_nsec > b._timespec.tv_nsec);

#elif AH_IS_WIN32

    return a._performance_count > b._performance_count;

#endif
}

ah_extern bool ah_time_is_before(const ah_time_t a, const ah_time_t b)
{
#if AH_IS_DARWIN

    return a._mach_absolute_time < b._mach_absolute_time;

#elif AH_IS_LINUX && AH_USE_URING

    return (a._timespec.tv_sec < b._timespec.tv_sec)
        || (a._timespec.tv_sec == b._timespec.tv_sec && a._timespec.tv_nsec < b._timespec.tv_nsec);

#elif AH_IS_WIN32

    return a._performance_count < b._performance_count;

#endif
}

ah_extern bool ah_time_is_zero(const ah_time_t time)
{
#if AH_IS_DARWIN

    return time._mach_absolute_time == UINT64_C(0);

#elif AH_IS_LINUX && AH_USE_URING

    return time._timespec.tv_sec == INT64_C(0) && time._timespec.tv_nsec == INT64_C(0);

#elif AH_IS_WIN32

    return time._performance_count == INT64_C(0);

#endif
}

ah_extern ah_err_t ah_timediff_add(ah_timediff_t a, ah_timediff_t b, ah_timediff_t* result)
{
    return ah_add_int64(a, b, result);
}

ah_extern ah_err_t ah_timediff_div(ah_timediff_t a, ah_timediff_t b, ah_timediff_t* result)
{
    return ah_div_int64(a, b, result);
}

ah_extern ah_err_t ah_timediff_mul(ah_timediff_t a, ah_timediff_t b, ah_timediff_t* result)
{
    return ah_mul_int64(a, b, result);
}

ah_extern ah_err_t ah_timediff_sub(ah_timediff_t a, ah_timediff_t b, ah_timediff_t* result)
{
    return ah_sub_int64(a, b, result);
}
