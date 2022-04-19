// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/time.h"

#include "ah/abort.h"
#include "ah/err.h"
#include "ah/math.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

ah_noreturn void s_abort_with_last_win32_error(const char* message);
static double s_get_ns_per_performance_tick(void);

ah_extern ah_time_t ah_time_now()
{
    LARGE_INTEGER time_lt = { 0 };
    if (!QueryPerformanceCounter(&time_lt)) {
        s_abort_with_last_win32_error("failed to query WIN32 performance counter");
    }

    return (ah_time_t) { ._performance_count = time_lt.QuadPart };
}

ah_noreturn void s_abort_with_last_win32_error(const char* message)
{
    DWORD err = GetLastError();
    char buf[256];

    WORD flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    size_t size = FormatMessageA(flags, NULL, err, 0, (LPSTR) &buf, sizeof(buf), NULL);

    ah_abortf("%s; %*.s", message, size, buf);
}

ah_extern ah_err_t ah_time_diff(const ah_time_t a, const ah_time_t b, ah_timediff_t* diff)
{
    if (diff == NULL) {
        return AH_EINVAL;
    }

    ah_timediff_t tmp_td;
    if (!ah_sub_int64(a._performance_count, b._performance_count, &tmp_td)) {
        return AH_ERANGE;
    }

    *diff = (ah_timediff_t) (((double) tmp_td) * s_get_ns_per_performance_tick());

    return AH_ENONE;
}

static double s_get_ns_per_performance_tick(void)
{
    static double s_ns_per_performance_tick = 0.0;

    static volatile LONG s_is_set = 0u;
    if (ah_unlikely(InterlockedCompareExchangeNoFence(&s_is_set, 1u, 0u) == 0u)) {
        LARGE_INTEGER performance_frequency = { .QuadPart = INT64_C(0) };
        if (!QueryPerformanceFrequency(&performance_frequency)) {
            s_abort_with_last_win32_error("failed to query WIN32 performance frequency");
        }
        s_ns_per_performance_tick = 1e9 / ((double) performance_frequency.QuadPart);
    }

    return s_ns_per_performance_tick;
}

ah_extern bool ah_time_eq(const ah_time_t a, const ah_time_t b)
{
    return a._performance_count == b._performance_count;
}

ah_extern int ah_time_cmp(const ah_time_t a, const ah_time_t b)
{
    if (a._performance_count < b._performance_count) {
        return -1;
    }
    else if (a._performance_count == b._performance_count) {
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

    const int64_t tmp = (int64_t) (((double) diff) / s_get_ns_per_performance_tick());

    if (!ah_add_int64(time._performance_count, tmp, &result->_performance_count)) {
        return AH_ERANGE;
    }

    return AH_ENONE;
}

ah_extern ah_err_t ah_time_sub(const ah_time_t time, const ah_timediff_t diff, ah_time_t* result)
{
    if (result == NULL) {
        return AH_EINVAL;
    }

    const int64_t tmp = (int64_t) (((double) diff) / s_get_ns_per_performance_tick());

    if (!ah_sub_int64(time._performance_count, tmp, &result->_performance_count)) {
        return AH_ERANGE;
    }

    return AH_ENONE;
}

ah_extern bool ah_time_is_after(const ah_time_t a, const ah_time_t b)
{
    return a._performance_count > b._performance_count;
}

ah_extern bool ah_time_is_before(const ah_time_t a, const ah_time_t b)
{
    return a._performance_count < b._performance_count;
}

ah_extern bool ah_time_is_zero(const ah_time_t time)
{
    return time._performance_count == INT64_C(0);
}
