// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/math.h"

#include "ah/err.h"
#include "ah/unit.h"

static void s_should_avoid_add_overflows(ah_unit_t* unit);
static void s_should_avoid_mul_overflows(ah_unit_t* unit);
static void s_should_avoid_sub_overflows(ah_unit_t* unit);
static void s_should_detect_add_overflows(ah_unit_t* unit);
static void s_should_detect_mul_overflows(ah_unit_t* unit);
static void s_should_detect_sub_overflows(ah_unit_t* unit);

void test_math(ah_unit_t* unit)
{
    s_should_avoid_add_overflows(unit);
    s_should_avoid_mul_overflows(unit);
    s_should_avoid_sub_overflows(unit);
    s_should_detect_add_overflows(unit);
    s_should_detect_mul_overflows(unit);
    s_should_detect_sub_overflows(unit);
}

static void s_should_avoid_add_overflows(ah_unit_t* unit)
{
    ah_err_t err;
    {
        int64_t result = 1;
        err = ah_add_int64(INT64_MAX / 2, INT64_MAX / 2 + 1, &result);
        if (ah_unit_assert_enum_eq(unit, err, AH_ENONE, ah_strerror)) {
            (void) ah_unit_assert_signed_eq(unit, result, INT64_MAX);
        }
    }
    {
        int64_t result = 1;
        err = ah_add_int64(INT64_MIN + 4, -4, &result);
        if (ah_unit_assert_enum_eq(unit, err, AH_ENONE, ah_strerror)) {
            (void) ah_unit_assert_signed_eq(unit, result, INT64_MIN);
        }
    }
    {
        size_t result = 2u;
        err = ah_add_size(SIZE_MAX / 2u, SIZE_MAX / 2u + 1u, &result);
        if (ah_unit_assert_enum_eq(unit, err, AH_ENONE, ah_strerror)) {
            (void) ah_unit_assert_unsigned_eq(unit, result, SIZE_MAX);
        }
    }
    {
        uint64_t result = 3u;
        err = ah_add_uint64(UINT64_MAX - 1u, 1u, &result);
        if (ah_unit_assert_enum_eq(unit, err, AH_ENONE, ah_strerror)) {
            (void) ah_unit_assert_unsigned_eq(unit, result, UINT64_MAX);
        }
    }
}

static void s_should_avoid_mul_overflows(ah_unit_t* unit)
{
    ah_err_t err;
    {
        int64_t result = 1;
        err = ah_mul_int64(INT64_MAX / 2, 2, &result);
        if (ah_unit_assert_enum_eq(unit, err, AH_ENONE, ah_strerror)) {
            (void) ah_unit_assert_signed_eq(unit, result, INT64_MAX - 1);
        }
    }
    {
        int64_t result = 1;
        err = ah_mul_int64(INT64_MIN / 2, 2, &result);
        if (ah_unit_assert_enum_eq(unit, err, AH_ENONE, ah_strerror)) {
#if (INT64_MIN / 2) * 2 == INT64_MIN
            (void) ah_unit_assert_signed_eq(unit, result, INT64_MIN);
#else
            (void) ah_unit_assertSignedEquality(unit, result, INT64_MIN + 1);
#endif
        }
    }
    {
        size_t result = 2u;
        err = ah_mul_size(SIZE_MAX / 2u, 2u, &result);
        if (ah_unit_assert_enum_eq(unit, err, AH_ENONE, ah_strerror)) {
            (void) ah_unit_assert_unsigned_eq(unit, result, SIZE_MAX - 1);
        }
    }
    {
        uint64_t result = 3u;
        err = ah_mul_uint64(UINT64_MAX / 2u, 2u, &result);
        if (ah_unit_assert_enum_eq(unit, err, AH_ENONE, ah_strerror)) {
            (void) ah_unit_assert_unsigned_eq(unit, result, UINT64_MAX - 1);
        }
    }
}

static void s_should_avoid_sub_overflows(ah_unit_t* unit)
{
    ah_err_t err;
    {
        int64_t result = 1;
        err = ah_sub_int64(INT64_MAX, INT64_MAX, &result);
        if (ah_unit_assert_enum_eq(unit, err, AH_ENONE, ah_strerror)) {
            (void) ah_unit_assert_signed_eq(unit, result, 0);
        }
    }
    {
        int64_t result = 1;
        err = ah_sub_int64(INT64_MIN, INT64_MIN, &result);
        if (ah_unit_assert_enum_eq(unit, err, AH_ENONE, ah_strerror)) {
            (void) ah_unit_assert_signed_eq(unit, result, 0);
        }
    }
    {
        size_t result = 2u;
        err = ah_sub_size(SIZE_MAX, SIZE_MAX, &result);
        if (ah_unit_assert_enum_eq(unit, err, AH_ENONE, ah_strerror)) {
            (void) ah_unit_assert_unsigned_eq(unit, result, 0);
        }
    }
    {
        uint64_t result = 3u;
        err = ah_sub_uint64(UINT64_MAX, UINT64_MAX, &result);
        if (ah_unit_assert_enum_eq(unit, err, AH_ENONE, ah_strerror)) {
            (void) ah_unit_assert_unsigned_eq(unit, result, 0);
        }
    }
}

static void s_should_detect_add_overflows(ah_unit_t* unit)
{
    ah_err_t err;
    {
        int64_t result;
        err = ah_add_int64(INT64_MAX - 8, 9, &result);
        (void) ah_unit_assert_enum_eq(unit, err, AH_ERANGE, ah_strerror);
    }
    {
        int64_t result;
        err = ah_add_int64(INT64_MIN + 4, -5, &result);
        (void) ah_unit_assert_enum_eq(unit, err, AH_ERANGE, ah_strerror);
    }
    {
        size_t result;
        err = ah_add_size(SIZE_MAX - 2u, 3u, &result);
        (void) ah_unit_assert_enum_eq(unit, err, AH_ERANGE, ah_strerror);
    }
    {
        uint64_t result;
        err = ah_add_uint64(UINT64_MAX - 6u, 7u, &result);
        (void) ah_unit_assert_enum_eq(unit, err, AH_ERANGE, ah_strerror);
    }
}

static void s_should_detect_mul_overflows(ah_unit_t* unit)
{
    ah_err_t err;
    {
        int64_t result;
        err = ah_mul_int64(INT64_MAX / 2, 4, &result);
        (void) ah_unit_assert_enum_eq(unit, err, AH_ERANGE, ah_strerror);
    }
    {
        int64_t result;
        err = ah_mul_int64(INT64_MIN / 3, -4, &result);
        (void) ah_unit_assert_enum_eq(unit, err, AH_ERANGE, ah_strerror);
    }
    {
        size_t result;
        err = ah_mul_size(SIZE_MAX / 5u, 6u, &result);
        (void) ah_unit_assert_enum_eq(unit, err, AH_ERANGE, ah_strerror);
    }
    {
        uint64_t result;
        err = ah_mul_uint64(UINT64_MAX / 19u, 20u, &result);
        (void) ah_unit_assert_enum_eq(unit, err, AH_ERANGE, ah_strerror);
    }
}

static void s_should_detect_sub_overflows(ah_unit_t* unit)
{
    ah_err_t err;
    {
        int64_t result;
        err = ah_sub_int64(INT64_MAX - 8, -9, &result);
        (void) ah_unit_assert_enum_eq(unit, err, AH_ERANGE, ah_strerror);
    }
    {
        int64_t result;
        err = ah_sub_int64(INT64_MIN + 4, 5, &result);
        (void) ah_unit_assert_enum_eq(unit, err, AH_ERANGE, ah_strerror);
    }
    {
        size_t result;
        err = ah_sub_size(SIZE_MAX - 2u, SIZE_MAX - 1u, &result);
        (void) ah_unit_assert_enum_eq(unit, err, AH_ERANGE, ah_strerror);
    }
    {
        uint64_t result;
        err = ah_sub_uint64(UINT64_MAX - 6u, UINT64_MAX - 5u, &result);
        (void) ah_unit_assert_enum_eq(unit, err, AH_ERANGE, ah_strerror);
    }
}
