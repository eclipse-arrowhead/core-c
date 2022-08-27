// SPDX-License-Identifier: EPL-2.0

#include "ah/err.h"
#include "ah/math.h"
#include <ah/unit.h>

static void s_should_avoid_add_overflows(ah_unit_res_t* res);
static void s_should_avoid_mul_overflows(ah_unit_res_t* res);
static void s_should_avoid_sub_overflows(ah_unit_res_t* res);
static void s_should_detect_add_overflows(ah_unit_res_t* res);
static void s_should_detect_mul_overflows(ah_unit_res_t* res);
static void s_should_detect_sub_overflows(ah_unit_res_t* res);

void test_math(ah_unit_res_t* res)
{
    s_should_avoid_add_overflows(res);
    s_should_avoid_mul_overflows(res);
    s_should_avoid_sub_overflows(res);
    s_should_detect_add_overflows(res);
    s_should_detect_mul_overflows(res);
    s_should_detect_sub_overflows(res);
}

static void s_should_avoid_add_overflows(ah_unit_res_t* res)
{
    ah_err_t err;
    {
        int64_t result = 1;
        err = ah_add_int64(INT64_MAX / 2, INT64_MAX / 2 + 1, &result);
        if (ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
            (void) ah_unit_assert_eq_intmax(AH_UNIT_CTX, res, result, INT64_MAX);
        }
    }
    {
        int64_t result = 1;
        err = ah_add_int64(INT64_MIN + 4, -4, &result);
        if (ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
            (void) ah_unit_assert_eq_intmax(AH_UNIT_CTX, res, result, INT64_MIN);
        }
    }
    {
        size_t result = 2u;
        err = ah_add_size(SIZE_MAX / 2u, SIZE_MAX / 2u + 1u, &result);
        if (ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
            (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, result, SIZE_MAX);
        }
    }
    {
        uint64_t result = 3u;
        err = ah_add_uint64(UINT64_MAX - 1u, 1u, &result);
        if (ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
            (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, result, UINT64_MAX);
        }
    }
}

static void s_should_avoid_mul_overflows(ah_unit_res_t* res)
{
    ah_err_t err;
    {
        int64_t result = 1;
        err = ah_mul_int64(INT64_MAX / 2, 2, &result);
        if (ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
            (void) ah_unit_assert_eq_intmax(AH_UNIT_CTX, res, result, INT64_MAX - 1);
        }
    }
    {
        int64_t result = 1;
        err = ah_mul_int64(INT64_MIN / 2, 2, &result);
        if (ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
#if (INT64_MIN / 2) * 2 == INT64_MIN
            (void) ah_unit_assert_eq_intmax(AH_UNIT_CTX, res, result, INT64_MIN);
#else
            (void) ah_unit_assert_eq_intmax(AH_UNIT_CTX, res, result, INT64_MIN + 1);
#endif
        }
    }
    {
        size_t result = 2u;
        err = ah_mul_size(SIZE_MAX / 2u, 2u, &result);
        if (ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
            (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, result, SIZE_MAX - 1);
        }
    }
    {
        uint64_t result = 3u;
        err = ah_mul_uint64(UINT64_MAX / 2u, 2u, &result);
        if (ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
            (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, result, UINT64_MAX - 1);
        }
    }
}

static void s_should_avoid_sub_overflows(ah_unit_res_t* res)
{
    ah_err_t err;
    {
        int64_t result = 1;
        err = ah_sub_int64(INT64_MAX, INT64_MAX, &result);
        if (ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
            (void) ah_unit_assert_eq_intmax(AH_UNIT_CTX, res, result, 0);
        }
    }
    {
        int64_t result = 1;
        err = ah_sub_int64(INT64_MIN, INT64_MIN, &result);
        if (ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
            (void) ah_unit_assert_eq_intmax(AH_UNIT_CTX, res, result, 0);
        }
    }
    {
        size_t result = 2u;
        err = ah_sub_size(SIZE_MAX, SIZE_MAX, &result);
        if (ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
            (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, result, 0);
        }
    }
    {
        uint64_t result = 3u;
        err = ah_sub_uint64(UINT64_MAX, UINT64_MAX, &result);
        if (ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
            (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, result, 0);
        }
    }
}

static void s_should_detect_add_overflows(ah_unit_res_t* res)
{
    ah_err_t err;
    {
        int64_t result;
        err = ah_add_int64(INT64_MAX - 8, 9, &result);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ERANGE);
    }
    {
        int64_t result;
        err = ah_add_int64(INT64_MIN + 4, -5, &result);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ERANGE);
    }
    {
        size_t result;
        err = ah_add_size(SIZE_MAX - 2u, 3u, &result);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ERANGE);
    }
    {
        uint64_t result;
        err = ah_add_uint64(UINT64_MAX - 6u, 7u, &result);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ERANGE);
    }
}

static void s_should_detect_mul_overflows(ah_unit_res_t* res)
{
    ah_err_t err;
    {
        int64_t result;
        err = ah_mul_int64(INT64_MAX / 2, 4, &result);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ERANGE);
    }
    {
        int64_t result;
        err = ah_mul_int64(INT64_MIN / 3, -4, &result);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ERANGE);
    }
    {
        size_t result;
        err = ah_mul_size(SIZE_MAX / 5u, 6u, &result);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ERANGE);
    }
    {
        uint64_t result;
        err = ah_mul_uint64(UINT64_MAX / 19u, 20u, &result);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ERANGE);
    }
}

static void s_should_detect_sub_overflows(ah_unit_res_t* res)
{
    ah_err_t err;
    {
        int64_t result;
        err = ah_sub_int64(INT64_MAX - 8, -9, &result);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ERANGE);
    }
    {
        int64_t result;
        err = ah_sub_int64(INT64_MIN + 4, 5, &result);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ERANGE);
    }
    {
        size_t result;
        err = ah_sub_size(SIZE_MAX - 2u, SIZE_MAX - 1u, &result);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ERANGE);
    }
    {
        uint64_t result;
        err = ah_sub_uint64(UINT64_MAX - 6u, UINT64_MAX - 5u, &result);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ERANGE);
    }
}
