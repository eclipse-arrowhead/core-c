// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/math.h"

#include "ah/err.h"

#if AH_IS_WIN32 && defined(_M_AMD64)
#    pragma intrinsic(_mul128, _umul128)
#    define s_x64_mul128  _mul128
#    define s_x64_umul128 _umul128
#elif AH_IS_WIN32 && defined(_M_ARM64)
#    pragma intrinsic(_mulh, _umulh)
#    define s_arm64_mulh  _mulh
#    define s_arm64_umulh _umulh
#endif

ah_extern ah_err_t ah_add_int64(const int64_t a, const int64_t b, int64_t* result)
{
    if (result == NULL) {
        return AH_EINVAL;
    }

    int64_t tmp;

#if defined(ah_i_add_overflow)
    if (ah_i_add_overflow(a, b, &tmp)) {
        return AH_ERANGE;
    }
#else
    tmp = a + b;
    if (((a < 0) == (b < 0)) && ((a < 0) != (tmp < 0))) {
        return AH_ERANGE;
    }
#endif

    *result = tmp;
    return AH_ENONE;
}

ah_extern ah_err_t ah_div_int64(const int64_t a, const int64_t b, int64_t* result)
{
    if (result == NULL) {
        return AH_EINVAL;
    }
    if (b == 0) {
        return AH_EDOM;
    }
    if (a == INT64_MIN && b == -1) {
        return AH_ERANGE;
    }
    *result = a / b;
    return AH_ENONE;
}

ah_extern ah_err_t ah_mul_int64(const int64_t a, const int64_t b, int64_t* result)
{
    if (result == NULL) {
        return AH_EINVAL;
    }

    int64_t tmp;

#if defined(ah_i_mul_overflow)
    if (ah_i_mul_overflow(a, b, &tmp)) {
        return AH_ERANGE;
    }
#elif defined(s_x64_mul128)
    int64_t overflow = INT64_C(0);
    tmp = s_x64_mul128(a, b, &overflow);
    if (!(overflow == 0 && tmp >= 0 && tmp <= INT64_MAX) && !(overflow == -1 && tmp < 0 && tmp >= INT64_MIN)) {
        return AH_ERANGE;
    }
#elif defined(s_arm64_mulh)
    int64_t overflow = s_arm64_mulh(a, b);
    tmp = a * b;
    if (!(overflow == 0 && tmp >= 0 && tmp <= INT64_MAX) && !(overflow == -1 && tmp < 0 && tmp >= INT64_MIN)) {
        return AH_ERANGE;
    }
#else
    tmp = a * b;
    if (a != 0 && (tmp / a) != b) {
        return AH_ERANGE;
    }
#endif

    *result = tmp;
    return AH_ENONE;
}

ah_extern ah_err_t ah_sub_int64(const int64_t a, const int64_t b, int64_t* result)
{
    if (result == NULL) {
        return AH_EINVAL;
    }

    int64_t tmp;

#if defined(ah_i_sub_overflow)
    if (ah_i_sub_overflow(a, b, &tmp)) {
        return AH_ERANGE;
    }
#else
    tmp = a - b;
    if (((a < 0) != (b < 0)) && ((a < 0) != (tmp < 0))) {
        return AH_ERANGE;
    }
#endif

    *result = tmp;
    return AH_ENONE;
}

ah_extern ah_err_t ah_add_size(const size_t a, const size_t b, size_t* result)
{
    if (result == NULL) {
        return AH_EINVAL;
    }

    size_t tmp;

#if defined(ah_i_add_overflow)
    if (ah_i_add_overflow(a, b, &tmp)) {
        return AH_ERANGE;
    }
#else
    tmp = a + b;
    if (tmp < a) {
        return AH_ERANGE;
    }
#endif

    *result = tmp;
    return AH_ENONE;
}

ah_extern ah_err_t ah_div_size(const size_t a, const size_t b, size_t* result)
{
    if (result == NULL) {
        return AH_EINVAL;
    }
    if (b == 0) {
        return AH_EDOM;
    }
    *result = a / b;
    return AH_ENONE;
}

ah_extern ah_err_t ah_mul_size(const size_t a, const size_t b, size_t* result)
{
    if (result == NULL) {
        return AH_EINVAL;
    }

    size_t tmp;

#if defined(ah_i_mul_overflow)
    if (ah_i_mul_overflow(a, b, &tmp)) {
        return AH_ERANGE;
    }
#elif defined(s_x64_umul128)
    uint64_t overflow = UINT64_C(0);
    tmp = s_x64_umul128(a, b, &overflow);
    if (overflow != 0) {
        return AH_ERANGE;
    }
#elif defined(s_arm64_umulh)
    if (s_arm64_umulh(a, b) != 0) {
        return AH_ERANGE;
    }
    tmp = a * b;
#else
    tmp = a * b;
    if (a != 0 && (tmp / a) != b) {
        return AH_ERANGE;
    }
#endif

    *result = tmp;
    return AH_ENONE;
}

ah_extern ah_err_t ah_sub_size(const size_t a, const size_t b, size_t* result)
{
    if (result == NULL) {
        return AH_EINVAL;
    }

    size_t tmp;

#if defined(ah_i_mul_overflow)
    if (ah_i_mul_overflow(a, b, &tmp)) {
        return AH_ERANGE;
    }
#else
    if (a < b) {
        return AH_ERANGE;
    }
    tmp = a - b;
#endif

    *result = tmp;
    return AH_ENONE;
}

ah_extern ah_err_t ah_add_uint64(const uint64_t a, const uint64_t b, uint64_t* result)
{
    if (result == NULL) {
        return AH_EINVAL;
    }

    uint64_t tmp;

#if defined(ah_i_add_overflow)
    if (ah_i_add_overflow(a, b, &tmp)) {
        return AH_ERANGE;
    }
#else
    tmp = a + b;
    if (tmp < a) {
        return AH_ERANGE;
    }
#endif

    *result = tmp;
    return AH_ENONE;
}

ah_extern ah_err_t ah_div_uint64(const uint64_t a, const uint64_t b, uint64_t* result)
{
    if (result == NULL) {
        return AH_EINVAL;
    }
    if (b == 0) {
        return AH_EDOM;
    }
    *result = a / b;
    return AH_ENONE;
}

ah_extern ah_err_t ah_mul_uint64(const uint64_t a, const uint64_t b, uint64_t* result)
{
    if (result == NULL) {
        return AH_EINVAL;
    }

    uint64_t tmp;

#if defined(ah_i_mul_overflow)
    if (ah_i_mul_overflow(a, b, &tmp)) {
        return AH_ERANGE;
    }
#elif defined(s_x64_umul128)
    uint64_t overflow = UINT64_C(0);
    tmp = s_x64_umul128(a, b, &overflow);
    if (overflow != 0) {
        return AH_ERANGE;
    }
#elif defined(s_arm64_umulh)
    if (s_arm64_umulh(a, b) != 0) {
        return AH_ERANGE;
    }
    tmp = a * b;
#else
    tmp = a * b;
    if (a != 0 && (tmp / a) != b) {
        return AH_ERANGE;
    }
#endif

    *result = tmp;
    return AH_ENONE;
}

ah_extern ah_err_t ah_sub_uint64(const uint64_t a, const uint64_t b, uint64_t* result)
{
    if (result == NULL) {
        return AH_EINVAL;
    }

    uint64_t tmp;

#if defined(ah_i_sub_overflow)
    if (ah_i_sub_overflow(a, b, &tmp)) {
        return AH_ERANGE;
    }
#else
    if (a < b) {
        return AH_ERANGE;
    }
    tmp = a - b;
#endif

    *result = tmp;
    return AH_ENONE;
}
