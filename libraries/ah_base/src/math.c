// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/math.h"

#include "ah/err.h"
#include "ah/intrin.h"

#if AH_IS_WIN32
# define ENABLE_INTSAFE_SIGNED_FUNCTIONS
# include <intsafe.h>
#endif

ah_extern ah_err_t ah_add_int64(const int64_t a, const int64_t b, int64_t* result)
{
    if (result == NULL) {
        return AH_EINVAL;
    }

    int64_t tmp;

#if defined(ah_p_add_overflow)
    if (ah_p_add_overflow(a, b, &tmp)) {
        return AH_ERANGE;
    }
#elif AH_IS_WIN32
    if (FAILED(Int64Add(a, b, &tmp))) {
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

#if defined(ah_p_mul_overflow)
    if (ah_p_mul_overflow(a, b, &tmp)) {
        return AH_ERANGE;
    }
#elif AH_IS_WIN32
    if (FAILED(Int64Mult(a, b, &tmp))) {
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

#if defined(ah_p_sub_overflow)
    if (ah_p_sub_overflow(a, b, &tmp)) {
        return AH_ERANGE;
    }
#elif AH_IS_WIN32
    if (FAILED(Int64Sub(a, b, &tmp))) {
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

#if defined(ah_p_add_overflow)
    if (ah_p_add_overflow(a, b, &tmp)) {
        return AH_ERANGE;
    }
#elif AH_IS_WIN32
    if (FAILED(SizeTAdd(a, b, &tmp))) {
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

#if defined(ah_p_mul_overflow)
    if (ah_p_mul_overflow(a, b, &tmp)) {
        return AH_ERANGE;
    }
#elif AH_IS_WIN32
    if (FAILED(SizeTMult(a, b, &tmp))) {
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

#if defined(ah_p_sub_overflow)
    if (ah_p_sub_overflow(a, b, &tmp)) {
        return AH_ERANGE;
    }
#elif AH_IS_WIN32
    if (FAILED(SizeTSub(a, b, &tmp))) {
        return AH_ERANGE;
    }
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

#if defined(ah_p_add_overflow)
    if (ah_p_add_overflow(a, b, &tmp)) {
        return AH_ERANGE;
    }
#elif AH_IS_WIN32
    if (FAILED(UInt64Add(a, b, &tmp))) {
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

#if defined(ah_p_mul_overflow)
    if (ah_p_mul_overflow(a, b, &tmp)) {
        return AH_ERANGE;
    }
#elif AH_IS_WIN32
    if (FAILED(UInt64Mult(a, b, &tmp))) {
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

#if defined(ah_p_sub_overflow)
    if (ah_p_sub_overflow(a, b, &tmp)) {
        return AH_ERANGE;
    }
#elif AH_IS_WIN32
    if (FAILED(UInt64Sub(a, b, &tmp))) {
        return AH_ERANGE;
    }
#endif

    *result = tmp;
    return AH_ENONE;
}
