// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/math.h"

ah_extern ah_err_t ah_add_int64(const int64_t a, const int64_t b, int64_t* result)
{
    if (result == NULL) {
        return AH_EINVAL;
    }

#ifdef ah_i_add_overflow

    int64_t tmp;
    if (ah_i_add_overflow(a, b, &tmp)) {
        return AH_ERANGE;
    }
    else {
        *result = tmp;
        return AH_ENONE;
    }

#endif
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

#ifdef ah_i_mul_overflow

    int64_t tmp;
    if (ah_i_mul_overflow(a, b, &tmp)) {
        return AH_ERANGE;
    }
    else {
        *result = tmp;
        return AH_ENONE;
    }

#endif
}

ah_extern ah_err_t ah_sub_int64(const int64_t a, const int64_t b, int64_t* result)
{
    if (result == NULL) {
        return AH_EINVAL;
    }

#ifdef ah_i_sub_overflow

    int64_t tmp;
    if (ah_i_sub_overflow(a, b, &tmp)) {
        return AH_ERANGE;
    }
    else {
        *result = tmp;
        return AH_ENONE;
    }

#endif
}

ah_extern ah_err_t ah_add_size(const size_t a, const size_t b, size_t* result)
{
    if (result == NULL) {
        return AH_EINVAL;
    }

#ifdef ah_i_add_overflow

    size_t tmp;
    if (ah_i_add_overflow(a, b, &tmp)) {
        return AH_ERANGE;
    }
    else {
        *result = tmp;
        return AH_ENONE;
    }

#endif
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

#ifdef ah_i_mul_overflow

    size_t tmp;
    if (ah_i_mul_overflow(a, b, &tmp)) {
        return AH_ERANGE;
    }
    else {
        *result = tmp;
        return AH_ENONE;
    }

#endif
}

ah_extern ah_err_t ah_sub_size(const size_t a, const size_t b, size_t* result)
{
    if (result == NULL) {
        return AH_EINVAL;
    }

#ifdef ah_i_sub_overflow

    size_t tmp;
    if (ah_i_sub_overflow(a, b, &tmp)) {
        return AH_ERANGE;
    }
    else {
        *result = tmp;
        return AH_ENONE;
    }

#endif
}

ah_extern ah_err_t ah_add_uint64(const uint64_t a, const uint64_t b, uint64_t* result)
{
    if (result == NULL) {
        return AH_EINVAL;
    }

#ifdef ah_i_add_overflow

    uint64_t tmp;
    if (ah_i_add_overflow(a, b, &tmp)) {
        return AH_ERANGE;
    }
    else {
        *result = tmp;
        return AH_ENONE;
    }

#endif
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

#ifdef ah_i_mul_overflow

    uint64_t tmp;
    if (ah_i_mul_overflow(a, b, &tmp)) {
        return AH_ERANGE;
    }
    else {
        *result = tmp;
        return AH_ENONE;
    }

#endif
}

ah_extern ah_err_t ah_sub_uint64(const uint64_t a, const uint64_t b, uint64_t* result)
{
    if (result == NULL) {
        return AH_EINVAL;
    }

#ifdef ah_i_sub_overflow

    uint64_t tmp;
    if (ah_i_sub_overflow(a, b, &tmp)) {
        return AH_ERANGE;
    }
    else {
        *result = tmp;
        return AH_ENONE;
    }

#endif
}
