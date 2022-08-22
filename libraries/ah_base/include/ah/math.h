// SPDX-License-Identifier: EPL-2.0

#ifndef AH_MATH_H_
#define AH_MATH_H_

/**
 * @file
 * Safe integer operations.
 *
 * This file provides a rather long list of functions that can be used to
 * ensure that certain integer operations never produce undefined behavior.
 *
 * The functions behave as follows: All @c add, @c div, @c mul and @c sub
 * functions return @c AH_ENONE if successful, @c AH_EINVAL if the @c result
 * argument is @c NULL or @c AH_ERANGE if the operation overflowed. The @c div
 * functions additionally return @c AH_EDOM if their @c b argument is zero.
 * Unsigned divisions are guaranteed to never yield @c AH_RANGE. In every case,
 * the @c result value is only updated if the return value is @c AH_ENONE.
 *
 * Note that signed divisions can overflow, causing @c AH_ERANGE to be
 * returned, if their @c a argument is the lowest representable such and their
 * @c b argument is @c -1. This is a consequence of the two's complement
 * integer representation having a negative number range being larger than its
 * positive counterpart. Only two's complement signed integer representations
 * are supported by this library.
 */

#include "defs.h"

#include <stddef.h>
#include <stdint.h>

ah_extern ah_err_t ah_add_int16(int16_t a, int16_t b, int16_t* result);
ah_extern ah_err_t ah_div_int16(int16_t a, int16_t b, int16_t* result);
ah_extern ah_err_t ah_mul_int16(int16_t a, int16_t b, int16_t* result);
ah_extern ah_err_t ah_sub_int16(int16_t a, int16_t b, int16_t* result);

ah_extern ah_err_t ah_add_int32(int32_t a, int32_t b, int32_t* result);
ah_extern ah_err_t ah_div_int32(int32_t a, int32_t b, int32_t* result);
ah_extern ah_err_t ah_mul_int32(int32_t a, int32_t b, int32_t* result);
ah_extern ah_err_t ah_sub_int32(int32_t a, int32_t b, int32_t* result);

ah_extern ah_err_t ah_add_int64(int64_t a, int64_t b, int64_t* result);
ah_extern ah_err_t ah_div_int64(int64_t a, int64_t b, int64_t* result);
ah_extern ah_err_t ah_mul_int64(int64_t a, int64_t b, int64_t* result);
ah_extern ah_err_t ah_sub_int64(int64_t a, int64_t b, int64_t* result);

ah_extern ah_err_t ah_add_intptr(intptr_t a, intptr_t b, intptr_t* result);
ah_extern ah_err_t ah_div_intptr(intptr_t a, intptr_t b, intptr_t* result);
ah_extern ah_err_t ah_mul_intptr(intptr_t a, intptr_t b, intptr_t* result);
ah_extern ah_err_t ah_sub_intptr(intptr_t a, intptr_t b, intptr_t* result);

ah_extern ah_err_t ah_add_size(size_t a, size_t b, size_t* result);
ah_extern ah_err_t ah_div_size(size_t a, size_t b, size_t* result);
ah_extern ah_err_t ah_mul_size(size_t a, size_t b, size_t* result);
ah_extern ah_err_t ah_sub_size(size_t a, size_t b, size_t* result);

ah_extern ah_err_t ah_add_uint16(uint16_t a, uint16_t b, uint16_t* result);
ah_extern ah_err_t ah_div_uint16(uint16_t a, uint16_t b, uint16_t* result);
ah_extern ah_err_t ah_mul_uint16(uint16_t a, uint16_t b, uint16_t* result);
ah_extern ah_err_t ah_sub_uint16(uint16_t a, uint16_t b, uint16_t* result);

ah_extern ah_err_t ah_add_uint32(uint32_t a, uint32_t b, uint32_t* result);
ah_extern ah_err_t ah_div_uint32(uint32_t a, uint32_t b, uint32_t* result);
ah_extern ah_err_t ah_mul_uint32(uint32_t a, uint32_t b, uint32_t* result);
ah_extern ah_err_t ah_sub_uint32(uint32_t a, uint32_t b, uint32_t* result);

ah_extern ah_err_t ah_add_uint64(uint64_t a, uint64_t b, uint64_t* result);
ah_extern ah_err_t ah_div_uint64(uint64_t a, uint64_t b, uint64_t* result);
ah_extern ah_err_t ah_mul_uint64(uint64_t a, uint64_t b, uint64_t* result);
ah_extern ah_err_t ah_sub_uint64(uint64_t a, uint64_t b, uint64_t* result);

ah_extern ah_err_t ah_add_uintptr(uintptr_t a, uintptr_t b, uintptr_t* result);
ah_extern ah_err_t ah_div_uintptr(uintptr_t a, uintptr_t b, uintptr_t* result);
ah_extern ah_err_t ah_mul_uintptr(uintptr_t a, uintptr_t b, uintptr_t* result);
ah_extern ah_err_t ah_sub_uintptr(uintptr_t a, uintptr_t b, uintptr_t* result);

#endif
