// SPDX-License-Identifier: EPL-2.0

#ifndef AH_MATH_H_
#define AH_MATH_H_

/**
 * @file
 * Safe integer operations.
 *
 * This file provides a rather long list of functions that can be used to
 * ensure that certain integer operations never produce undefined behavior.
 */

#include "defs.h"

#include <stddef.h>
#include <stdint.h>

/**
 * @name Addition Functions
 * @{
 * Adds @a a to @a b and writes the result to @a result.
 *
 * @param a First addend.
 * @param b Second addend.
 * @param result Pointer to sum receiver.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE  - Operation successful.
 *   <li>@ref AH_EINVAL - @a result is @c NULL.
 *   <li>@ref AH_ERANGE - Operation overflowed.
 * </ul>
 */

ah_extern ah_err_t ah_add_int8(int8_t a, int8_t b, int8_t* result);
ah_extern ah_err_t ah_add_int16(int16_t a, int16_t b, int16_t* result);
ah_extern ah_err_t ah_add_int32(int32_t a, int32_t b, int32_t* result);
ah_extern ah_err_t ah_add_int64(int64_t a, int64_t b, int64_t* result);
ah_extern ah_err_t ah_add_intptr(intptr_t a, intptr_t b, intptr_t* result);
ah_extern ah_err_t ah_add_size(size_t a, size_t b, size_t* result);
ah_extern ah_err_t ah_add_uint8(uint8_t a, uint8_t b, uint8_t* result);
ah_extern ah_err_t ah_add_uint16(uint16_t a, uint16_t b, uint16_t* result);
ah_extern ah_err_t ah_add_uint32(uint32_t a, uint32_t b, uint32_t* result);
ah_extern ah_err_t ah_add_uint64(uint64_t a, uint64_t b, uint64_t* result);
ah_extern ah_err_t ah_add_uintptr(uintptr_t a, uintptr_t b, uintptr_t* result);

/** @} */

/**
 * @name Signed Division Functions
 * @{
 * Divides @a a by @a b and writes the result to @a result.
 *
 * @param a Dividend.
 * @param b Divisor.
 * @param result Pointer to quotient receiver.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE  - Operation successful.
 *   <li>@ref AH_EDOM   - @a b is @c 0.
 *   <li>@ref AH_EINVAL - @a result is @c NULL.
 *   <li>@ref AH_ERANGE - Operation result outside representable range.
 * </ul>
 */

ah_extern ah_err_t ah_div_int8(int8_t a, int8_t b, int8_t* result);
ah_extern ah_err_t ah_div_int16(int16_t a, int16_t b, int16_t* result);
ah_extern ah_err_t ah_div_int32(int32_t a, int32_t b, int32_t* result);
ah_extern ah_err_t ah_div_int64(int64_t a, int64_t b, int64_t* result);
ah_extern ah_err_t ah_div_intptr(intptr_t a, intptr_t b, intptr_t* result);

/** @} */

/**
 * @name Unsigned Division Functions
 * @{
 * Divides @a a by @a b and writes the result to @a result.
 *
 * @param a Dividend.
 * @param b Divisor.
 * @param result Pointer to quotient receiver.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE  - Operation successful.
 *   <li>@ref AH_EDOM   - @a b is @c 0.
 *   <li>@ref AH_EINVAL - @a result is @c NULL.
 * </ul>
 */

ah_extern ah_err_t ah_div_size(size_t a, size_t b, size_t* result);
ah_extern ah_err_t ah_div_uint8(uint8_t a, uint8_t b, uint8_t* result);
ah_extern ah_err_t ah_div_uint16(uint16_t a, uint16_t b, uint16_t* result);
ah_extern ah_err_t ah_div_uint32(uint32_t a, uint32_t b, uint32_t* result);
ah_extern ah_err_t ah_div_uint64(uint64_t a, uint64_t b, uint64_t* result);
ah_extern ah_err_t ah_div_uintptr(uintptr_t a, uintptr_t b, uintptr_t* result);

/** @} */

/**
 * @name Multiplication Functions
 * @{
 * Multiplies @a a by @a b and writes the result to @a result.
 *
 * @param a Multiplier.
 * @param b Multiplicand.
 * @param result Pointer to product receiver.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE  - Operation successful.
 *   <li>@ref AH_EINVAL - @a result is @c NULL.
 *   <li>@ref AH_ERANGE - Operation overflowed.
 * </ul>
 */

ah_extern ah_err_t ah_mul_int8(int8_t a, int8_t b, int8_t* result);
ah_extern ah_err_t ah_mul_int16(int16_t a, int16_t b, int16_t* result);
ah_extern ah_err_t ah_mul_int32(int32_t a, int32_t b, int32_t* result);
ah_extern ah_err_t ah_mul_int64(int64_t a, int64_t b, int64_t* result);
ah_extern ah_err_t ah_mul_intptr(intptr_t a, intptr_t b, intptr_t* result);
ah_extern ah_err_t ah_mul_size(size_t a, size_t b, size_t* result);
ah_extern ah_err_t ah_mul_uint8(uint8_t a, uint8_t b, uint8_t* result);
ah_extern ah_err_t ah_mul_uint16(uint16_t a, uint16_t b, uint16_t* result);
ah_extern ah_err_t ah_mul_uint32(uint32_t a, uint32_t b, uint32_t* result);
ah_extern ah_err_t ah_mul_uint64(uint64_t a, uint64_t b, uint64_t* result);
ah_extern ah_err_t ah_mul_uintptr(uintptr_t a, uintptr_t b, uintptr_t* result);

/** @} */

/**
 * @name Multiplication Functions
 * @{
 * Subtract @a a with @a b and writes the result to @a result.
 *
 * @param a Minuend.
 * @param b Subtrahend.
 * @param result Pointer to difference receiver.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE  - Operation successful.
 *   <li>@ref AH_EINVAL - @a result is @c NULL.
 *   <li>@ref AH_ERANGE - Operation overflowed.
 * </ul>
 */

ah_extern ah_err_t ah_sub_int8(int8_t a, int8_t b, int8_t* result);
ah_extern ah_err_t ah_sub_int16(int16_t a, int16_t b, int16_t* result);
ah_extern ah_err_t ah_sub_int32(int32_t a, int32_t b, int32_t* result);
ah_extern ah_err_t ah_sub_int64(int64_t a, int64_t b, int64_t* result);
ah_extern ah_err_t ah_sub_intptr(intptr_t a, intptr_t b, intptr_t* result);
ah_extern ah_err_t ah_sub_size(size_t a, size_t b, size_t* result);
ah_extern ah_err_t ah_sub_uint8(uint8_t a, uint8_t b, uint8_t* result);
ah_extern ah_err_t ah_sub_uint16(uint16_t a, uint16_t b, uint16_t* result);
ah_extern ah_err_t ah_sub_uint32(uint32_t a, uint32_t b, uint32_t* result);
ah_extern ah_err_t ah_sub_uint64(uint64_t a, uint64_t b, uint64_t* result);
ah_extern ah_err_t ah_sub_uintptr(uintptr_t a, uintptr_t b, uintptr_t* result);

/** @} */

#endif
