// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_MATH_H_
#define AH_MATH_H_

#include "defs.h"

#include <stddef.h>
#include <stdint.h>

// All `add`, `div`, `mul` and `sub` functions return AH_ENONE if successful,
// AH_EINVAL if the `result` argument is NULL or AH_ERANGE if the operation
// overflowed. The signed `div` functions additionally return AH_EDOM of the `b`
// argument is zero.

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
