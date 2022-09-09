// SPDX-License-Identifier: EPL-2.0

#include "ah/math.h"

#include "ah/err.h"
#include "ah/intrin.h"

#if AH_IS_WIN32
# define ENABLE_INTSAFE_SIGNED_FUNCTIONS
# include <intsafe.h>
#endif

#if defined(ah_p_add_overflow)
# define S_ADD_INT8(a, b, result)    ah_p_add_overflow((a), (b), (result))
# define S_ADD_INT16(a, b, result)   ah_p_add_overflow((a), (b), (result))
# define S_ADD_INT32(a, b, result)   ah_p_add_overflow((a), (b), (result))
# define S_ADD_INT64(a, b, result)   ah_p_add_overflow((a), (b), (result))
# define S_ADD_INTPTR(a, b, result)  ah_p_add_overflow((a), (b), (result))
# define S_ADD_SIZE(a, b, result)    ah_p_add_overflow((a), (b), (result))
# define S_ADD_UINT8(a, b, result)   ah_p_add_overflow((a), (b), (result))
# define S_ADD_UINT16(a, b, result)  ah_p_add_overflow((a), (b), (result))
# define S_ADD_UINT32(a, b, result)  ah_p_add_overflow((a), (b), (result))
# define S_ADD_UINT64(a, b, result)  ah_p_add_overflow((a), (b), (result))
# define S_ADD_UINTPTR(a, b, result) ah_p_add_overflow((a), (b), (result))
#elif AH_IS_WIN32
# define S_ADD_INT8(a, b, result)    FAILED(Int8Add((a), (b), (result)))
# define S_ADD_INT16(a, b, result)   FAILED(Int16Add((a), (b), (result)))
# define S_ADD_INT32(a, b, result)   FAILED(Int32Add((a), (b), (result)))
# define S_ADD_INT64(a, b, result)   FAILED(Int64Add((a), (b), (result)))
# define S_ADD_INTPTR(a, b, result)  FAILED(IntPtrAdd((a), (b), (result)))
# define S_ADD_SIZE(a, b, result)    FAILED(SizeTAdd((a), (b), (result)))
# define S_ADD_UINT8(a, b, result)   FAILED(UInt8Add((a), (b), (result)))
# define S_ADD_UINT16(a, b, result)  FAILED(UInt16Add((a), (b), (result)))
# define S_ADD_UINT32(a, b, result)  FAILED(UInt32Add((a), (b), (result)))
# define S_ADD_UINT64(a, b, result)  FAILED(UInt64Add((a), (b), (result)))
# define S_ADD_UINTPTR(a, b, result) FAILED(UIntPtrAdd((a), (b), (result)))
#endif

#if defined(ah_p_mul_overflow)
# define S_MUL_INT8(a, b, result)    ah_p_mul_overflow((a), (b), (result))
# define S_MUL_INT16(a, b, result)   ah_p_mul_overflow((a), (b), (result))
# define S_MUL_INT32(a, b, result)   ah_p_mul_overflow((a), (b), (result))
# define S_MUL_INT64(a, b, result)   ah_p_mul_overflow((a), (b), (result))
# define S_MUL_INTPTR(a, b, result)  ah_p_mul_overflow((a), (b), (result))
# define S_MUL_SIZE(a, b, result)    ah_p_mul_overflow((a), (b), (result))
# define S_MUL_UINT8(a, b, result)   ah_p_mul_overflow((a), (b), (result))
# define S_MUL_UINT16(a, b, result)  ah_p_mul_overflow((a), (b), (result))
# define S_MUL_UINT32(a, b, result)  ah_p_mul_overflow((a), (b), (result))
# define S_MUL_UINT64(a, b, result)  ah_p_mul_overflow((a), (b), (result))
# define S_MUL_UINTPTR(a, b, result) ah_p_mul_overflow((a), (b), (result))
#elif AH_IS_WIN32
# define S_MUL_INT8(a, b, result)    FAILED(Int8Mult((a), (b), (result)))
# define S_MUL_INT16(a, b, result)   FAILED(Int16Mult((a), (b), (result)))
# define S_MUL_INT32(a, b, result)   FAILED(Int32Mult((a), (b), (result)))
# define S_MUL_INT64(a, b, result)   FAILED(Int64Mult((a), (b), (result)))
# define S_MUL_INTPTR(a, b, result)  FAILED(IntPtrMult((a), (b), (result)))
# define S_MUL_SIZE(a, b, result)    FAILED(SizeTMult((a), (b), (result)))
# define S_MUL_UINT8(a, b, result)   FAILED(UInt8Mult((a), (b), (result)))
# define S_MUL_UINT16(a, b, result)  FAILED(UInt16Mult((a), (b), (result)))
# define S_MUL_UINT32(a, b, result)  FAILED(UInt32Mult((a), (b), (result)))
# define S_MUL_UINT64(a, b, result)  FAILED(UInt64Mult((a), (b), (result)))
# define S_MUL_UINTPTR(a, b, result) FAILED(UIntPtrMult((a), (b), (result)))
#endif

#if defined(ah_p_sub_overflow)
# define S_SUB_INT8(a, b, result)    ah_p_sub_overflow((a), (b), (result))
# define S_SUB_INT16(a, b, result)   ah_p_sub_overflow((a), (b), (result))
# define S_SUB_INT32(a, b, result)   ah_p_sub_overflow((a), (b), (result))
# define S_SUB_INT64(a, b, result)   ah_p_sub_overflow((a), (b), (result))
# define S_SUB_INTPTR(a, b, result)  ah_p_sub_overflow((a), (b), (result))
# define S_SUB_SIZE(a, b, result)    ah_p_sub_overflow((a), (b), (result))
# define S_SUB_UINT8(a, b, result)   ah_p_sub_overflow((a), (b), (result))
# define S_SUB_UINT16(a, b, result)  ah_p_sub_overflow((a), (b), (result))
# define S_SUB_UINT32(a, b, result)  ah_p_sub_overflow((a), (b), (result))
# define S_SUB_UINT64(a, b, result)  ah_p_sub_overflow((a), (b), (result))
# define S_SUB_UINTPTR(a, b, result) ah_p_sub_overflow((a), (b), (result))
#elif AH_IS_WIN32
# define S_SUB_INT8(a, b, result)    FAILED(Int8Sub((a), (b), (result)))
# define S_SUB_INT16(a, b, result)   FAILED(Int16Sub((a), (b), (result)))
# define S_SUB_INT32(a, b, result)   FAILED(Int32Sub((a), (b), (result)))
# define S_SUB_INT64(a, b, result)   FAILED(Int64Sub((a), (b), (result)))
# define S_SUB_INTPTR(a, b, result)  FAILED(IntPtrSub((a), (b), (result)))
# define S_SUB_SIZE(a, b, result)    FAILED(SizeTSub((a), (b), (result)))
# define S_SUB_UINT8(a, b, result)   FAILED(UInt8Sub((a), (b), (result)))
# define S_SUB_UINT16(a, b, result)  FAILED(UInt16Sub((a), (b), (result)))
# define S_SUB_UINT32(a, b, result)  FAILED(UInt32Sub((a), (b), (result)))
# define S_SUB_UINT64(a, b, result)  FAILED(UInt64Sub((a), (b), (result)))
# define S_SUB_UINTPTR(a, b, result) FAILED(UIntPtrSub((a), (b), (result)))
#endif

#define S_GEN(NAME, TYPE, FN)                                      \
 ah_extern ah_err_t NAME(const TYPE a, const TYPE b, TYPE* result) \
 {                                                                 \
  if (result == NULL) {                                            \
   return AH_EINVAL;                                               \
  }                                                                \
                                                                   \
  TYPE tmp = 0;                                                    \
  if (FN(a, b, &tmp)) {                                            \
   return AH_ERANGE;                                               \
  }                                                                \
  *result = tmp;                                                   \
                                                                   \
  return AH_ENONE;                                                 \
 }

#define S_GEN_DIV_SIGNED(NAME, TYPE, TYPE_MIN)                     \
 ah_extern ah_err_t NAME(const TYPE a, const TYPE b, TYPE* result) \
 {                                                                 \
  if (result == NULL) {                                            \
   return AH_EINVAL;                                               \
  }                                                                \
  if (b == 0) {                                                    \
   return AH_EDOM;                                                 \
  }                                                                \
  if (a == TYPE_MIN && b == -1) {                                  \
   return AH_ERANGE;                                               \
  }                                                                \
  *result = a / b;                                                 \
  return AH_ENONE;                                                 \
 }

#define S_GEN_DIV_UNSIGNED(NAME, TYPE)                             \
 ah_extern ah_err_t NAME(const TYPE a, const TYPE b, TYPE* result) \
 {                                                                 \
  if (result == NULL) {                                            \
   return AH_EINVAL;                                               \
  }                                                                \
  if (b == 0) {                                                    \
   return AH_EDOM;                                                 \
  }                                                                \
  *result = a / b;                                                 \
  return AH_ENONE;                                                 \
 }

S_GEN(ah_math_add_int8, int8_t, S_ADD_INT8)
S_GEN(ah_math_add_int16, int16_t, S_ADD_INT16)
S_GEN(ah_math_add_int32, int32_t, S_ADD_INT32)
S_GEN(ah_math_add_int64, int64_t, S_ADD_INT64)
S_GEN(ah_math_add_intptr, intptr_t, S_ADD_INTPTR)
S_GEN(ah_math_add_size, size_t, S_ADD_SIZE)
S_GEN(ah_math_add_uint8, uint8_t, S_ADD_UINT8)
S_GEN(ah_math_add_uint16, uint16_t, S_ADD_UINT16)
S_GEN(ah_math_add_uint32, uint32_t, S_ADD_UINT32)
S_GEN(ah_math_add_uint64, uint64_t, S_ADD_UINT64)
S_GEN(ah_math_add_uintptr, uintptr_t, S_ADD_UINTPTR)

S_GEN_DIV_SIGNED(ah_math_div_int8, int8_t, INT8_MIN)
S_GEN_DIV_SIGNED(ah_math_div_int16, int16_t, INT16_MIN)
S_GEN_DIV_SIGNED(ah_math_div_int32, int32_t, INT32_MIN)
S_GEN_DIV_SIGNED(ah_math_div_int64, int64_t, INT64_MIN)
S_GEN_DIV_SIGNED(ah_math_div_intptr, intptr_t, INTPTR_MIN)

S_GEN_DIV_UNSIGNED(ah_math_div_size, size_t)
S_GEN_DIV_UNSIGNED(ah_math_div_uint8, uint8_t)
S_GEN_DIV_UNSIGNED(ah_math_div_uint16, uint16_t)
S_GEN_DIV_UNSIGNED(ah_math_div_uint32, uint32_t)
S_GEN_DIV_UNSIGNED(ah_math_div_uint64, uint64_t)
S_GEN_DIV_UNSIGNED(ah_math_div_uintptr, uintptr_t)

S_GEN(ah_math_mul_int8, int8_t, S_MUL_INT8)
S_GEN(ah_math_mul_int16, int16_t, S_MUL_INT16)
S_GEN(ah_math_mul_int32, int32_t, S_MUL_INT32)
S_GEN(ah_math_mul_int64, int64_t, S_MUL_INT64)
S_GEN(ah_math_mul_intptr, intptr_t, S_MUL_INTPTR)
S_GEN(ah_math_mul_size, size_t, S_MUL_SIZE)
S_GEN(ah_math_mul_uint8, uint8_t, S_MUL_UINT8)
S_GEN(ah_math_mul_uint16, uint16_t, S_MUL_UINT16)
S_GEN(ah_math_mul_uint32, uint32_t, S_MUL_UINT32)
S_GEN(ah_math_mul_uint64, uint64_t, S_MUL_UINT64)
S_GEN(ah_math_mul_uintptr, uintptr_t, S_MUL_UINTPTR)

S_GEN(ah_math_sub_int8, int8_t, S_SUB_INT8)
S_GEN(ah_math_sub_int16, int16_t, S_SUB_INT16)
S_GEN(ah_math_sub_int32, int32_t, S_SUB_INT32)
S_GEN(ah_math_sub_int64, int64_t, S_SUB_INT64)
S_GEN(ah_math_sub_intptr, intptr_t, S_SUB_INTPTR)
S_GEN(ah_math_sub_size, size_t, S_SUB_SIZE)
S_GEN(ah_math_sub_uint8, uint8_t, S_SUB_UINT8)
S_GEN(ah_math_sub_uint16, uint16_t, S_SUB_UINT16)
S_GEN(ah_math_sub_uint32, uint32_t, S_SUB_UINT32)
S_GEN(ah_math_sub_uint64, uint64_t, S_SUB_UINT64)
S_GEN(ah_math_sub_uintptr, uintptr_t, S_SUB_UINTPTR)
