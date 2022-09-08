// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTRIN_H_
#define AH_INTRIN_H_

/**
 * Compiler intrinsics.
 * @file
 *
 * A compiler intrinsic is a special function provided by the compiler, causing
 * it to optimize or add to its output. This file provides two categories of
 * intrinsics, (1) such supported by all supported compilers and (2) those only
 * supported by some supported compilers. The former category are prefixed with
 * the usual "ah_", while the latter category have the slightly longer "ah_p_"
 * prefix.
 */

#include "defs.h"

#if defined(AH_DOXYGEN)

/**
 * Indicates that @a expr is most likely going to evaluate to @c true.
 *
 * @param expr Arbitrary expression.
 * @return Whatever @a expr returns.
 */
# define ah_likely(expr)

/**
 * Traps execution, preventing the application process from progressing any
 * further.
 *
 * Traps can be useful while debugging, or as a last resort when all other ways
 * of stopping the application fails.
 */
# define ah_trap()

/**
 * Indicates that @a expr is most likely going to evaluate to @c false.
 *
 * @param expr Arbitrary expression.
 * @return Whatever @a expr returns.
 */
# define ah_unlikely(expr)

/**
 * Informs the compiler that the line at which this intrinsic is used will never
 * be executed.
 *
 * @warning If the line is reached during execution anyway, the result is
 *          undefined. The platform @a may chose to ah_trap(), but that is not
 *          guaranteed.
 */
# define ah_unreachable()

/**
 * [Clang, GCC] Adds @a a and @a b, storing the sum to @a result.
 *
 * @param a Value of an arbitrary integer type.
 * @param b Value of an arbitrary integer type.
 * @param result Pointer to value of an arbitrary integer type.
 * @return @c true if the sum of @a a and @a b cannot be represented by
 *         @a result. @c false otherwise.
 */
# define ah_p_add_overflow(a, b, result)

/**
 * [Clang, GCC] Multiplties @a a and @a b, storing the product to @a result.
 *
 * @param a Value of an arbitrary integer type.
 * @param b Value of an arbitrary integer type.
 * @param result Pointer to value of an arbitrary integer type.
 * @return @c true if the product of @a a and @a b cannot be represented by
 *         @a result. @c false otherwise.
 */
# define ah_p_mul_overflow(a, b, result)

/**
 * [Clang, GCC] Subtracts @a a and @a b, storing the difference to @a result.
 *
 * @param a Value of an arbitrary integer type.
 * @param b Value of an arbitrary integer type.
 * @param result Pointer to value of an arbitrary integer type.
 * @return @c true if the difference of @a a and @a b cannot be represented by
 *         @a result. @c false otherwise.
 */
# define ah_p_sub_overflow(a, b, result)

#elif AH_VIA_CLANG || AH_VIA_GCC

# define ah_likely(expr)   __builtin_expect(!!(expr), 1)
# define ah_trap()         __builtin_trap()
# define ah_unlikely(expr) __builtin_expect(!!(expr), 0)
# define ah_unreachable()  __builtin_unreachable()

# define ah_p_add_overflow(a, b, result) __builtin_add_overflow((a), (b), (result))
# define ah_p_mul_overflow(a, b, result) __builtin_mul_overflow((a), (b), (result))
# define ah_p_sub_overflow(a, b, result) __builtin_sub_overflow((a), (b), (result))

#elif AH_VIA_MSVC
# pragma intrinsic(__debugbreak)

# define ah_likely(expr)   expr
# define ah_trap()         __debugbreak()
# define ah_unlikely(expr) expr
# define ah_unreachable()  __assume(0)

#endif

#endif
