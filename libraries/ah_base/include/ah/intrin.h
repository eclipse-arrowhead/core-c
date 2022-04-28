// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTRIN_H_
#define AH_INTRIN_H_

#include "defs.h"

#if AH_VIA_CLANG || AH_VIA_GCC
#    define ah_likely(expr)   __builtin_expect(!!(expr), 1)
#    define ah_trap()         __builtin_trap()
#    define ah_unlikely(expr) __builtin_expect(!!(expr), 0)
#    define ah_unreachable()  __builtin_unreachable()

#    define ah_p_add_overflow(a, b, result) __builtin_add_overflow((a), (b), (result))
#    define ah_p_mul_overflow(a, b, result) __builtin_mul_overflow((a), (b), (result))
#    define ah_p_sub_overflow(a, b, result) __builtin_sub_overflow((a), (b), (result))
#elif AH_VIA_MSVC
#    pragma intrinsic(__debugbreak)

#    define ah_likely(expr)   expr
#    define ah_trap()         __debugbreak()
#    define ah_unlikely(expr) expr
#    define ah_unreachable()  __assume(0)
#endif

#endif
