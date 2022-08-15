// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_ASSERT_H_
#define AH_ASSERT_H_

/// \brief Assertion macros.
/// \file
///
/// Provides macros analogous to the C99 assert() macro. The key differences
/// being, however, that a variant exists that is not stripped when compiling
/// with \c -DNDEBUG and that the ah_abortf() is used to report the result of a
/// failed assertion.

#include "abort.h"
#include "intrin.h"

/// \brief Aborts application if \a expr evaluates to false.
///
/// \param expr Arbitrary expression.
///
/// \note Invocations of this macro will \e not be removed if compiling with
/// \c -DNDEBUG. If you do want certain of them to be removed in that case,
/// please use ah_assert_if_debug() instead.
///
/// \see ah_abort()
#define ah_assert(expr) (ah_likely((expr)) ? ((void) 0) : ah_abortf("%s:%d " #expr "\n", __FILE__, __LINE__))

#ifndef NDEBUG

/// \brief Aborts application if \a expr evaluates to false, unless the
/// application is compiled with \c -DNDEBUG.
///
/// \param expr Arbitrary expression.
///
/// \note Invocations of this macro \e will be removed if compiling with
/// \c -DNDEBUG. If you do not want certain them to be removed in that case,
/// please use ah_assert() instead.
///
/// \see ah_abort()
# define ah_assert_if_debug(expr) ah_assert(expr)

#else
# define ah_assert_if_debug(expr) ((void) 0)
#endif

#endif
