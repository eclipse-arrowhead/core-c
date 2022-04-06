// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_ASSERT_H_
#define AH_ASSERT_H_

#include <ah/abort.h>
#include <ah/defs.h>

#define ah_assert(expression)                                                                                          \
    (ah_likely((expression)) ? ((void) 0) : ah_abortf("%s:%d " #expression "\n", __FILE__, __LINE__))

#ifndef NDEBUG
#    define ah_assert_if_debug(expression) ah_assert(expression)
#else
#    define ah_assert_if_debug(expression) ((void) 0)
#endif

#endif
