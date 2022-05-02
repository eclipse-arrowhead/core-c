// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/err.h"

#include "ah/unit.h"

static void s_should_never_return_null_when_calling_strerror(ah_unit_t* unit);

void test_err(ah_unit_t* unit)
{
    s_should_never_return_null_when_calling_strerror(unit);
}

static void s_should_never_return_null_when_calling_strerror(ah_unit_t* unit)
{
    for (int i = -100; i < 100; ++i) {
        (void) ah_unit_assertf(unit, ah_strerror(i) != NULL, "ah_strerror(%d) == NULL", i);
    }
}
