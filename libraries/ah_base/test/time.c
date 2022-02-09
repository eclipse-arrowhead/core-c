// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/time.h"

#include "ah/unit.h"

void s_should_return_non_zero_time(struct ah_unit* unit);

void test_time(struct ah_unit* unit)
{
    s_should_return_non_zero_time(unit);
}

// A primary point of this test is to ensure that ah_time_now() does not raise
// the SIGABRT signal, which it only should if it cannot determine the current
// time.
void s_should_return_non_zero_time(struct ah_unit* unit)
{
    struct ah_time time = ah_time_now();
    ah_unit_assert(unit, !ah_time_is_zero(time), "current time must not be zero");
}
