// SPDX-License-Identifier: EPL-2.0

#include "ah/time.h"
#include "ah/unit.h"

void s_should_return_non_zero_time(ah_unit_t* unit);

void test_time(ah_unit_t* unit)
{
    s_should_return_non_zero_time(unit);
}

void s_should_return_non_zero_time(ah_unit_t* unit)
{
    ah_time_t time = ah_time_now();
    ah_unit_assert(unit, !ah_time_is_zero(time), "current time must not be zero");
}
