// SPDX-License-Identifier: EPL-2.0

#include "ah/time.h"

#include <ah/unit.h>

void s_should_return_non_zero_time(ah_unit_res_t* res);

void test_time(ah_unit_res_t* res)
{
    s_should_return_non_zero_time(res);
}

void s_should_return_non_zero_time(ah_unit_res_t* res)
{
    ah_time_t time = ah_time_now();
    ah_unit_assert(AH_UNIT_CTX, res, !ah_time_is_zero(time), "current time must not be zero");
}
