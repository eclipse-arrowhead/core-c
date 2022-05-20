// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/time.h"

#include "ah/math.h"

ah_extern ah_err_t ah_timediff_add(ah_timediff_t a, ah_timediff_t b, ah_timediff_t* result)
{
    return ah_add_int64(a, b, result);
}

ah_extern ah_err_t ah_timediff_div(ah_timediff_t a, ah_timediff_t b, ah_timediff_t* result)
{
    return ah_div_int64(a, b, result);
}

ah_extern ah_err_t ah_timediff_mul(ah_timediff_t a, ah_timediff_t b, ah_timediff_t* result)
{
    return ah_mul_int64(a, b, result);
}

ah_extern ah_err_t ah_timediff_sub(ah_timediff_t a, ah_timediff_t b, ah_timediff_t* result)
{
    return ah_sub_int64(a, b, result);
}
