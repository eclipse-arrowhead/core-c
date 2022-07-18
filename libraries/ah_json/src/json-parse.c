// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/json.h"

#include <ah/assert.h>
#include <ah/err.h>

ah_extern ah_err_t ah_json_parse(ah_buf_t src, ah_json_buf_t* dst)
{
    (void) src;
    (void) dst;

    return AH_EOPNOTSUPP;
}
