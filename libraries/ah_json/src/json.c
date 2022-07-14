// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/json.h"

#include <ah/err.h>

ah_extern int ah_json_str_compare(const char* a, size_t a_length, const char* b, size_t b_length)
{
    (void) a;
    (void) a_length;
    (void) b;
    (void) b_length;

    return -1;
}

ah_extern ah_err_t ah_json_str_unescape(const char* src, size_t src_length, char* dst, size_t* dst_length)
{
    (void) src;
    (void) src_length;
    (void) dst;
    (void) dst_length;

    return AH_EOPNOTSUPP;
}

ah_extern ah_err_t ah_json_parse(ah_buf_t src, ah_json_buf_t* dst)
{
    (void) src;
    (void) dst;

    return AH_EOPNOTSUPP;
}
