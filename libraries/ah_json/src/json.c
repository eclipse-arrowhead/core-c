// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/json.h"

ah_extern void ah_json_escape(const char* src, size_t src_length, char* dst, size_t dst_length)
{
        (void) src;
        (void) src_length;
        (void) dst;
        (void) dst_length;
}

ah_extern int ah_json_strcmp(const char* a, size_t a_length, const char* b, size_t b_length)
{
        (void) a;
        (void) a_length;
        (void) b;
        (void) b_length;

        return -1;
}

ah_extern void* ah_json_parse(void* src, size_t size, void* user_data, ah_json_cb_t cb)
{
    (void) src;
    (void) size;
    (void) user_data;
    (void) cb;

    return NULL;
}
