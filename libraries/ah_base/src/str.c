// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/str.h"

static int s_to_lower_ascii(char ch);

ah_extern int ah_str_cmp(const ah_str_t a, const ah_str_t b)
{
    int diff_len;
    size_t len;

    if (ah_str_len(&a) > ah_str_len(&b)) {
        diff_len = 1;
        len = ah_str_len(&a) - ah_str_len(&b);
    }
    else if (ah_str_len(&a) == ah_str_len(&b)) {
        diff_len = 0;
        len = ah_str_len(&a);
    }
    else {
        diff_len = -1;
        len = ah_str_len(&b);
    }

    int diff_cmp = memcmp(ah_str_ptr(&a), ah_str_ptr(&b), len);
    if (diff_cmp != 0) {
        return diff_cmp;
    }

    return diff_len;
}

ah_extern int ah_str_cmp_ignore_case_ascii(ah_str_t a, ah_str_t b)
{
    size_t a_rem = ah_str_len(&a);
    size_t b_rem = ah_str_len(&b);

    const char* a_off = ah_str_ptr(&a);
    const char* b_off = ah_str_ptr(&b);

    for (;;) {
        if (a_rem == 0u) {
            return b_rem != 0u ? -1 : 0;
        }
        if (b_rem == 0u) {
            return 1;
        }

        int diff = s_to_lower_ascii(*a_off) - s_to_lower_ascii(*b_off);
        if (diff != 0) {
            return diff;
        }

        a_off = &a_off[1u];
        b_off = &b_off[1u];

        a_rem -= 1u;
        b_rem -= 1u;
    }
}

static int s_to_lower_ascii(char ch)
{
    return (ch >= 'A' && ch <= 'Z') ? (ch | 0x20) : ch;
}

ah_extern bool ah_str_eq(const ah_str_t a, const ah_str_t b)
{
    return ah_str_len(&a) == ah_str_len(&b) && memcmp(ah_str_ptr(&a), ah_str_ptr(&b), ah_str_len(&a)) == 0;
}

ah_extern bool ah_str_eq_ignore_case_ascii(ah_str_t a, ah_str_t b)
{
    size_t len = ah_str_len(&a);

    if (len != ah_str_len(&b)) {
        return false;
    }

    const char* a_off = ah_str_ptr(&a);
    const char* b_off = ah_str_ptr(&b);

    while (len != 0u) {
        if (s_to_lower_ascii(*a_off) != s_to_lower_ascii(*b_off)) {
            return false;
        }

        a_off = &a_off[1u];
        b_off = &b_off[1u];

        len -= 1u;
    }

    return true;
}
