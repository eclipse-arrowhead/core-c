// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/str.h"

ah_extern int ah_str_cmp(const ah_str_t* a, const ah_str_t* b)
{
    int diff_len;
    size_t len;

    if (a->_as_any._len > b->_as_any._len) {
        diff_len = 1;
        len = a->_as_any._len - b->_as_any._len;
    }
    else if (a->_as_any._len == b->_as_any._len) {
        diff_len = 0;
        len = a->_as_any._len;
    }
    else {
        diff_len = -1;
        len = b->_as_any._len;
    }

    int diff_cmp = memcmp(ah_str_ptr(a), ah_str_ptr(b), len);
    if (diff_cmp != 0) {
        return diff_cmp;
    }

    return diff_len;
}

ah_extern bool ah_str_eq(const ah_str_t* a, const ah_str_t* b)
{
    return a->_as_any._len == b->_as_any._len && memcmp(ah_str_ptr(a), ah_str_ptr(b), a->_as_any._len) == 0;
}
