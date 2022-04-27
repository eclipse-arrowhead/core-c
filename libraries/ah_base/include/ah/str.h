// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_STR_H_
#define AH_STR_H_

#include "defs.h"
#include "internal/str.h"

#include <stdbool.h>
#include <string.h>

// A binary string of known length. May or may not be null-terminated. If the
// string is short enough, it is inlined. Values of this type are small enough
// to be efficiently passed by value (copy). Whoever uses them must ensure that
// the memory they refer to stay valid for their lifetimes.
union ah_str {
    AH_I_STR_FIELDS
};

ah_extern_inline ah_str_t ah_str_from(const void* str, size_t len)
{
    ah_str_t res = { ._as_any._len = len };

    if (len <= AH_I_STR_INL_BUF_SIZE) {
        memcpy(res._as_inl._buf, str, len);
    }
    else {
        res._as_ptr._ptr = str;
    }

    return res;
}

// `str` must be null-terminated.
ah_extern_inline ah_str_t ah_str_nt(char* str)
{
    return ah_str_from(str, strlen(str));
}

ah_extern_inline bool ah_str_is_inlined(const ah_str_t* str)
{
    return str->_as_any._len <= AH_I_STR_INL_BUF_SIZE;
}

ah_extern_inline size_t ah_str_len(const ah_str_t* str)
{
    return str->_as_any._len;
}

ah_extern_inline const char* ah_str_ptr(const ah_str_t* str)
{
    return ah_str_is_inlined(str) ? str->_as_inl._buf : str->_as_ptr._ptr;
}

ah_extern int ah_str_cmp(ah_str_t a, ah_str_t b);
ah_extern int ah_str_cmp_ignore_case_ascii(ah_str_t a, ah_str_t b);
ah_extern bool ah_str_eq(ah_str_t a, ah_str_t b);
ah_extern bool ah_str_eq_ignore_case_ascii(ah_str_t a, ah_str_t b);

#endif
