// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_STR_H_
#define AH_INTERNAL_STR_H_

#include <stddef.h>

#define AH_I_STR_FIELDS                                                                                                \
    struct ah_i_str_any _as_any;                                                                                       \
    struct ah_i_str_ptr _as_ptr;                                                                                       \
    struct ah_i_str_inl _as_inl;

#define AH_I_STR_COMMON_FIELDS size_t _len;
#define AH_I_STR_INL_BUF_SIZE  sizeof(char*)

struct ah_i_str_any {
    AH_I_STR_COMMON_FIELDS
};

struct ah_i_str_ptr {
    AH_I_STR_COMMON_FIELDS
    const char* _ptr;
};

struct ah_i_str_inl {
    AH_I_STR_COMMON_FIELDS
    char _buf[AH_I_STR_INL_BUF_SIZE];
};

#endif
