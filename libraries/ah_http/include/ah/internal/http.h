// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_HTTP_H_
#define AH_INTERNAL_HTTP_H_

#include <ah/alloc.h>
#include <ah/defs.h>
#include <ah/str.h>
#include <stddef.h>

#define AH_I_HTTP_CLIENT_FIELDS void* _user_data;

#define AH_I_HTTP_SERVER_FIELDS void* _user_data;

#define AH_I_HTTP_HMAP_FIELDS                                                                                          \
    uint16_t _mask;                                                                                                    \
    uint16_t _count;                                                                                                   \
    ah_str_t* _names;                                                                                                  \
    struct ah_i_http_hmap_value* _values;

#define AH_I_HTTP_HMAP_VALUE_ITER_FIELDS const struct ah_i_http_hmap_value* _value;

#define AH_I_HTTP_OBODY_FIELDS int _todo;

struct ah_i_http_hmap_value {
    ah_str_t _value;
    struct ah_i_http_hmap_value* _next_value_with_same_name;
};

#endif
