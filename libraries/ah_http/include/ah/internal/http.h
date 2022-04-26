// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_HTTP_H_
#define AH_INTERNAL_HTTP_H_

#include <ah/alloc.h>
#include <ah/defs.h>
#include <stddef.h>

#define AH_I_HTTP_CLIENT_FIELDS int _todo;

#define AH_I_HTTP_SERVER_FIELDS int _todo;

#define AH_I_HTTP_IHEADERS_FIELDS                                                                                      \
    uint16_t _mask;                                                                                                    \
    uint16_t _count;                                                                                                   \
    const char** _names;                                                                                               \
    struct ah_i_http_iheader_value* _values;

#define AH_I_HTTP_IHEADERS_VALUES_FIELDS const struct ah_i_http_iheader_value* _value;

struct ah_http_iheaders;

struct ah_i_http_iheader_value {
    const char* _value;
    struct ah_i_http_iheader_value* _next_value_with_same_name;
};

ah_err_t ah_i_http_iheaders_init(struct ah_http_iheaders* headers, ah_alloc_cb alloc_cb, size_t capacity);
ah_err_t ah_i_http_iheaders_push(struct ah_http_iheaders* headers, const char* name, const char* value);

#endif
