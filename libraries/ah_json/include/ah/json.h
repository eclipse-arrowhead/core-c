// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_JSON_H_
#define AH_JSON_H_

#include <ah/defs.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define AH_JSON_TYPE_ERROR  0u
#define AH_JSON_TYPE_OBJECT 1u
#define AH_JSON_TYPE_ARRAY  2u
#define AH_JSON_TYPE_STRING 3u
#define AH_JSON_TYPE_NUMBER 4u
#define AH_JSON_TYPE_TRUE   5u
#define AH_JSON_TYPE_FALSE  6u
#define AH_JSON_TYPE_NULL   7u

typedef void* (*ah_json_cb_t)(const char* base, size_t length, unsigned type, unsigned level, void* user_data);

ah_extern void ah_json_escape(const char* src, size_t src_length, char* dst, size_t dst_length);
ah_extern int ah_json_strcmp(const char* a, size_t a_length, const char* b, size_t b_length);
ah_extern void* ah_json_parse(void* src, size_t size, void* user_data, ah_json_cb_t cb);

// [ 1, 2, 3, 4, [ 5, 6, [ 7 ] ], 8, 9]
// 0 1  1  1  1  1 2  2  2 3      1  1

// { "a": 1, "b": { "c": 3 }, "d": 4 }
// 0  1   1   1   1  2   2     1   1

#endif
