// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_JSON_H_
#define AH_JSON_H_

#include <ah/buf.h>
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

typedef struct ah_json_buf ah_json_buf_t;
typedef struct ah_json_val ah_json_val_t;

struct ah_json_buf {
    size_t capacity;
    size_t length;

    // If NULL, memory will be allocated and reallocated dynamically by
    // ah_json_parse(). The `capacity` field is then treated as the desired
    // default capacity. If  `capacity` is zero an arbitrary default capacity
    // will be used.
    ah_json_val_t* values;
};

struct ah_json_val {
    const char* base;

#if UINTPTR_MAX == UINT32_MAX
# define AH_JSON_LENGTH_MAX (UINT32_C(0x001FFFFF))
# define AH_JSON_LEVEL_MAX  (0xFF)

    uint32_t type   : 3;
    uint32_t level  : 8;
    uint32_t length : 21;

#elif UINTPTR_MAX == UINT64_MAX
# define AH_JSON_LENGTH_MAX (UINT64_C(0x0000FFFFFFFFFFFF))
# define AH_JSON_LEVEL_MAX  (0x1FFF)

    uint64_t type   : 3;
    uint64_t level  : 13;
    uint64_t length : 48;

#else
# define AH_JSON_LENGTH_MAX (UINT32_MAX)
# define AH_JSON_LEVEL_MAX  (UINT16_MAX)

    uint16_t type;
    uint16_t level;
    uint32_t length;

#endif
};

ah_extern ah_err_t ah_json_parse(ah_buf_t src, ah_json_buf_t* dst);

// JSON numbers are compatible with snprintf, sscanf, strfromd, strtod, etc. as
// long as the set locale uses "." as radix character (which the default "C"
// locale does). You may use those functions to read and write JSON numbers.

ah_extern int ah_json_str_compare(const char* a, size_t a_length, const char* b, size_t b_length);
ah_extern ah_err_t ah_json_str_unescape(const char* src, size_t src_length, char* dst, size_t* dst_length);

#endif
