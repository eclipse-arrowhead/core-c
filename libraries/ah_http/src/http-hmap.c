// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include <ah/assert.h>
#include <ah/err.h>
#include <string.h>

static struct ah_i_http_hmap_value* s_get_value(const ah_http_hmap_t* headers, const char* name);
static uint32_t s_hash_header_name(const char* name);
static uint8_t s_to_lower(uint8_t ch);
static uint16_t s_to_mask(uint16_t capacity);

ah_extern ah_err_t ah_i_http_hmap_init(ah_http_hmap_t* headers, ah_alloc_cb alloc_cb, size_t capacity)
{
    ah_assert_if_debug(headers != NULL);
    ah_assert_if_debug(alloc_cb != NULL);

    if (capacity == 1u || capacity > UINT8_MAX + 1u) {
        return AH_EDOM;
    }

    uint16_t mask;
    const char** names;
    struct ah_i_http_hmap_value* values;

    mask = s_to_mask(capacity);

    names = ah_calloc(alloc_cb, mask + 1u, sizeof(char*));
    if (names == NULL) {
        return AH_ENOMEM;
    }

    values = ah_malloc_array(alloc_cb, mask + 1u, sizeof(struct ah_i_http_hmap_value));
    if (values == NULL) {
        ah_dealloc(alloc_cb, names);
        return AH_ENOMEM;
    }

    *headers = (ah_http_hmap_t) {
        ._mask = mask,
        ._count = 0u,
        ._names = names,
        ._values = values,
    };

    return AH_ENONE;
}

static uint16_t s_to_mask(const uint16_t capacity)
{
    ah_assert_if_debug(capacity != 1u);
    ah_assert_if_debug(capacity <= 256);

    if (capacity == 0u) {
        return 15u;
    }
    if (capacity >= 128u) {
        return 255u;
    }
    uint16_t v = capacity - 1u;
    v |= v >> 1u;
    v |= v >> 2u;
    v |= v >> 4u;
    return v;
}

ah_err_t ah_i_http_hmap_add(ah_http_hmap_t* headers, const char* name, const char* value)
{
    ah_assert_if_debug(headers != NULL);
    ah_assert_if_debug(name != NULL);
    ah_assert_if_debug(value != NULL);

    uint32_t hash = s_hash_header_name(name);

    struct ah_i_http_hmap_value* last_value = NULL;

    for (size_t i = 0u; i <= headers->_mask; i += 1u) {
        size_t index = (hash + i) & headers->_mask;
        const char* current_name = headers->_names[index];

        if (current_name == NULL) {
            headers->_count += 1u;
            headers->_names[index] = name;
            headers->_values[index] = (struct ah_i_http_hmap_value) {
                ._value = value,
                ._next_value_with_same_name = NULL,
            };
            if (last_value != NULL) {
                last_value->_next_value_with_same_name = &headers->_values[index];
            }
            return AH_ENONE;
        }

        if (strcasecmp(name, current_name) == 0) {
            last_value = &headers->_values[index];
        }
    }

    return AH_ENOBUFS;
}

// FNV-1a, 32-bit.
static uint32_t s_hash_header_name(const char* name)
{
    uint32_t hash = 2166136261;
    for (char ch; (ch = name[0u]) != '\0'; name = &name[1u]) {
        hash ^= s_to_lower(ch);
        hash *= 16777619;
    }
    return hash;
}

static uint8_t s_to_lower(uint8_t ch)
{
    return ch >= 'A' && ch <= 'Z' ? (ch | 0x20) : ch;
}

ah_err_t ah_i_http_hmap_add_if_not_exists(ah_http_hmap_t* headers, const char* name, const char* value)
{
    ah_assert_if_debug(headers != NULL);
    ah_assert_if_debug(name != NULL);
    ah_assert_if_debug(value != NULL);

    uint32_t hash = s_hash_header_name(name);

    for (size_t i = 0u; i <= headers->_mask; i += 1u) {
        size_t index = (hash + i) & headers->_mask;
        const char* current_name = headers->_names[index];

        if (current_name == NULL) {
            headers->_count += 1u;
            headers->_names[index] = name;
            headers->_values[index] = (struct ah_i_http_hmap_value) {
                ._value = value,
                ._next_value_with_same_name = NULL,
            };
            return AH_ENONE;
        }

        if (strcasecmp(name, current_name) == 0) {
            return AH_EEXIST;
        }
    }

    return AH_ENOBUFS;
}

void ah_i_http_hmap_term(ah_http_hmap_t* headers, ah_alloc_cb alloc_cb)
{
    ah_assert_if_debug(headers != NULL);
    ah_assert_if_debug(alloc_cb != NULL);

    ah_dealloc(alloc_cb, headers->_names);
    ah_dealloc(alloc_cb, headers->_values);

#ifndef NDEBUG
    *headers = (ah_http_hmap_t) { 0u };
#endif
}

ah_extern const char* ah_http_hmap_get_value(const ah_http_hmap_t* headers, const char* name, bool* has_next)
{
    ah_assert_if_debug(headers != NULL);
    ah_assert_if_debug(name != NULL);
    ah_assert_if_debug(has_next != NULL);

    struct ah_i_http_hmap_value* value = s_get_value(headers, name);
    if (value == NULL) {
        *has_next = false;
        return NULL;
    }

    if (value->_next_value_with_same_name != NULL) {
        *has_next = true;
        return NULL;
    }

    *has_next = false;
    return value->_value;
}

static struct ah_i_http_hmap_value* s_get_value(const ah_http_hmap_t* headers, const char* name)
{
    ah_assert_if_debug(headers != NULL);
    ah_assert_if_debug(name != NULL);

    uint32_t hash = s_hash_header_name(name);

    for (size_t i = 0u; i <= headers->_count; i += 1u) {
        size_t index = (hash + i) & headers->_mask;
        const char* current_name = headers->_names[index];

        if (current_name == NULL || strcasecmp(name, current_name) == 0) {
            return &headers->_values[index];
        }
    }

    return NULL;
}

ah_extern ah_http_hmap_value_iter_t ah_http_hmap_get_values(const ah_http_hmap_t* headers, const char* name)
{
    ah_assert_if_debug(headers != NULL);
    ah_assert_if_debug(name != NULL);

    ah_http_hmap_value_iter_t iter;
    iter._value = s_get_value(headers, name);
    return iter;
}

ah_extern const char* ah_http_hmap_next_value(ah_http_hmap_value_iter_t* iter)
{
    ah_assert_if_debug(iter != NULL);

    if (iter->_value == NULL) {
        return NULL;
    }

    const char* value = iter->_value->_value;

    if (iter->_value->_next_value_with_same_name != NULL) {
        iter->_value = iter->_value->_next_value_with_same_name;
    }
    else {
        iter->_value = NULL;
    }

    return value;
}
