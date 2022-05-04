// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include <ah/assert.h>
#include <ah/err.h>
#include <string.h>

static struct ah_i_http_hmap_header* s_find_header_by_name(const ah_http_hmap_t* hmap, ah_str_t name);
static uint32_t s_hash_header_name(ah_str_t name);
static uint8_t s_to_lower(uint8_t ch);

ah_extern ah_err_t ah_http_hmap_init(struct ah_http_hmap* hmap, struct ah_i_http_hmap_header* headers, size_t len)
{
    ah_assert_if_debug(hmap != NULL);
    ah_assert_if_debug(headers != NULL || len == 0u);

    // `len` must be a positive power of two no larger than 256.
    if (len == 0 || len > 256u || (len & (len - 1u)) != 0u) {
        return AH_EDOM;
    }

    *hmap = (ah_http_hmap_t) {
        ._mask = (uint16_t) len - 1u,
        ._count = 0u,
        ._headers = memset(headers, 0, sizeof(struct ah_i_http_hmap_header) * len),
    };

    return AH_ENONE;
}

ah_extern ah_err_t ah_http_hmap_add(ah_http_hmap_t* hmap, ah_str_t name, ah_str_t value)
{
    ah_assert_if_debug(hmap != NULL);

    uint32_t hash = s_hash_header_name(name);

    struct ah_i_http_hmap_header* last_header = NULL;

    for (size_t i = 0u; i <= hmap->_mask; i += 1u) {
        size_t index = (hash + i) & hmap->_mask;
        struct ah_i_http_hmap_header* header = &hmap->_headers[index];

        if (ah_str_get_len(&header->_name) == 0u) {
            hmap->_count += 1u;
            *header = (struct ah_i_http_hmap_header) {
                ._name = name,
                ._value = value,
                ._next_with_same_name = NULL,
            };
            if (last_header != NULL) {
                last_header->_next_with_same_name = header;
            }
            return AH_ENONE;
        }

        if (ah_str_eq_ignore_case_ascii(name, header->_name)) {
            last_header = header;
        }
    }

    return AH_ENOBUFS;
}

// FNV-1a, 32-bit.
static uint32_t s_hash_header_name(ah_str_t name)
{
    const char* str_ptr = ah_str_get_ptr(&name);
    uint32_t hash = 2166136261;
    for (size_t i = 0u; i < ah_str_get_len(&name); i += 1u) {
        hash ^= s_to_lower(str_ptr[i]);
        hash *= 16777619;
    }
    return hash;
}

static uint8_t s_to_lower(uint8_t ch)
{
    return ch >= 'A' && ch <= 'Z' ? (ch | 0x20) : ch;
}

ah_extern const ah_str_t* ah_http_hmap_get_value(const ah_http_hmap_t* headers, ah_str_t name, bool* has_next)
{
    ah_assert_if_debug(headers != NULL);
    ah_assert_if_debug(has_next != NULL);

    struct ah_i_http_hmap_header* header = s_find_header_by_name(headers, name);
    if (header == NULL) {
        *has_next = false;
        return NULL;
    }

    if (header->_next_with_same_name != NULL) {
        *has_next = true;
        return NULL;
    }

    *has_next = false;
    return &header->_value;
}

static struct ah_i_http_hmap_header* s_find_header_by_name(const ah_http_hmap_t* hmap, ah_str_t name)
{
    ah_assert_if_debug(hmap != NULL);

    uint32_t hash = s_hash_header_name(name);

    for (size_t i = 0u; i < hmap->_count; i += 1u) {
        size_t index = (hash + i) & hmap->_mask;
        struct ah_i_http_hmap_header* header = &hmap->_headers[index];

        if (ah_str_get_len(&header->_name) == 0u) {
            break;
        }
        if (ah_str_eq_ignore_case_ascii(name, header->_name)) {
            return header;
        }
    }

    return NULL;
}

ah_extern ah_http_hmap_value_iter_t ah_http_hmap_get_values(const ah_http_hmap_t* headers, ah_str_t name)
{
    ah_assert_if_debug(headers != NULL);

    ah_http_hmap_value_iter_t iter;
    iter._header = s_find_header_by_name(headers, name);
    return iter;
}

ah_extern const ah_str_t* ah_http_hmap_next_value(ah_http_hmap_value_iter_t* iter)
{
    ah_assert_if_debug(iter != NULL);

    if (iter->_header == NULL) {
        return NULL;
    }

    const ah_str_t* value = &iter->_header->_value;
    iter->_header = iter->_header->_next_with_same_name;
    return value;
}
