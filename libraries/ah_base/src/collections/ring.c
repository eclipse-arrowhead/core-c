// SPDX-License-Identifier: EPL-2.0

#include "ah/internal/collections/ring.h"

#include "ah/err.h"

#include <string.h>

ah_err_t ah_i_ring_init(struct ah_i_ring* ring, size_t entry_capacity, size_t entry_size)
{
    ah_assert_if_debug(ring != NULL);
    ah_assert_if_debug(entry_size > 0u);

    if (entry_size > UINT16_MAX) {
        return AH_EDOM;
    }

    if (ah_math_add_size(entry_capacity, 1u, &entry_capacity) != AH_ENONE) {
        return AH_ENOMEM;
    }

    if (entry_capacity > UINT16_MAX) {
        return AH_EOVERFLOW;
    }

    size_t entry_capacity_in_bytes;
    if (ah_math_mul_size(entry_capacity, entry_size, &entry_capacity_in_bytes) != AH_ENONE) {
        return AH_ENOMEM;
    }

    ring->_entry_size = (uint16_t) entry_size;
    ring->_base = ah_malloc(entry_capacity_in_bytes);
    if (ring->_base == NULL) {
        return AH_ENOMEM;
    }

    ring->_offset_read = 0u;
    ring->_offset_write = 0u;
    ring->_capacity = (uint16_t) entry_capacity;

    return AH_ENONE;
}

void* ah_i_ring_alloc(struct ah_i_ring* ring)
{
    ah_assert_if_debug(ring != NULL);

    uint16_t offset_write = ring->_offset_write + 1u;
    if (offset_write == ring->_capacity) {
        offset_write = 0u;
    }

    if (ring->_offset_read == offset_write) {
        return NULL;
    }

    void* entry = &((uint8_t*) ring->_base)[ring->_offset_write * ring->_entry_size];
    ring->_offset_write = offset_write;

#ifndef NDEBUG
    memset(entry, 0, ring->_entry_size);
#endif

    return entry;
}

void* ah_i_ring_peek(struct ah_i_ring* ring)
{
    ah_assert_if_debug(ring != NULL);

    if (ring->_offset_read == ring->_offset_write) {
        return NULL;
    }

    return &((uint8_t*) ring->_base)[ring->_offset_read * ring->_entry_size];
}

void* ah_i_ring_pop(struct ah_i_ring* ring)
{
    ah_assert_if_debug(ring != NULL);

    if (ring->_offset_read == ring->_offset_write) {
        return NULL;
    }

    void* entry = &((uint8_t*) ring->_base)[ring->_offset_read * ring->_entry_size];

    uint16_t offset_read = ring->_offset_read + 1u;
    if (offset_read == ring->_capacity) {
        offset_read = 0u;
    }
    ring->_offset_read = offset_read;

    return entry;
}

void ah_i_ring_skip(struct ah_i_ring* ring)
{
    ah_assert_if_debug(ring != NULL);

    if (ring->_offset_read == ring->_offset_write) {
        return;
    }

    uint16_t offset_read = ring->_offset_read + 1u;
    if (offset_read == ring->_capacity) {
        offset_read = 0u;
    }
    ring->_offset_read = offset_read;
}

void ah_i_ring_term(struct ah_i_ring* ring)
{
    ah_assert_if_debug(ring != NULL);

    ah_free(ring->_base);
#ifndef NDEBUG
    memset(ring, 0, sizeof(struct ah_i_ring));
#endif
}
