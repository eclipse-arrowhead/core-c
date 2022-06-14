// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/internal/collections/ring.h"

#include "ah/err.h"

#include <string.h>

static size_t s_get_capacity_in_bytes(const struct ah_i_ring* ring);

ah_err_t ah_i_ring_init(struct ah_i_ring* ring, size_t initial_entry_capacity, size_t entry_size)
{
    ah_assert_if_debug(ring != NULL);
    ah_assert_if_debug(entry_size > 0u);

    size_t initial_entry_capacity_in_bytes;
    if (ah_mul_size(initial_entry_capacity, entry_size, &initial_entry_capacity_in_bytes) != AH_ENONE) {
        return AH_ENOMEM;
    }

    ring->_offset_start = ah_malloc(initial_entry_capacity_in_bytes);
    if (ring->_offset_start == NULL) {
        return AH_ENOMEM;
    }

    ring->_offset_read = ring->_offset_start;
    ring->_offset_write = ring->_offset_start;
    ring->_offset_end = &((uint8_t*) ring->_offset_start)[initial_entry_capacity_in_bytes];

    return AH_ENONE;
}

void* ah_i_ring_alloc(struct ah_i_ring* ring)
{
    ah_assert_if_debug(ring != NULL);

    void* offset_write = &((uint8_t*) ring->_offset_write)[ring->_entry_size];
    if (offset_write == ring->_offset_end) {
        offset_write = ring->_offset_start;
    }

    if (ring->_offset_read == offset_write) {
        size_t capacity_in_bytes = s_get_capacity_in_bytes(ring);

        const size_t min_capacity_in_bytes = ring->_entry_size * 4u;
        if (capacity_in_bytes < min_capacity_in_bytes) {
            capacity_in_bytes = min_capacity_in_bytes;
        }
        else {
            if (ah_mul_size(capacity_in_bytes, 2u, &capacity_in_bytes) != AH_ENONE) {
                return NULL;
            }
        }

        void* entries = ah_malloc(capacity_in_bytes);
        if (entries == NULL) {
            return NULL;
        }

        uintptr_t size_of_entries_in_bytes;
        if (ring->_offset_read > ring->_offset_write) {
            size_t size_of_rhs_entries_in_bytes = ((uint8_t*) ring->_offset_end) - ((uint8_t*) ring->_offset_read);
            memcpy(entries, ring->_offset_read, size_of_rhs_entries_in_bytes);

            size_t size_of_lhs_entries_in_bytes = ((uint8_t*) ring->_offset_write) - ((uint8_t*) ring->_offset_start);
            memcpy(&((uint8_t*) entries)[size_of_rhs_entries_in_bytes], ring->_offset_start, size_of_lhs_entries_in_bytes);

            size_of_entries_in_bytes = size_of_lhs_entries_in_bytes + size_of_rhs_entries_in_bytes;
        }
        else {
            size_of_entries_in_bytes = ((uint8_t*) ring->_offset_write) - ((uint8_t*) ring->_offset_read);
            memcpy(entries, ring->_offset_read, size_of_entries_in_bytes);
        }

        ah_free(ring->_offset_start);

        ring->_offset_start = entries;
        ring->_offset_read = entries;
        ring->_offset_write = &((uint8_t*) entries)[size_of_entries_in_bytes];
        ring->_offset_end = &((uint8_t*) entries)[capacity_in_bytes];

        offset_write = &((uint8_t*) ring->_offset_write)[ring->_entry_size];
    }

    void* entry = ring->_offset_write;
    ring->_offset_write = offset_write;

    return entry;
}

static size_t s_get_capacity_in_bytes(const struct ah_i_ring* ring)
{
    ah_assert_if_debug(ring != NULL);

    return ((uint8_t*) ring->_offset_end) - ((uint8_t*) ring->_offset_start);
}

void* ah_i_ring_peek(struct ah_i_ring* ring)
{
    ah_assert_if_debug(ring != NULL);

    if (ring->_offset_read == ring->_offset_write) {
        return NULL;
    }

    return ring->_offset_read;
}

void ah_i_ring_skip(struct ah_i_ring* ring)
{
    ah_assert_if_debug(ring != NULL);

    if (ring->_offset_read == ring->_offset_write) {
        return;
    }

    void* offset_read = &((uint8_t*) ring->_offset_read)[ring->_entry_size];
    if (offset_read == ring->_offset_end) {
        offset_read = ring->_offset_start;
    }
}

void ah_i_ring_term(struct ah_i_ring* ring)
{
    ah_assert_if_debug(ring != NULL);

    ah_free(ring->_offset_start);
}
