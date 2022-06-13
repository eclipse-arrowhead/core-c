// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/internal/collections/slab.h"

#include "ah/alloc.h"
#include "ah/assert.h"
#include "ah/err.h"

#include <stdbool.h>

#define S_CACHE_SLOT_CAPACITY_IN_BYTES (AH_PSIZE - offsetof(struct ah_i_slab_cache, _slots_as_raw_bytes))

bool s_try_grow(struct ah_i_slab* slab);

ah_err_t ah_i_slab_init(struct ah_i_slab* slab, size_t initial_slot_capacity, size_t slot_data_size)
{
    ah_assert_if_debug(slab != NULL);
    ah_assert_if_debug(slot_data_size != 0u && slot_data_size <= (SIZE_MAX - offsetof(struct ah_i_slab_slot, _entry)));

    const size_t slot_size = slot_data_size + offsetof(struct ah_i_slab_slot, _entry);
    const size_t cache_slot_capacity = S_CACHE_SLOT_CAPACITY_IN_BYTES / slot_size;

    *slab = (struct ah_i_slab) {
        ._cache_slot_capacity = cache_slot_capacity,
        ._slot_size = slot_size,
    };

    while (initial_slot_capacity > 0u) {
        if (!s_try_grow(slab)) {
            ah_i_slab_term(slab, 0);
            return AH_ENOMEM;
        }
        if (ah_sub_size(initial_slot_capacity, cache_slot_capacity, &initial_slot_capacity) != AH_ENONE) {
            break;
        }
    }

    return AH_ENONE;
}

bool s_try_grow(struct ah_i_slab* slab)
{
    ah_assert_if_debug(slab != NULL);

    struct ah_i_slab_cache* cache = ah_palloc();
    if (cache == NULL) {
        return false;
    }

    for (size_t i = 1u; i < slab->_cache_slot_capacity; i += 1u) {
        size_t byte_off = i * slab->_slot_size;
        struct ah_i_slab_slot* prev = ((struct ah_i_slab_slot*) &cache->_slots_as_raw_bytes[byte_off - slab->_slot_size]);
        struct ah_i_slab_slot* cur = (struct ah_i_slab_slot*) &cache->_slots_as_raw_bytes[byte_off];
        prev->_next_free = cur;
    }

    struct ah_i_slab_slot* last = ((struct ah_i_slab_slot*) &cache->_slots_as_raw_bytes[(slab->_cache_slot_capacity - 1u) * slab->_slot_size]);
    if (slab->_cache_list != NULL) {
        last->_next_free = (struct ah_i_slab_slot*) &slab->_cache_list->_slots_as_raw_bytes[0u];
    }
    else {
        last->_next_free = NULL;
    }

    cache->_next = slab->_cache_list;

    slab->_cache_list = cache;
    slab->_free_list = (struct ah_i_slab_slot*) &cache->_slots_as_raw_bytes[0u];

    return true;
}

void* ah_i_slab_alloc(struct ah_i_slab* slab)
{
    ah_assert_if_debug(slab != NULL);

    struct ah_i_slab_slot* slot = slab->_free_list;
    if (slot == NULL) {
        if (!s_try_grow(slab)) {
            return NULL;
        }
        slot = slab->_free_list;
    }

    slab->_free_list = slot->_next_free;
    slot->_next_free = NULL;

    return slot->_entry;
}

void ah_i_slab_free(struct ah_i_slab* slab, void* entry)
{
    ah_assert_if_debug(slab != NULL);
    ah_assert_if_debug(entry != NULL);

    struct ah_i_slab_slot* slot = (struct ah_i_slab_slot*) &((unsigned char*) entry)[-((ptrdiff_t) offsetof(struct ah_i_slab_slot, _entry))];
    ah_assert_if_debug(slot->_next_free == NULL);

    slot->_next_free = slab->_free_list;
    slab->_free_list = slot;
}

void ah_i_slab_term(struct ah_i_slab* slab, void (*allocated_entry_cb)(void*))
{
    ah_assert_if_debug(slab != NULL);

    if (allocated_entry_cb != NULL) {
        // Mark each free slot by setting its free pointer to an invalid (unaligned) address.
        for (struct ah_i_slab_slot *next, *slot = slab->_free_list; slot != NULL; slot = next) {
            next = slot->_next_free;
            slot->_next_free = (struct ah_i_slab_slot*) 1u;
        }

        // Sweep through all slots, providing those with unmarked free pointers to the callback.
        for (struct ah_i_slab_cache* cache = slab->_cache_list; cache != NULL; cache = cache->_next) {
            for (size_t i = 0u; i < slab->_cache_slot_capacity; i += 1u) {
                struct ah_i_slab_slot* slot = (struct ah_i_slab_slot*) &cache->_slots_as_raw_bytes[i * slab->_slot_size];
                if (slot->_next_free != (struct ah_i_slab_slot*) 1u) {
                    allocated_entry_cb(slot->_entry);
                }
#ifndef NDEBUG
                else {
                    slot->_next_free = NULL;
                }
#endif
            }
        }
    }

    struct ah_i_slab_cache* current = slab->_cache_list;
    while (current != NULL) {
        struct ah_i_slab_cache* next = current->_next;
        ah_pfree(current);
        current = next;
    }
}
