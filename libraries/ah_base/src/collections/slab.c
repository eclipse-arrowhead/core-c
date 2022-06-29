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
#ifndef NDEBUG
# include <string.h>
#endif

#define S_CACHE_SLOT_CAPACITY_IN_BYTES (AH_PSIZE - sizeof(struct ah_i_slab_cache))

static struct ah_i_slab_slot* s_cache_get_slot(struct ah_i_slab_cache* cache, size_t index, size_t slot_size);
static struct ah_i_slab_slot* s_entry_get_slot(void* entry);
static bool s_slab_is_full(struct ah_i_slab* slab);
static bool s_slab_try_grow(struct ah_i_slab* slab);
static void* s_slot_get_entry(struct ah_i_slab_slot* slot);

ah_err_t ah_i_slab_init(struct ah_i_slab* slab, size_t initial_slot_capacity, size_t slot_data_size)
{
    ah_assert_if_debug(slab != NULL);
    ah_assert_if_debug(slot_data_size != 0u && slot_data_size <= (SIZE_MAX - sizeof(struct ah_i_slab_slot)));

    size_t slot_size = slot_data_size + sizeof(struct ah_i_slab_slot);

    // Round up slot_size to the nearest multiple of the platform pointer size.
    slot_size = slot_size + (sizeof(uintptr_t) - slot_size % sizeof(uintptr_t));

    const size_t cache_slot_capacity = S_CACHE_SLOT_CAPACITY_IN_BYTES / slot_size;
    if (cache_slot_capacity == 0u || cache_slot_capacity > AH_PSIZE) {
        return AH_EOVERFLOW;
    }

    *slab = (struct ah_i_slab) {
        ._cache_slot_capacity = cache_slot_capacity,
        ._slot_size = slot_size,
    };

    while (initial_slot_capacity > 0u) {
        if (!s_slab_try_grow(slab)) {
            ah_i_slab_term(slab, 0);
            return AH_ENOMEM;
        }
        if (ah_sub_size(initial_slot_capacity, cache_slot_capacity, &initial_slot_capacity) != AH_ENONE) {
            break;
        }
    }

    return AH_ENONE;
}

static bool s_slab_try_grow(struct ah_i_slab* slab)
{
    ah_assert_if_debug(slab != NULL);

    struct ah_i_slab_cache* cache = ah_palloc();
    if (cache == NULL) {
        return false;
    }

    for (size_t i = 1u; i < slab->_cache_slot_capacity; i += 1u) {
        s_cache_get_slot(cache, i - 1u, slab->_slot_size)->_next_free = s_cache_get_slot(cache, i, slab->_slot_size);
    }

    struct ah_i_slab_slot* last = s_cache_get_slot(cache, slab->_cache_slot_capacity - 1u, slab->_slot_size);
    if (slab->_cache_list != NULL) {
        last->_next_free = s_cache_get_slot(slab->_cache_list, 0u, slab->_slot_size);
    }
    else {
        last->_next_free = NULL;
    }

    cache->_next = slab->_cache_list;

    slab->_cache_list = cache;
    slab->_free_list = s_cache_get_slot(cache, 0u, slab->_slot_size);

    return true;
}

static struct ah_i_slab_slot* s_cache_get_slot(struct ah_i_slab_cache* cache, size_t index, size_t slot_size)
{
    ah_assert_if_debug(cache != NULL);
    ah_assert_if_debug(slot_size != 0u);
    ah_assert_if_debug(index < (S_CACHE_SLOT_CAPACITY_IN_BYTES / slot_size));

    uint8_t* base = &((uint8_t*) cache)[sizeof(struct ah_i_slab_cache)];

    return (struct ah_i_slab_slot*) &base[index * slot_size];
}

void* ah_i_slab_alloc(struct ah_i_slab* slab)
{
    ah_assert_if_debug(slab != NULL);

    if (s_slab_is_full(slab)) {
        if (!s_slab_try_grow(slab)) {
            return NULL;
        }
    }
    struct ah_i_slab_slot* slot = slab->_free_list;

    slab->_free_list = slot->_next_free;
#ifndef NDEBUG
    slot->_next_free = NULL;
#endif

    return s_slot_get_entry(slot);
}

static bool s_slab_is_full(struct ah_i_slab* slab)
{
    ah_assert_if_debug(slab != NULL);

    return slab->_free_list == NULL;
}

static void* s_slot_get_entry(struct ah_i_slab_slot* slot)
{
    ah_assert_if_debug(slot != NULL);

    return &((uint8_t*) slot)[sizeof(struct ah_i_slab_slot)];
}

void ah_i_slab_free(struct ah_i_slab* slab, void* entry)
{
    ah_assert_if_debug(slab != NULL);
    ah_assert_if_debug(entry != NULL);

    struct ah_i_slab_slot* slot = s_entry_get_slot(entry);
    ah_assert_if_debug(slot->_next_free == NULL);

#ifndef NDEBUG
    memset(slot, 0, slab->_slot_size);
#endif

    slot->_next_free = slab->_free_list;
    slab->_free_list = slot;
}

static struct ah_i_slab_slot* s_entry_get_slot(void* entry)
{
    ah_assert_if_debug(entry != NULL);

    return (struct ah_i_slab_slot*) &((uint8_t*) entry)[-((ptrdiff_t) sizeof(struct ah_i_slab_slot))];
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
                struct ah_i_slab_slot* slot = s_cache_get_slot(cache, i, slab->_slot_size);
                if (slot->_next_free != (struct ah_i_slab_slot*) 1u) {
                    allocated_entry_cb(s_slot_get_entry(slot));
                }
#ifndef NDEBUG
                slot->_next_free = NULL;
#endif
            }
        }
    }

    struct ah_i_slab_cache* current = slab->_cache_list;
    while (current != NULL) {
        struct ah_i_slab_cache* next = current->_next;
#ifndef NDEBUG
        memset(current, 0, AH_PSIZE);
#endif
        ah_pfree(current);
        current = next;
    }
}
