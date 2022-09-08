// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_COLLECTIONS_SLAB_H_
#define AH_INTERNAL_COLLECTIONS_SLAB_H_

#include "../../alloc.h"
#include "../../math.h"

#include <stdbool.h>

#if AH_PSIZE <= UINT8_MAX
# define AH_I_SLAB_SIZE_MAX UINT8_MAX
# define AH_I_SLAB_SIZE_T   uint8_t
#elif AH_PSIZE <= UINT16_MAX
# define AH_I_SLAB_SIZE_MAX UINT16_MAX
# define AH_I_SLAB_SIZE_T   uint16_t
#elif AH_PSIZE <= UINT32_MAX
# define AH_I_SLAB_SIZE_MAX UINT32_MAX
# define AH_I_SLAB_SIZE_T   uint32_t
#else
# define AH_I_SLAB_SIZE_MAX SIZE_MAX
# define AH_I_SLAB_SIZE_T   size_t
#endif

// A slab allocator.
struct ah_i_slab {
    struct ah_i_slab_cache* _cache_list;
    struct ah_i_slab_slot* _free_list;
    AH_I_SLAB_SIZE_T _cache_slot_capacity;
    AH_I_SLAB_SIZE_T _ref_count;
    AH_I_SLAB_SIZE_T _slot_size;
    bool _is_visiting_entries;
};

// Slot contents are stored right after the slot structure itself.
struct ah_i_slab_slot {
    struct ah_i_slab_slot* _next_free;
};

// Cache slots are stored right after the cache structure itself.
struct ah_i_slab_cache {
    struct ah_i_slab_cache* _next;
};

// Initializes slab for subsequent use. Uses ah_palloc() to allocate caches.
// Returns AH_EOVERFLOW if a AH_PSIZE is too small for it to be possible store
// both the ah_i_slab_cache data structure and at least one complete slot in a
// page. Returns AH_ENOMEM if not enough pages could be allocated to accommodate
// for the desired initial_slot_capacity.
//
// Every initialized slab must be terminated using ah_i_slab_term() exactly
// once.
ah_err_t ah_i_slab_init(struct ah_i_slab* slab, size_t initial_slot_capacity, size_t slot_data_size);

// Allocates entry and increments reference count of slab, or returns NULL if
// the operation fails due to all caches being full and another could not be
// allocated.
void* ah_i_slab_alloc(struct ah_i_slab* slab);

// Frees given entry and decrements reference count of slab. If the reference
// count reaches zero all caches are freed. The entry pointer must have been
// acquired via a previous call to ah_i_slab_alloc() with the same slab pointer.
//
// It is only safe to free any given entry once, unless the same pointer is
// acquired again via a call to ah_i_slab_alloc().
void ah_i_slab_free(struct ah_i_slab* slab, void* entry);

// If allocated_entry_cb is not NULL, every currently allocated entry is
// provided to that function before the slab caches are freed. We refer to the
// process of providing all allocated entries to the callback as _visiting_
// those entries. It is safe to call ah_i_slab_free() from the provided callback
// function, both with freed and allocated entries. If called with an allocated
// entry that has not yet been provided to the callback, it will not be provided
// to the callback. Freeing other entries have no effect.
//
// If allocated_entry_cb is NULL, the reference count of slab is decremented and
// no other action is taken unless the reference count reaches zero, in which
// case the slab caches are freed.
void ah_i_slab_term(struct ah_i_slab* slab, void (*allocated_entry_cb)(void*));

#endif
