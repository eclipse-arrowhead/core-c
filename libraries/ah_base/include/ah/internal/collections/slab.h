// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_COLLECTIONS_SLAB_H_
#define AH_INTERNAL_COLLECTIONS_SLAB_H_

#include "../../alloc.h"
#include "../../math.h"

struct ah_i_slab {
    struct ah_i_slab_cache* _cache_list;
    struct ah_i_slab_slot* _free_list;
    size_t _cache_slot_capacity;
    size_t _slot_size;
};

struct ah_i_slab_slot {
    struct ah_i_slab_slot* _next_free;
    uint8_t _entry[];
};

struct ah_i_slab_cache {
    struct ah_i_slab_cache* _next;
    uint8_t _slots_as_raw_bytes[];
};

ah_err_t ah_i_slab_init(struct ah_i_slab* slab, size_t initial_slot_capacity, size_t slot_data_size);
void* ah_i_slab_alloc(struct ah_i_slab* slab);
void ah_i_slab_free(struct ah_i_slab* slab, void* entry);
void ah_i_slab_term(struct ah_i_slab* slab, void (*allocated_entry_cb)(void*));

#endif
