// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_COLLECTIONS_RING_H_
#define AH_INTERNAL_COLLECTIONS_RING_H_

#include "../../alloc.h"
#include "../../assert.h"
#include "../../math.h"

#include <stdbool.h>
#include <stdlib.h>

struct ah_i_ring {
    size_t _entry_size;
    void* _offset_start;
    void* _offset_read;
    void* _offset_write;
    void* _offset_end;
};

ah_err_t ah_i_ring_init(struct ah_i_ring* ring, size_t initial_entry_capacity, size_t entry_size);
void* ah_i_ring_alloc(struct ah_i_ring* ring);
void* ah_i_ring_peek(struct ah_i_ring* ring);
void ah_i_ring_skip(struct ah_i_ring* ring);
void ah_i_ring_term(struct ah_i_ring* ring);

#endif
