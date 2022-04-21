// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_ALLOC_H_
#define AH_ALLOC_H_

#include "defs.h"

#include <stddef.h>

typedef void* (*ah_alloc_cb)(void* ptr, size_t size);

ah_extern void ah_dealloc(ah_alloc_cb alloc_cb, void* ptr);
ah_extern void* ah_malloc(ah_alloc_cb alloc_cb, size_t size);
ah_extern void* ah_malloc_zeroed(ah_alloc_cb alloc_cb, size_t size);
ah_extern void* ah_malloc_array(ah_alloc_cb alloc_cb, size_t array_length, size_t item_size);
ah_extern void* ah_calloc(ah_alloc_cb alloc_cb, size_t array_length, size_t item_size);
ah_extern void* ah_realloc_array(ah_alloc_cb alloc_cb, void* ptr, size_t new_array_length, size_t item_size);
ah_extern void* ah_realloc_array_zero_expansion(ah_alloc_cb alloc_cb, void* ptr, size_t old_array_length,
    size_t new_array_length, size_t item_size);
ah_extern void* ah_realloc_array_larger(ah_alloc_cb alloc_cb, void* ptr, size_t* array_length, size_t item_size);

#endif
