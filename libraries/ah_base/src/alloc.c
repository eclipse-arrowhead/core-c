// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/alloc.h"

#include "ah/math.h"

#include <string.h>

ah_extern void ah_dealloc(ah_alloc_cb alloc_cb, void* ptr)
{
    if (alloc_cb != NULL && ptr != NULL) {
        (void) alloc_cb(ptr, 0u);
    }
}

ah_extern void* ah_malloc(ah_alloc_cb alloc_cb, size_t size)
{
    if (alloc_cb == NULL || size == 0u) {
        return NULL;
    }

    return alloc_cb(NULL, size);
}

ah_extern void* ah_malloc_zeroed(ah_alloc_cb alloc_cb, size_t size)
{
    void* pointer = ah_malloc(alloc_cb, size);
    if (pointer == NULL) {
        return NULL;
    }

    return memset(pointer, 0, size);
}

ah_extern void* ah_malloc_array(ah_alloc_cb alloc_cb, size_t array_length, size_t item_size)
{
    if (alloc_cb == NULL) {
        return NULL;
    }

    size_t total_size;
    if (ah_mul_size(array_length, item_size, &total_size) != AH_ENONE) {
        return NULL;
    }
    if (total_size == 0u) {
        return NULL;
    }

    return alloc_cb(NULL, total_size);
}

ah_extern void* ah_calloc(ah_alloc_cb alloc_cb, size_t array_length, size_t item_size)
{
    if (alloc_cb == NULL) {
        return NULL;
    }

    size_t total_size;
    if (ah_mul_size(array_length, item_size, &total_size) != AH_ENONE) {
        return NULL;
    }
    if (total_size == 0u) {
        return NULL;
    }

    return ah_malloc_zeroed(alloc_cb, total_size);
}

ah_extern void* ah_realloc(ah_alloc_cb alloc_cb, void* ptr, size_t new_array_length, size_t item_size)
{
    if (alloc_cb == NULL || ptr == NULL) {
        return NULL;
    }

    size_t total_size;
    if (ah_mul_size(new_array_length, item_size, &total_size) != AH_ENONE) {
        return NULL;
    }

    return alloc_cb(ptr, total_size);
}

ah_extern void* ah_realloc_zero_expansion(ah_alloc_cb alloc_cb, void* ptr, size_t old_array_length,
    size_t new_array_length, size_t item_size)
{
    void* new_ptr = ah_realloc(alloc_cb, ptr, new_array_length, item_size);

    if (new_ptr != NULL && old_array_length < new_array_length) {
        char* ptr_to_zero_region = &((char*) ptr)[old_array_length * item_size];
        (void) memset(ptr_to_zero_region, 0, (new_array_length - old_array_length) * item_size);
    }

    return new_ptr;
}

ah_extern void* ah_realloc_larger(ah_alloc_cb alloc_cb, void* ptr, size_t* array_length, size_t item_size)
{
    if (alloc_cb == NULL || ptr == NULL || array_length == NULL || item_size == 0u) {
        return NULL;
    }

    size_t new_array_length;
    if (*array_length == 0u) {
        new_array_length = 8u;
    }
    else if (ah_mul_size(*array_length, 2u, &new_array_length) != AH_ENONE) {
        return NULL;
    }
    else {
    }

    size_t total_size;
    if (ah_mul_size(new_array_length, item_size, &total_size) != AH_ENONE) {
        return NULL;
    }

    void* new_ptr = alloc_cb(ptr, total_size);

    if (new_ptr != NULL) {
        *array_length = new_array_length;
    }

    return new_ptr;
}
