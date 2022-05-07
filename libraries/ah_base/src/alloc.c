// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/alloc.h"

#include "ah/err.h"
#include "ah/math.h"

#include <string.h>

ah_extern void ah_dealloc(ah_alloc_cb a, void* ptr)
{
    if (a != NULL && ptr != NULL) {
        (void) a(ptr, 0u);
    }
}

ah_extern void* ah_malloc(ah_alloc_cb a, size_t size)
{
    if (a == NULL || size == 0u) {
        return NULL;
    }

    return a(NULL, size);
}

ah_extern void* ah_malloc_array(ah_alloc_cb a, size_t array_length, size_t item_size)
{
    if (a == NULL) {
        return NULL;
    }

    size_t total_size;
    if (ah_mul_size(array_length, item_size, &total_size) != AH_ENONE) {
        return NULL;
    }
    if (total_size == 0u) {
        return NULL;
    }

    return a(NULL, total_size);
}

ah_extern void* ah_realloc_array(ah_alloc_cb a, void* ptr, size_t new_array_length, size_t item_size)
{
    if (a == NULL || ptr == NULL) {
        return NULL;
    }

    size_t total_size;
    if (ah_mul_size(new_array_length, item_size, &total_size) != AH_ENONE) {
        return NULL;
    }

    return a(ptr, total_size);
}

ah_extern void* ah_realloc_array_larger(ah_alloc_cb a, void* ptr, size_t* array_length, size_t item_size)
{
    if (a == NULL || ptr == NULL || array_length == NULL || item_size == 0u) {
        return NULL;
    }

    size_t new_array_length;
    if (*array_length == 0u) {
        new_array_length = 8u;
    }
    else if (ah_add_size(*array_length, *array_length / 2u, &new_array_length) != AH_ENONE) {
        return NULL;
    }

    size_t total_size;
    if (ah_mul_size(new_array_length, item_size, &total_size) != AH_ENONE) {
        return NULL;
    }

    void* new_ptr = a(ptr, total_size);

    if (new_ptr != NULL) {
        *array_length = new_array_length;
    }

    return new_ptr;
}
