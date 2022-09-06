// SPDX-License-Identifier: EPL-2.0

#include "ah/internal/collections/list.h"

#include "ah/assert.h"

bool ah_i_list_is_empty(struct ah_i_list* list)
{
    ah_assert_if_debug(list != NULL);

    return list->_first == NULL;
}

void* ah_i_list_peek(struct ah_i_list* list, ptrdiff_t list_entry_offset)
{
    ah_assert_if_debug(list != NULL);

    if (list->_first == NULL) {
        return NULL;
    }

    return &((uint8_t*) list->_first)[-list_entry_offset];
}

void* ah_i_list_pop(struct ah_i_list* list, ptrdiff_t list_entry_offset)
{
    ah_assert_if_debug(list != NULL);

    if (list->_first == NULL) {
        return NULL;
    }

    struct ah_i_list_entry* entry = list->_first;
    list->_first = entry->_next;

#ifndef NDEBUG

    entry->_next = NULL;

    if (list->_first == NULL) {
        list->_last = NULL;
    }

#endif

    return &((uint8_t*) entry)[-list_entry_offset];
}

void ah_i_list_push(struct ah_i_list* list, void* entry, ptrdiff_t list_entry_offset)
{
    ah_assert_if_debug(list != NULL);
    ah_assert_if_debug(entry != NULL);

    struct ah_i_list_entry* entry0 = (void*) &((uint8_t*) entry)[list_entry_offset];

    entry0->_next = NULL;

    if (list->_first == NULL) {
        list->_first = entry0;
        list->_last = entry0;
    }
    else {
        list->_last->_next = entry0;
        list->_last = entry0;
    }
}

void ah_i_list_skip(struct ah_i_list* list)
{
    ah_assert_if_debug(list != NULL);

    if (list->_first == NULL) {
        return;
    }

    struct ah_i_list_entry* entry = list->_first;
    list->_first = entry->_next;

#ifndef NDEBUG

    entry->_next = NULL;

    if (list->_first == NULL) {
        list->_last = NULL;
    }

#endif
}
