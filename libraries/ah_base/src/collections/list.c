// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/internal/collections/list.h"

#include "ah/assert.h"

#include <stdlib.h>

bool ah_i_list_is_empty(struct ah_i_list* list)
{
    ah_assert_if_debug(list != NULL);

    return list->_first == NULL;
}

void ah_i_list_push(struct ah_i_list* list, struct ah_i_list_entry* entry)
{
    ah_assert_if_debug(list != NULL);
    ah_assert_if_debug(entry != NULL);

    entry->_next = NULL;

    if (list->_first == NULL) {
        list->_first = entry;
        list->_last = entry;
    }
    else {
        list->_last->_next = entry;
        list->_last = entry;
    }
}

struct ah_i_list_entry* ah_i_list_peek(struct ah_i_list* list)
{
    ah_assert_if_debug(list != NULL);

    return list->_first;
}

struct ah_i_list_entry* ah_i_list_pop(struct ah_i_list* list)
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

    return entry;
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
