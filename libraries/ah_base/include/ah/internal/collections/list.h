// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_COLLECTIONS_LIST_H_
#define AH_INTERNAL_COLLECTIONS_LIST_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct ah_i_list {
    struct ah_i_list_entry* _first;
    struct ah_i_list_entry* _last;
};

struct ah_i_list_entry {
    struct ah_i_list_entry* _next;
};

bool ah_i_list_is_empty(struct ah_i_list* list);
void* ah_i_list_peek(struct ah_i_list* list, ptrdiff_t list_entry_offset);
void* ah_i_list_pop(struct ah_i_list* list, ptrdiff_t list_entry_offset);
void ah_i_list_push(struct ah_i_list* list, void* entry, ptrdiff_t list_entry_offset);
void ah_i_list_skip(struct ah_i_list* list);

#endif
