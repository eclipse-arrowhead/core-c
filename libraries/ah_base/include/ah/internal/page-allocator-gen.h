// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_PAGE_ALLOCATOR_GEN_H_
#define AH_INTERNAL_PAGE_ALLOCATOR_GEN_H_

#include "../math.h"

// struct ALLOCATOR_TYPE {
//     PAGE_TYPE* _page_list;
//     ENTRY_TYPE* _free_list;
// };

// struct ENTRY_TYPE {
//     ENTRY_TYPE* _next_free;
// };

// struct PAGE_TYPE {
//     ENTRY_TYPE _entries[PAGE_CAPACITY];
//     PAGE_TYPE* _next_page;
// };

#define AH_I_PAGE_ALLOCATOR_GEN_ALLOC(QUALIFIERS, NAME_PREFIX, ALLOCATOR_TYPE, ENTRY_TYPE) \
 QUALIFIERS ah_err_t NAME_PREFIX##_alloc(ALLOCATOR_TYPE* allocator, ENTRY_TYPE** entry)    \
 {                                                                                         \
  ah_assert_if_debug(allocator != NULL);                                                   \
  ah_assert_if_debug(entry != NULL);                                                       \
                                                                                           \
  ENTRY_TYPE* allocated_entry = allocator->_free_list;                                     \
  if (allocated_entry == NULL) {                                                           \
   ah_err_t err = NAME_PREFIX##_grow(allocator, NULL);                                     \
   if (err != AH_ENONE) {                                                                  \
    return err;                                                                            \
   }                                                                                       \
   allocated_entry = allocator->_free_list;                                                \
  }                                                                                        \
                                                                                           \
  *entry = allocated_entry;                                                                \
  allocator->_free_list = allocated_entry->_next_free;                                     \
                                                                                           \
  return AH_ENONE;                                                                         \
 }

#define AH_I_PAGE_ALLOCATOR_GEN_FREE(QUALIFIERS, NAME_PREFIX, ALLOCATOR_TYPE, ENTRY_TYPE) \
 QUALIFIERS void NAME_PREFIX##_free(ALLOCATOR_TYPE* allocator, ENTRY_TYPE* entry)         \
 {                                                                                        \
  ah_assert_if_debug(allocator != NULL);                                                  \
  ah_assert_if_debug(entry != NULL);                                                      \
                                                                                          \
  entry->_next_free = allocator->_free_list;                                              \
  allocator->_free_list = entry;                                                          \
 }

#define AH_I_PAGE_ALLOCATOR_GEN_GROW(QUALIFIERS, NAME_PREFIX, ALLOCATOR_TYPE, PAGE_TYPE, ENTRY_TYPE, PAGE_CAPACITY) \
 QUALIFIERS ah_err_t NAME_PREFIX##_grow(ALLOCATOR_TYPE* allocator, ENTRY_TYPE* free_entry)                          \
 {                                                                                                                  \
  ah_assert_if_debug(allocator != NULL);                                                                            \
                                                                                                                    \
  PAGE_TYPE* page = malloc(sizeof(PAGE_TYPE));                                                                      \
  if (page == NULL) {                                                                                               \
   return AH_ENOMEM;                                                                                                \
  }                                                                                                                 \
                                                                                                                    \
  for (size_t i = 1u; i < PAGE_CAPACITY; i += 1u) {                                                                 \
   page->_entries[i - 1u]._next_free = &page->_entries[i];                                                          \
  }                                                                                                                 \
                                                                                                                    \
  page->_entries[PAGE_CAPACITY - 1u]._next_free = free_entry;                                                       \
                                                                                                                    \
  page->_next_page = allocator->_page_list;                                                                         \
  allocator->_page_list = page;                                                                                     \
                                                                                                                    \
  return AH_ENONE;                                                                                                  \
 }

#define AH_I_PAGE_ALLOCATOR_GEN_INIT(QUALIFIERS, NAME_PREFIX, ALLOCATOR_TYPE, PAGE_TYPE, ENTRY_TYPE, PAGE_CAPACITY) \
 QUALIFIERS ah_err_t NAME_PREFIX##_init(ALLOCATOR_TYPE* allocator, size_t initial_capacity)                         \
 {                                                                                                                  \
  ah_assert_if_debug(allocator != NULL);                                                                            \
                                                                                                                    \
  ENTRY_TYPE* free_entry = NULL;                                                                                    \
  while (initial_capacity > 0u) {                                                                                   \
   ah_err_t err = NAME_PREFIX##_grow(allocator, free_entry);                                                        \
   if (err != AH_ENONE) {                                                                                           \
    NAME_PREFIX##_term(allocator);                                                                                  \
    return err;                                                                                                     \
   }                                                                                                                \
   if (ah_sub_size(initial_capacity, PAGE_CAPACITY, &initial_capacity) != AH_ENONE) {                               \
    break;                                                                                                          \
   }                                                                                                                \
   free_entry = &allocator->_page_list->_entries[PAGE_CAPACITY - 1u];                                               \
  }                                                                                                                 \
                                                                                                                    \
  allocator->_free_list = &allocator->_page_list->_entries[0u];                                                     \
                                                                                                                    \
  return AH_ENONE;                                                                                                  \
 }

#define AH_I_PAGE_ALLOCATOR_GEN_TERM(QUALIFIERS, NAME_PREFIX, ALLOCATOR_TYPE, PAGE_TYPE) \
 QUALIFIERS void NAME_PREFIX##_term(ALLOCATOR_TYPE* allocator)                           \
 {                                                                                       \
  ah_assert_if_debug(allocator != NULL);                                                 \
                                                                                         \
  PAGE_TYPE* page = allocator->_page_list;                                               \
  while (page != NULL) {                                                                 \
   PAGE_TYPE* next_page = page->_next_page;                                              \
   free(page);                                                                           \
   page = next_page;                                                                     \
  }                                                                                      \
 }

#endif
