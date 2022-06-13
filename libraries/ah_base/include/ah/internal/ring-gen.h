// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_RING_GEN_H_
#define AH_INTERNAL_RING_GEN_H_

#include "../alloc.h"
#include "../assert.h"
#include "../math.h"

#include <stdbool.h>
#include <stdlib.h>

// struct RING_TYPE {
//     size_t _capacity;
//     size_t _index_read;
//     size_t _index_write;
//     ENTRY_TYPE* _entries;
// }

#define AH_I_RING_GEN_ALLOC_ENTRY(QUALIFIERS, NAME_PREFIX, RING_TYPE, ENTRY_TYPE, MIN_CAPACITY) \
 QUALIFIERS ah_err_t NAME_PREFIX##_alloc_entry(RING_TYPE* ring, ENTRY_TYPE** entry)             \
 {                                                                                              \
  ah_assert_if_debug(ring != NULL && entry != NULL);                                            \
                                                                                                \
  size_t new_index_write = ring->_index_write + 1u;                                             \
  if (new_index_write == ring->_capacity) {                                                     \
   new_index_write = 0u;                                                                        \
  }                                                                                             \
                                                                                                \
  if (ring->_index_read == new_index_write) {                                                   \
   size_t capacity;                                                                             \
                                                                                                \
   if (ring->_capacity < MIN_CAPACITY) {                                                        \
    capacity = MIN_CAPACITY;                                                                    \
   }                                                                                            \
   else {                                                                                       \
    capacity = ring->_capacity;                                                                 \
    if (ah_mul_size(capacity, 2u, &capacity) != AH_ENONE) {                                     \
     return AH_ENOMEM;                                                                          \
    }                                                                                           \
   }                                                                                            \
                                                                                                \
   size_t capacity_in_bytes;                                                                    \
   if (ah_mul_size(capacity, sizeof(ENTRY_TYPE), &capacity_in_bytes) != AH_ENONE) {             \
    return AH_ENOMEM;                                                                           \
   }                                                                                            \
                                                                                                \
   ENTRY_TYPE* entries = ah_malloc(capacity_in_bytes);                                          \
   if (entries == NULL) {                                                                       \
    return AH_ENOMEM;                                                                           \
   }                                                                                            \
                                                                                                \
   size_t n_entries;                                                                            \
   if (ring->_index_read > ring->_index_write) {                                                \
    n_entries = ring->_capacity - ring->_index_read;                                            \
    memcpy(entries, &ring->_entries[ring->_index_read], n_entries * sizeof(ENTRY_TYPE));        \
    memcpy(&entries[n_entries], ring->_entries, ring->_index_write * sizeof(ENTRY_TYPE));       \
    n_entries += ring->_index_write;                                                            \
   }                                                                                            \
   else {                                                                                       \
    n_entries = ring->_index_write - ring->_index_read;                                         \
    memcpy(entries, &ring->_entries[ring->_index_read], n_entries * sizeof(ENTRY_TYPE));        \
   }                                                                                            \
                                                                                                \
   ah_free(ring->_entries);                                                                     \
                                                                                                \
   ring->_capacity = capacity;                                                                  \
   ring->_entries = entries;                                                                    \
   ring->_index_read = 0u;                                                                      \
   ring->_index_write = n_entries;                                                              \
                                                                                                \
   new_index_write = n_entries + 1u;                                                            \
  }                                                                                             \
                                                                                                \
  *entry = &ring->_entries[ring->_index_write];                                                 \
  ring->_index_write = new_index_write;                                                         \
                                                                                                \
  return AH_ENONE;                                                                              \
 }

#define AH_I_RING_GEN_DISCARD(QUALIFIERS, NAME_PREFIX, RING_TYPE) \
 QUALIFIERS void NAME_PREFIX##_discard(RING_TYPE* ring)           \
 {                                                                \
  ah_assert_if_debug(ring != NULL);                               \
                                                                  \
  if (ring->_index_read == ring->_index_write) {                  \
   return;                                                        \
  }                                                               \
                                                                  \
  ring->_index_read += 1u;                                        \
  if (ring->_index_read > ring->_capacity) {                      \
   ring->_index_read = 0u;                                        \
  }                                                               \
 }

#define AH_I_RING_GEN_INIT(QUALIFIERS, NAME_PREFIX, RING_TYPE, ENTRY_TYPE, INITIAL_CAPACITY) \
 QUALIFIERS ah_err_t NAME_PREFIX##_init(RING_TYPE* ring)                                     \
 {                                                                                           \
  ah_assert_if_debug(ring != NULL);                                                          \
                                                                                             \
  size_t capacity_in_bytes;                                                                  \
  if (ah_mul_size(INITIAL_CAPACITY, sizeof(ENTRY_TYPE), &capacity_in_bytes) != AH_ENONE) {   \
   return AH_ENOMEM;                                                                         \
  }                                                                                          \
                                                                                             \
  ring->_entries = ah_malloc(capacity_in_bytes);                                             \
  if (ring->_entries == NULL) {                                                              \
   return AH_ENOMEM;                                                                         \
  }                                                                                          \
                                                                                             \
  ring->_capacity = INITIAL_CAPACITY;                                                        \
  ring->_index_read = 0u;                                                                    \
  ring->_index_write = 0u;                                                                   \
                                                                                             \
  return AH_ENONE;                                                                           \
 }

#define AH_I_RING_GEN_IS_EMPTY(QUALIFIERS, NAME_PREFIX, RING_TYPE) \
 QUALIFIERS bool NAME_PREFIX##_is_empty(RING_TYPE* ring)           \
 {                                                                 \
  ah_assert_if_debug(ring != NULL);                                \
                                                                   \
  return ring->_index_read == ring->_index_write;                  \
 }

#define AH_I_RING_GEN_PEEK(QUALIFIERS, NAME_PREFIX, RING_TYPE, ENTRY_TYPE) \
 QUALIFIERS ENTRY_TYPE* NAME_PREFIX##_peek(RING_TYPE* ring)                \
 {                                                                         \
  ah_assert_if_debug(ring != NULL);                                        \
                                                                           \
  if (ring->_index_read == ring->_index_write) {                           \
   return NULL;                                                            \
  }                                                                        \
                                                                           \
  return &ring->_entries[ring->_index_read];                               \
 }

#define AH_I_RING_GEN_POP(QUALIFIERS, NAME_PREFIX, RING_TYPE, ENTRY_TYPE) \
 QUALIFIERS bool NAME_PREFIX##_pop(RING_TYPE* ring, ENTRY_TYPE* entry)    \
 {                                                                        \
  ah_assert_if_debug(ring != NULL && entry != NULL);                      \
                                                                          \
  if (ring->_index_read == ring->_index_write) {                          \
   return false;                                                          \
  }                                                                       \
                                                                          \
  *entry = ring->_entries[ring->_index_read];                             \
                                                                          \
  ring->_index_read += 1u;                                                \
  if (ring->_index_read > ring->_capacity) {                              \
   ring->_index_read = 0u;                                                \
  }                                                                       \
                                                                          \
  return true;                                                            \
 }

#define AH_I_RING_GEN_PUSH(QUALIFIERS, NAME_PREFIX, RING_TYPE, ENTRY_TYPE) \
 QUALIFIERS ah_err_t NAME_PREFIX##_push(RING_TYPE* ring, ENTRY_TYPE entry) \
 {                                                                         \
  ah_assert_if_debug(ring != NULL);                                        \
                                                                           \
  ENTRY_TYPE* entry_ptr;                                                   \
  ah_err_t err = NAME_PREFIX##_alloc(ring, &entry_ptr);                    \
  if (err == AH_ENONE) {                                                   \
   *entry_ptr = entry;                                                     \
  }                                                                        \
  return err;                                                              \
 }

#define AH_I_RING_GEN_TERM(QUALIFIERS, NAME_PREFIX, RING_TYPE) \
 QUALIFIERS void NAME_PREFIX##_term(RING_TYPE* ring)           \
 {                                                             \
  ah_assert_if_debug(ring != NULL);                            \
                                                               \
  ah_free(ring->_entries);                                     \
 }

#endif
