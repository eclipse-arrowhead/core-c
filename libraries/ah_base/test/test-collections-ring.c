// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/err.h"
#include "ah/internal/collections/ring.h"
#include "ah/unit.h"

static void s_should_peek_and_pop_entries_in_order_of_allocation(ah_unit_t* unit);

void test_collections_ring(ah_unit_t* unit)
{
    s_should_peek_and_pop_entries_in_order_of_allocation(unit);
}

static void s_should_peek_and_pop_entries_in_order_of_allocation(ah_unit_t* unit)
{
    struct s_entry {
        int ordinal;
    };

    ah_err_t err;

    struct ah_i_ring ring;
    err = ah_i_ring_init(&ring, 4u, sizeof(struct s_entry));
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    // Allocate entries.

    struct s_entry* entry0 = ah_i_ring_alloc(&ring);
    if (!ah_unit_assert(unit, entry0 != NULL, "entry0 == NULL")) {
        return;
    }
    entry0->ordinal = 1000;

    struct s_entry* entry1 = ah_i_ring_alloc(&ring);
    if (!ah_unit_assert(unit, entry1 != NULL, "entry1 == NULL")) {
        return;
    }
    entry1->ordinal = 1001;

    struct s_entry* entry2 = ah_i_ring_alloc(&ring);
    if (!ah_unit_assert(unit, entry2 != NULL, "entry2 == NULL")) {
        return;
    }
    entry2->ordinal = 1002;

    struct s_entry* entry3 = ah_i_ring_alloc(&ring);
    if (!ah_unit_assert(unit, entry3 != NULL, "entry3 == NULL")) {
        return;
    }
    entry3->ordinal = 1003;

    // Peek, pop and skip entries and check their contents.

    struct s_entry* entry;

    entry = ah_i_ring_peek(&ring);
    ah_unit_assert_unsigned_eq(unit, entry0, entry);
    ah_unit_assert_signed_eq(unit, entry0->ordinal, entry->ordinal);

    entry = ah_i_ring_pop(&ring);
    ah_unit_assert_unsigned_eq(unit, entry0, entry);
    ah_unit_assert_signed_eq(unit, entry0->ordinal, entry->ordinal);

    entry = ah_i_ring_peek(&ring);
    ah_unit_assert_unsigned_eq(unit, entry1, entry);
    ah_unit_assert_signed_eq(unit, entry1->ordinal, entry->ordinal);

    entry = ah_i_ring_pop(&ring);
    ah_unit_assert_unsigned_eq(unit, entry1, entry);
    ah_unit_assert_signed_eq(unit, entry1->ordinal, entry->ordinal);

    entry = ah_i_ring_peek(&ring);
    ah_unit_assert_unsigned_eq(unit, entry2, entry);
    ah_unit_assert_signed_eq(unit, entry2->ordinal, entry->ordinal);

    ah_i_ring_skip(&ring);

    entry = ah_i_ring_peek(&ring);
    ah_unit_assert_unsigned_eq(unit, entry3, entry);
    ah_unit_assert_signed_eq(unit, entry3->ordinal, entry->ordinal);

    entry = ah_i_ring_pop(&ring);
    ah_unit_assert_unsigned_eq(unit, entry3, entry);
    ah_unit_assert_signed_eq(unit, entry3->ordinal, entry->ordinal);

    entry = ah_i_ring_peek(&ring);
    ah_unit_assert(unit, entry == NULL, "entry != NULL");

    // We're done.

    ah_i_ring_term(&ring);
}
