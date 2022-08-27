// SPDX-License-Identifier: EPL-2.0

#include "ah/err.h"
#include "ah/internal/collections/ring.h"

#include <ah/unit.h>

static void s_should_peek_and_pop_entries_in_order_of_allocation(ah_unit_res_t* res);

void test_collections_ring(ah_unit_res_t* res)
{
    s_should_peek_and_pop_entries_in_order_of_allocation(res);
}

static void s_should_peek_and_pop_entries_in_order_of_allocation(ah_unit_res_t* res)
{
    struct s_entry {
        int ordinal;
    };

    ah_err_t err;

    struct ah_i_ring ring;
    err = ah_i_ring_init(&ring, 4u, sizeof(struct s_entry));
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, AH_ENONE, err)) {
        return;
    }

    // Allocate entries.

    struct s_entry* entry0 = ah_i_ring_alloc(&ring);
    if (!ah_unit_assert(AH_UNIT_CTX, res, entry0 != NULL, "entry0 == NULL")) {
        return;
    }
    entry0->ordinal = 1000;

    struct s_entry* entry1 = ah_i_ring_alloc(&ring);
    if (!ah_unit_assert(AH_UNIT_CTX, res, entry1 != NULL, "entry1 == NULL")) {
        return;
    }
    entry1->ordinal = 1001;

    struct s_entry* entry2 = ah_i_ring_alloc(&ring);
    if (!ah_unit_assert(AH_UNIT_CTX, res, entry2 != NULL, "entry2 == NULL")) {
        return;
    }
    entry2->ordinal = 1002;

    struct s_entry* entry3 = ah_i_ring_alloc(&ring);
    if (!ah_unit_assert(AH_UNIT_CTX, res, entry3 != NULL, "entry3 == NULL")) {
        return;
    }
    entry3->ordinal = 1003;

    // Peek, pop and skip entries and check their contents.

    struct s_entry* entry;

    entry = ah_i_ring_peek(&ring);
    ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, (uintmax_t) entry, (uintmax_t) entry0);
    ah_unit_assert_eq_intmax(AH_UNIT_CTX, res, entry->ordinal, entry0->ordinal);

    entry = ah_i_ring_pop(&ring);
    ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, (uintmax_t) entry, (uintmax_t) entry0);
    ah_unit_assert_eq_intmax(AH_UNIT_CTX, res, entry->ordinal, entry0->ordinal);

    entry = ah_i_ring_peek(&ring);
    ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, (uintmax_t) entry, (uintmax_t) entry1);
    ah_unit_assert_eq_intmax(AH_UNIT_CTX, res, entry->ordinal, entry1->ordinal);

    entry = ah_i_ring_pop(&ring);
    ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, (uintmax_t) entry, (uintmax_t) entry1);
    ah_unit_assert_eq_intmax(AH_UNIT_CTX, res, entry->ordinal, entry1->ordinal);

    entry = ah_i_ring_peek(&ring);
    ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, (uintmax_t) entry, (uintmax_t) entry2);
    ah_unit_assert_eq_intmax(AH_UNIT_CTX, res, entry->ordinal, entry2->ordinal);

    ah_i_ring_skip(&ring);

    entry = ah_i_ring_peek(&ring);
    ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, (uintmax_t) entry, (uintmax_t) entry3);
    ah_unit_assert_eq_intmax(AH_UNIT_CTX, res, entry->ordinal, entry3->ordinal);

    entry = ah_i_ring_pop(&ring);
    ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, (uintmax_t) entry, (uintmax_t) entry3);
    ah_unit_assert_eq_intmax(AH_UNIT_CTX, res, entry->ordinal, entry3->ordinal);

    entry = ah_i_ring_peek(&ring);
    ah_unit_assert(AH_UNIT_CTX, res, entry == NULL, "entry != NULL");

    // We're done.

    ah_i_ring_term(&ring);
}
