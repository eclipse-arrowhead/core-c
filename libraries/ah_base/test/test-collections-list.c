// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/internal/collections/list.h"
#include "ah/unit.h"

#include <stdlib.h>

static void s_should_peek_and_pop_entries_in_order_of_insertion(ah_unit_t* unit);
static void s_should_report_correctly_about_when_list_is_empty(ah_unit_t* unit);

void test_collections_list(ah_unit_t* unit)
{
    s_should_peek_and_pop_entries_in_order_of_insertion(unit);
    s_should_report_correctly_about_when_list_is_empty(unit);
}

static void s_should_peek_and_pop_entries_in_order_of_insertion(ah_unit_t* unit)
{
    struct ah_i_list list = { 0u };

    struct s_entry {
        const char* text;
        int entry_order;
        struct ah_i_list_entry entry;
    };

    struct s_entry* entry0 = malloc(sizeof(struct s_entry));
    entry0->text = "Entry 0";
    entry0->entry_order = 0;
    entry0->entry._next = NULL;

    struct s_entry* entry1 = malloc(sizeof(struct s_entry));
    entry1->text = "Entry 1";
    entry1->entry_order = 1;
    entry1->entry._next = NULL;

    struct s_entry* entry2 = malloc(sizeof(struct s_entry));
    entry2->text = "Entry 2";
    entry2->entry_order = 2;
    entry2->entry._next = NULL;

    ah_i_list_push(&list, entry0, offsetof(struct s_entry, entry));
    ah_i_list_push(&list, entry1, offsetof(struct s_entry, entry));
    ah_i_list_push(&list, entry2, offsetof(struct s_entry, entry));

    struct s_entry* entry;

    entry = ah_i_list_peek(&list, offsetof(struct s_entry, entry));
    ah_unit_assert_unsigned_eq(unit, entry0, entry);
    ah_unit_assert_signed_eq(unit, entry0->entry_order, entry->entry_order);

    entry = ah_i_list_pop(&list, offsetof(struct s_entry, entry));
    ah_unit_assert_unsigned_eq(unit, entry0, entry);
    ah_unit_assert_signed_eq(unit, entry0->entry_order, entry->entry_order);

    entry = ah_i_list_peek(&list, offsetof(struct s_entry, entry));
    ah_unit_assert_unsigned_eq(unit, entry1, entry);
    ah_unit_assert_signed_eq(unit, entry1->entry_order, entry->entry_order);

    entry = ah_i_list_pop(&list, offsetof(struct s_entry, entry));
    ah_unit_assert_unsigned_eq(unit, entry1, entry);
    ah_unit_assert_signed_eq(unit, entry1->entry_order, entry->entry_order);

    entry = ah_i_list_peek(&list, offsetof(struct s_entry, entry));
    ah_unit_assert_unsigned_eq(unit, entry2, entry);
    ah_unit_assert_signed_eq(unit, entry2->entry_order, entry->entry_order);

    entry = ah_i_list_pop(&list, offsetof(struct s_entry, entry));
    ah_unit_assert_unsigned_eq(unit, entry2, entry);
    ah_unit_assert_signed_eq(unit, entry2->entry_order, entry->entry_order);

    entry = ah_i_list_peek(&list, offsetof(struct s_entry, entry));
    ah_unit_assert(unit, entry == NULL, "entry != NULL");

    free(entry0);
    free(entry1);
    free(entry2);
}

static void s_should_report_correctly_about_when_list_is_empty(ah_unit_t* unit)
{
    struct ah_i_list list = { 0u };

    struct s_entry {
        const char* text;
        struct ah_i_list_entry entry;
    };

    struct s_entry* entry0 = malloc(sizeof(struct s_entry));
    entry0->text = "Entry 0";
    entry0->entry._next = NULL;

    struct s_entry* entry1 = malloc(sizeof(struct s_entry));
    entry1->text = "Entry 1";
    entry1->entry._next = NULL;

    ah_unit_assert(unit, ah_i_list_is_empty(&list), "!ah_i_list_is_empty(&list)");

    ah_i_list_push(&list, entry0, offsetof(struct s_entry, entry));
    ah_unit_assert(unit, !ah_i_list_is_empty(&list), "ah_i_list_is_empty(&list)");

    ah_i_list_push(&list, entry1, offsetof(struct s_entry, entry));
    ah_unit_assert(unit, !ah_i_list_is_empty(&list), "ah_i_list_is_empty(&list)");

    ah_i_list_skip(&list);
    ah_unit_assert(unit, !ah_i_list_is_empty(&list), "ah_i_list_is_empty(&list)");

    ah_i_list_skip(&list);
    ah_unit_assert(unit, ah_i_list_is_empty(&list), "!ah_i_list_is_empty(&list)");

    free(entry0);
    free(entry1);
}
