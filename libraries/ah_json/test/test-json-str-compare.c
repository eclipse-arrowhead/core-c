// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/json.h"

#include <ah/unit.h>

struct s_json_compare_test {
    const char* a; // Terminated by \0.
    const char* b; // Terminated by \0.
    int expected_result;
};

void s_should_consider_certain_strings_equal(ah_unit_t* unit);
void s_should_consider_certain_strings_not_equal(ah_unit_t* unit);

void test_json_str_compare(ah_unit_t* unit)
{
    s_should_consider_certain_strings_equal(unit);
    s_should_consider_certain_strings_not_equal(unit);
}

void s_assert_json_compare_tests(ah_unit_t* unit, const char* label, struct s_json_compare_test* tests)
{
    size_t test_i = 0u;
    for (struct s_json_compare_test* test = &tests[0u]; test->a != NULL; test = &test[1u], test_i += 1u) {
        int actual_result = ah_json_str_compare(test->a, strlen(test->a), test->b, strlen(test->b));
        if (actual_result != test->expected_result) {
            ah_unit_failf(unit, "%s [%zu]:\n\tcomparison of \"%s\" and \"%s\" produced %d; expected %d",
                label, test_i, test->a, test->b, actual_result, test->expected_result);
            continue;
        }
        ah_unit_pass(unit);
    }
}

void s_should_consider_certain_strings_equal(ah_unit_t* unit)
{
    s_assert_json_compare_tests(unit, __func__,
        (struct s_json_compare_test[]) {
            [0] = { "", "", 0 },
            [1] = { "a", "a", 0 },
            [2] = { "B", "B", 0 },
            [3] = { "cc", "cc", 0 },
            [4] = { "DdDd", "DdDd", 0 },
            [5] = { "Two words!", "Two words!", 0 },
            [6] = { "\\00f6", "ö", 0 },
            [7] = { "Ä", "\\00C4", 0 },
            [8] = { "猫", "\\732B", 0 },
            [9] = { "Åk!", "\\00C5k!", 0 },
            { 0u },
        });
}

void s_should_consider_certain_strings_not_equal(ah_unit_t* unit)
{
    s_assert_json_compare_tests(unit, __func__,
        (struct s_json_compare_test[]) {
            [0] = { "0", "", -1 },
            [1] = { "", "0", 1 },
            [2] = { "Ba", "Bb", 1 },
            [3] = { "aB", "bB", 1 },
            [4] = { "2", "1", -1 },
            [5] = { "Two words!!", "Two words!", -1 },
            [6] = { "\\00f6", "Ö", 1 },
            [7] = { "ä", "\\00C4", -1 },
            [8] = { "猫", "\\732C", 1 },
            [9] = { "Åk?", "\\00C5k!", -1 },
            { 0u },
        });
}
