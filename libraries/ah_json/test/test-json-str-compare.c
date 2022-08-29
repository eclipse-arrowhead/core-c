// SPDX-License-Identifier: EPL-2.0

#include "ah/json.h"

#include <ah/unit.h>
#include <string.h>

struct s_json_compare_test {
    ah_unit_ctx_t ctx;
    const char* a; // Terminated by \0.
    const char* b; // Terminated by \0.
    int expected_result;
};

void s_should_consider_certain_strings_equal(ah_unit_res_t* res);
void s_should_consider_certain_strings_not_equal(ah_unit_res_t* res);

void test_json_str_compare(ah_unit_res_t* res)
{
    s_should_consider_certain_strings_equal(res);
    s_should_consider_certain_strings_not_equal(res);
}

void s_assert_json_compare_tests(ah_unit_res_t* res, struct s_json_compare_test* tests)
{
    for (struct s_json_compare_test* test = &tests[0u]; test->a != NULL; test = &test[1u]) {
        int actual_result = ah_json_str_compare(test->a, strlen(test->a), test->b, strlen(test->b));

        if (actual_result > 0) {
            actual_result = 1;
        }
        else if (actual_result < 0) {
            actual_result = -1;
        }

        if (actual_result != test->expected_result) {
            ah_unit_fail(test->ctx, res, "comparison of \"%s\" and \"%s\" produced %d; expected %d",
                test->a, test->b, actual_result, test->expected_result);
            continue;
        }
        ah_unit_pass(res);
    }
}

void s_should_consider_certain_strings_equal(ah_unit_res_t* res)
{
    s_assert_json_compare_tests(res,
        (struct s_json_compare_test[]) {
            { AH_UNIT_CTX, "", "", 0 },
            { AH_UNIT_CTX, "a", "a", 0 },
            { AH_UNIT_CTX, "B", "B", 0 },
            { AH_UNIT_CTX, "cc", "cc", 0 },
            { AH_UNIT_CTX, "DdDd", "DdDd", 0 },
            { AH_UNIT_CTX, "Two words!", "Two words!", 0 },
            { AH_UNIT_CTX, "\\u00f6", "ö", 0 },
            { AH_UNIT_CTX, "Ä", "\\u00C4", 0 },
            { AH_UNIT_CTX, "猫", "\\u732B", 0 },
            { AH_UNIT_CTX, "Åk!", "\\u00C5k!", 0 },
            { { 0u } },
        });
}

void s_should_consider_certain_strings_not_equal(ah_unit_res_t* res)
{
    s_assert_json_compare_tests(res,
        (struct s_json_compare_test[]) {
            { AH_UNIT_CTX, "0", "", 1 },
            { AH_UNIT_CTX, "", "0", -1 },
            { AH_UNIT_CTX, "Ba", "Bb", -1 },
            { AH_UNIT_CTX, "aB", "bB", -1 },
            { AH_UNIT_CTX, "2", "1", 1 },
            { AH_UNIT_CTX, "Two words!!", "Two words!", 1 },
            { AH_UNIT_CTX, "\\u00f6", "Ö", 1 },
            { AH_UNIT_CTX, "ä", "\\u00C4", 1 },
            { AH_UNIT_CTX, "猫", "\\u732C", -1 },
            { AH_UNIT_CTX, "Åk?", "\\u00C5k!", 1 },
            { { 0u } },
        });
}
