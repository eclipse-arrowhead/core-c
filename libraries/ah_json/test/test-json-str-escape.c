// SPDX-License-Identifier: EPL-2.0

#include "ah/json.h"

#include <ah/err.h>
#include <ah/unit.h>
#include <string.h>

struct s_json_escape_test {
    ah_unit_ctx_t ctx;
    const char* input; // Terminated by \0.
    ah_err_t expected_err;
    const char* expected_output; // Terminated by \0.
};

void s_should_escape_strings(ah_unit_res_t* res);

void test_json_str_escape(ah_unit_res_t* res)
{
    s_should_escape_strings(res);
}

void s_assert_json_escape_tests(ah_unit_res_t* res, struct s_json_escape_test* tests)
{
    char actual[16u];

    for (struct s_json_escape_test* test = &tests[0u]; test->input != NULL; test = &test[1u]) {
        memset(actual, 0, sizeof(actual));
        size_t actual_length = sizeof(actual);

        ah_err_t err = ah_json_str_escape(test->input, strlen(test->input), actual, &actual_length);
        if (ah_unit_assert_eq_err(test->ctx, res, err, test->expected_err)) {
            (void) ah_unit_assert_eq_str(test->ctx, res, actual, actual_length, test->expected_output, strlen(test->expected_output));
        }
    }
}

void s_should_escape_strings(ah_unit_res_t* res)
{
    s_assert_json_escape_tests(res,
        (struct s_json_escape_test[]) {
            { AH_UNIT_CTX, "", AH_ENONE, "" },
            { AH_UNIT_CTX, "a", AH_ENONE, "a" },
            { AH_UNIT_CTX, "\x01", AH_ENONE, "\\u0001" },
            { AH_UNIT_CTX, "\t\r\n", AH_ENONE, "\\t\\r\\n" },
            { AH_UNIT_CTX, "\b\f", AH_ENONE, "\\b\\f" },
            { AH_UNIT_CTX, "\x1F", AH_ENONE, "\\u001F" },
            { AH_UNIT_CTX, "111100001111\x01", AH_EOVERFLOW, "111100001111" },
            { { 0u }, NULL, 0u, NULL },
        });
}
