// SPDX-License-Identifier: EPL-2.0

#include "ah/json.h"

#include <ah/err.h>
#include <ah/unit.h>
#include <string.h>

struct s_json_unescape_test {
    ah_unit_ctx_t ctx;
    const char* input; // Terminated by \0.
    ah_err_t expected_err;
    const char* expected_output; // Terminated by \0.
};

void s_should_fail_to_unescape_invalid_strings(ah_unit_res_t* res);
void s_should_unescape_valid_strings(ah_unit_res_t* res);

void test_json_str_unescape(ah_unit_res_t* res)
{
    s_should_fail_to_unescape_invalid_strings(res);
    s_should_unescape_valid_strings(res);
}

void s_assert_json_unescape_tests(ah_unit_res_t* res, struct s_json_unescape_test* tests)
{
    char actual[32u];

    size_t test_i = 0u;
    for (struct s_json_unescape_test* test = &tests[0u]; test->input != NULL; test = &test[1u], test_i += 1u) {
        memset(actual, 0, sizeof(actual));
        size_t actual_length = sizeof(actual);

        ah_err_t err = ah_json_str_unescape(test->input, strlen(test->input), actual, &actual_length);
        if (ah_unit_assert_eq_err(test->ctx, res, err, test->expected_err)) {
            (void) ah_unit_assert_eq_str(test->ctx, res, actual, actual_length, test->expected_output, strlen(test->expected_output));
        }
    }
}

void s_should_fail_to_unescape_invalid_strings(ah_unit_res_t* res)
{
    s_assert_json_unescape_tests(res,
        (struct s_json_unescape_test[]) {
            { AH_UNIT_CTX, "\\", AH_ESYNTAX, "" },
            { AH_UNIT_CTX, "\\0", AH_ESYNTAX, "" },
            { AH_UNIT_CTX, "\\0F", AH_ESYNTAX, "" },
            { AH_UNIT_CTX, "\\u00d", AH_ESYNTAX, "" },
            { AH_UNIT_CTX, "\\u?", AH_ESYNTAX, "" },
            { AH_UNIT_CTX, "\\u00FZ", AH_ESYNTAX, "" },
            { AH_UNIT_CTX, "Hello \\xFF!", AH_ESYNTAX, "Hello " },
            { AH_UNIT_CTX, "\\u", AH_ESYNTAX, "" },
            { AH_UNIT_CTX, "\\t\\x", AH_ESYNTAX, "\t" },
            { AH_UNIT_CTX, "\\x\\t", AH_ESYNTAX, "" },
            { { 0u } },
        });
}

void s_should_unescape_valid_strings(ah_unit_res_t* res)
{
    s_assert_json_unescape_tests(res,
        (struct s_json_unescape_test[]) {
            { AH_UNIT_CTX, "", AH_ENONE, "" },
            { AH_UNIT_CTX, "a", AH_ENONE, "a" },
            { AH_UNIT_CTX, "\\u00f6", AH_ENONE, "ö" },
            { AH_UNIT_CTX, "\\u00C4", AH_ENONE, "Ä" },
            { AH_UNIT_CTX, "\\u732B", AH_ENONE, "猫" },
            { AH_UNIT_CTX, "\\u00C5k!", AH_ENONE, "Åk!" },
            { AH_UNIT_CTX, "\\\" \\\\ \\/ \\b \\f \\n \\r \\t", AH_ENONE, "\" \\ / \b \f \n \r \t" },
            { { 0u } },
        });
}
