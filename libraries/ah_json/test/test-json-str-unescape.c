// SPDX-License-Identifier: EPL-2.0

#include "ah/json.h"

#include <ah/err.h>
#include <ah/unit.h>

struct s_json_unescape_test {
    const char* input; // Terminated by \0.
    ah_err_t expected_err;
    const char* expected_output; // Terminated by \0.
};

void s_should_fail_to_unescape_invalid_strings(ah_unit_t* unit);
void s_should_unescape_valid_strings(ah_unit_t* unit);

void test_json_str_unescape(ah_unit_t* unit)
{
    s_should_fail_to_unescape_invalid_strings(unit);
    s_should_unescape_valid_strings(unit);
}

void s_assert_json_unescape_tests(ah_unit_t* unit, const char* label, struct s_json_unescape_test* tests)
{
    char buf[32u];

    size_t test_i = 0u;
    for (struct s_json_unescape_test* test = &tests[0u]; test->input != NULL; test = &test[1u], test_i += 1u) {
        memset(buf, 0, sizeof(buf));
        size_t actual_length = sizeof(buf);

        ah_err_t err = ah_json_str_unescape(test->input, strlen(test->input), buf, &actual_length);
        if (err != test->expected_err) {
            char actual_err_buf[128u];
            ah_strerror_r(err, actual_err_buf, sizeof(actual_err_buf));

            char expected_err_buf[128u];
            ah_strerror_r(test->expected_err, expected_err_buf, sizeof(expected_err_buf));

            ah_unit_failf(unit, "%s [%zu]:\n\tescaping failed with error `%d: %s`; expected error `%d: %s`",
                label, test_i, err, actual_err_buf, test->expected_err, expected_err_buf);
            continue;
        }
        ah_unit_pass(unit);

        if (actual_length != strlen(test->expected_output) || memcmp(buf, test->expected_output, actual_length) != 0) {
            ah_unit_failf(unit, "%s [%zu]:\n\texpected value `%s` not matching actual value `%s`",
                label, test_i, test->expected_output, buf);
            continue;
        }
        ah_unit_pass(unit);
    }
}

void s_should_fail_to_unescape_invalid_strings(ah_unit_t* unit)
{
    s_assert_json_unescape_tests(unit, __func__,
        (struct s_json_unescape_test[]) {
            [0] = { "\\", AH_ESYNTAX, "" },
            [1] = { "\\0", AH_ESYNTAX, "" },
            [2] = { "\\0F", AH_ESYNTAX, "" },
            [3] = { "\\u00d", AH_ESYNTAX, "" },
            [4] = { "\\u?", AH_ESYNTAX, "" },
            [5] = { "\\u00FZ", AH_ESYNTAX, "" },
            [6] = { "Hello \\xFF!", AH_ESYNTAX, "Hello " },
            [7] = { "\\u", AH_ESYNTAX, "" },
            [8] = { "\\t\\x", AH_ESYNTAX, "\t" },
            [9] = { "\\x\\t", AH_ESYNTAX, "" },
            { 0u },
        });
}

void s_should_unescape_valid_strings(ah_unit_t* unit)
{
    s_assert_json_unescape_tests(unit, __func__,
        (struct s_json_unescape_test[]) {
            [0] = { "", AH_ENONE, "" },
            [1] = { "a", AH_ENONE, "a" },
            [2] = { "\\u00f6", AH_ENONE, "ö" },
            [3] = { "\\u00C4", AH_ENONE, "Ä" },
            [4] = { "\\u732B", AH_ENONE, "猫" },
            [5] = { "\\u00C5k!", AH_ENONE, "Åk!" },
            [6] = { "\\\" \\\\ \\/ \\b \\f \\n \\r \\t", AH_ENONE, "\" \\ / \b \f \n \r \t" },
            { 0u },
        });
}
