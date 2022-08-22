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
        size_t actual_length = sizeof(buf);

        ah_err_t err = ah_json_str_unescape(test->input, strlen(test->input), buf, &actual_length);
        if (err != test->expected_err) {
            char actual_err_buf[128u];
            ah_strerror_r(err, actual_err_buf, sizeof(actual_err_buf));

            char expected_err_buf[128u];
            ah_strerror_r(test->expected_err, expected_err_buf, sizeof(expected_err_buf));

            ah_unit_failf(unit, "%s [%zu]:\n\tparsing failed with error `%d: %s`; expected error `%d: %s`",
                label, test_i, err, actual_err_buf, test->expected_err, expected_err_buf);
            continue;
        }
        ah_unit_pass(unit);

        if (actual_length != strlen(test->expected_output) || memcmp(buf, test->expected_output, actual_length) != 0) {
            ah_unit_failf(unit, "%s [%zu]:\n\texpected value `%s` not matching actual value `%s`",
                label, test_i, test, test->expected_output, buf);
            continue;
        }
        ah_unit_pass(unit);
    }
}

void s_should_fail_to_unescape_invalid_strings(ah_unit_t* unit)
{
    s_assert_json_unescape_tests(unit, __func__,
        (struct s_json_unescape_test[]) {
            [0] = { "\\", AH_EILSEQ, "" },
            [1] = { "\\0", AH_EILSEQ, "" },
            [2] = { "\\0F", AH_EILSEQ, "" },
            [3] = { "\\u00d", AH_EILSEQ, "" },
            [4] = { "\\u?", AH_EILSEQ, "" },
            [5] = { "\\u00FZ", AH_EILSEQ, "" },
            [6] = { "Hello \\xFF!", AH_EILSEQ, "Hello " },
            [7] = { "\\u", AH_EILSEQ, "" },
            [8] = { "\\t\\x", AH_EILSEQ, "\t" },
            [9] = { "\\x\\t", AH_EILSEQ, "" },
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
