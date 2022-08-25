// SPDX-License-Identifier: EPL-2.0

#include "ah/json.h"

#include <ah/err.h>
#include <ah/unit.h>

struct s_json_escape_test {
    const char* input; // Terminated by \0.
    ah_err_t expected_err;
    const char* expected_output; // Terminated by \0.
};

void s_should_escape_strings(ah_unit_t* unit);

void test_json_str_escape(ah_unit_t* unit)
{
    s_should_escape_strings(unit);
}

void s_assert_json_escape_tests(ah_unit_t* unit, const char* label, struct s_json_escape_test* tests)
{
    char buf[16u];

    size_t test_i = 0u;
    for (struct s_json_escape_test* test = &tests[0u]; test->input != NULL; test = &test[1u], test_i += 1u) {
        memset(buf, 0, sizeof(buf));
        size_t actual_length = sizeof(buf);

        ah_err_t err = ah_json_str_escape(test->input, strlen(test->input), buf, &actual_length);
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

void s_should_escape_strings(ah_unit_t* unit)
{
    s_assert_json_escape_tests(unit, __func__,
        (struct s_json_escape_test[]) {
            [0] = { "", AH_ENONE, "" },
            [1] = { "a", AH_ENONE, "a" },
            [2] = { "\x01", AH_ENONE, "\\u0001" },
            [3] = { "\t\r\n", AH_ENONE, "\\t\\r\\n" },
            [4] = { "\b\f", AH_ENONE, "\\b\\f" },
            [5] = { "\x1F", AH_ENONE, "\\u001F" },
            [6] = { "111100001111\x01", AH_EOVERFLOW, "111100001111" },
            { 0u },
        });
}
