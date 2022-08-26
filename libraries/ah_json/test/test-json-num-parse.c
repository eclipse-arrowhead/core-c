// SPDX-License-Identifier: EPL-2.0

#include "ah/json.h"

#include <ah/err.h>
#include <ah/unit.h>
#include <inttypes.h>

struct s_json_num_parse_int32_test {
    const char* input; // Terminated by \0.
    ah_err_t expected_err;
    int32_t expected_result;
};

struct s_json_num_validation_test {
    const char* input; // Terminated by \0.
    bool expected_result;
};

void s_should_parse_int32_numbers(ah_unit_t* unit);
void s_should_validate_utf8_strings(ah_unit_t* unit);

void test_json_num_parse(ah_unit_t* unit)
{
    s_should_parse_int32_numbers(unit);
    s_should_validate_utf8_strings(unit);
}

void s_assert_json_num_parse_int32_tests(ah_unit_t* unit, const char* label, struct s_json_num_parse_int32_test* tests)
{
    int32_t actual_result;

    size_t test_i = 0u;
    for (struct s_json_num_parse_int32_test* test = &tests[0u]; test->input != NULL; test = &test[1u], test_i += 1u) {
        actual_result = INT32_MIN;

        ah_err_t err = ah_json_num_parse_int32(test->input, strlen(test->input), &actual_result);
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

        if (actual_result != test->expected_result) {
            ah_unit_failf(unit, "%s [%zu]:\n\texpected value `%" PRId32 "` not matching actual value `%" PRId32 "`",
                label, test_i, test->expected_result, actual_result);
            continue;
        }
        ah_unit_pass(unit);
    }
}

void s_should_parse_int32_numbers(ah_unit_t* unit)
{
    s_assert_json_num_parse_int32_tests(unit, __func__,
        (struct s_json_num_parse_int32_test[]) {
            [0] = { "", AH_ESYNTAX, INT32_MIN },
            [1] = { "a", AH_ESYNTAX, INT32_MIN },
            [2] = { "0", AH_ENONE, 0 },
            [3] = { "1", AH_ENONE, 1 },
            [4] = { "11", AH_ENONE, 11 },
            [5] = { "01", AH_ESYNTAX, INT32_MIN },
            [6] = { "203", AH_ENONE, 203 },
            [7] = { "-2147483648", AH_ENONE, -2147483648 },
            [8] = { "-2147483649", AH_ERANGE, INT32_MIN },
            [9] = { "2147483647", AH_ENONE, 2147483647 },
            [10] = { "2147483648", AH_ERANGE, INT32_MIN },
            [11] = { "456.", AH_ESYNTAX, INT32_MIN },
            [12] = { "456.0", AH_ENONE, 456 },
            [13] = { "789.000", AH_ENONE, 789 },
            [14] = { "1234.567", AH_EDOM, 1234 },
            [15] = { "0e+0", AH_ENONE, 0 },
            [16] = { "12E-0", AH_ENONE, 12 },
            [17] = { "54E00001", AH_ENONE, 540 },
            [18] = { "1e9", AH_ENONE, 1000000000 },
            [19] = { "1.000000000e+9", AH_ENONE, 1000000000 },
            [20] = { "1.1e9", AH_EOPNOTSUPP, INT32_MIN },
            [21] = { "1.0e-0", AH_ENONE, 1 },
            [22] = { "1.0e0x", AH_ESYNTAX, INT32_MIN },
            [23] = { "1 ", AH_ESYNTAX, INT32_MIN },
            [24] = { " 1", AH_ESYNTAX, INT32_MIN },
            [25] = { "1234.0000e-0000", AH_ENONE, 1234 },
            [26] = { "1234.0000E+0000", AH_ENONE, 1234 },
            [27] = { "1234.567e+00000", AH_EDOM, 1234 },
            { 0u },
        });
}

void s_assert_json_num_validation_tests(ah_unit_t* unit, const char* label, struct s_json_num_validation_test* tests)
{
    size_t test_i = 0u;
    for (struct s_json_num_validation_test* test = &tests[0u]; test->input != NULL; test = &test[1u], test_i += 1u) {
        bool actual_result = ah_json_num_validate(test->input, strlen(test->input));
        if (actual_result != test->expected_result) {
            ah_unit_failf(unit, "%s [%zu]:\n\texpected `%s`; actual result is `%s`",
                label, test_i, test->expected_result ? "true" : "false", actual_result ? "true" : "false");
            continue;
        }
        ah_unit_pass(unit);
    }
}

void s_should_validate_utf8_strings(ah_unit_t* unit)
{
    s_assert_json_num_validation_tests(unit, __func__,
        (struct s_json_num_validation_test[]) {
            [0] = { "", false },
            [1] = { "a", false },
            [2] = { "0", true },
            [3] = { "1", true },
            [4] = { "11", true },
            [5] = { "01", false },
            [6] = { "203", true },
            [7] = { "-2147483648", true },
            [8] = { "-2147483649", true },
            [9] = { "2147483647", true },
            [10] = { "2147483648", true },
            [11] = { "456.", false },
            [12] = { "456.0", true },
            [13] = { "789.000", true },
            [14] = { "1234.567", true },
            [15] = { "0e0", true },
            [16] = { "12e-0", true },
            [17] = { "54E-1", true },
            [18] = { "1e+9", true },
            [19] = { "1.000000000E+9", true },
            [20] = { "1.1e9", true },
            [21] = { "1.0E0", true },
            [22] = { "1.0e0x", false },
            [23] = { "1 ", false },
            [24] = { " 1", false },
            { 0u },
        });
}
