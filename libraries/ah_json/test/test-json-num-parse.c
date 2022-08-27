// SPDX-License-Identifier: EPL-2.0

#include "ah/json.h"

#include <ah/err.h>
#include <ah/unit.h>
#include <inttypes.h>

struct s_json_num_parse_int32_test {
    ah_unit_ctx_t ctx;
    const char* input; // Terminated by \0.
    ah_err_t expected_err;
    int32_t expected_result;
};

struct s_json_num_validation_test {
    ah_unit_ctx_t ctx;
    const char* input; // Terminated by \0.
    bool expected_result;
};

void s_should_parse_int32_numbers(ah_unit_res_t* res);
void s_should_validate_utf8_strings(ah_unit_res_t* res);

void test_json_num_parse(ah_unit_res_t* res)
{
    s_should_parse_int32_numbers(res);
    s_should_validate_utf8_strings(res);
}

void s_assert_json_num_parse_int32_tests(ah_unit_res_t* res, struct s_json_num_parse_int32_test* tests)
{
    int32_t actual_result;

    for (struct s_json_num_parse_int32_test* test = &tests[0u]; test->input != NULL; test = &test[1u]) {
        actual_result = INT32_MIN;

        ah_err_t err = ah_json_num_parse_int32(test->input, strlen(test->input), &actual_result);
        if (ah_unit_assert_eq_err(test->ctx, res, err, test->expected_err)) {
            (void) ah_unit_assert_eq_intmax(test->ctx, res, actual_result, test->expected_result);
        }
    }
}

void s_should_parse_int32_numbers(ah_unit_res_t* res)
{
    s_assert_json_num_parse_int32_tests(res,
        (struct s_json_num_parse_int32_test[]) {
            { AH_UNIT_CTX, "", AH_ESYNTAX, INT32_MIN },
            { AH_UNIT_CTX, "a", AH_ESYNTAX, INT32_MIN },
            { AH_UNIT_CTX, "0", AH_ENONE, 0 },
            { AH_UNIT_CTX, "1", AH_ENONE, 1 },
            { AH_UNIT_CTX, "11", AH_ENONE, 11 },
            { AH_UNIT_CTX, "01", AH_ESYNTAX, INT32_MIN },
            { AH_UNIT_CTX, "203", AH_ENONE, 203 },
            { AH_UNIT_CTX, "-2147483648", AH_ENONE, -2147483648 },
            { AH_UNIT_CTX, "-2147483649", AH_ERANGE, INT32_MIN },
            { AH_UNIT_CTX, "2147483647", AH_ENONE, 2147483647 },
            { AH_UNIT_CTX, "2147483648", AH_ERANGE, INT32_MIN },
            { AH_UNIT_CTX, "456.", AH_ESYNTAX, INT32_MIN },
            { AH_UNIT_CTX, "456.0", AH_ENONE, 456 },
            { AH_UNIT_CTX, "789.000", AH_ENONE, 789 },
            { AH_UNIT_CTX, "1234.567", AH_EDOM, 1234 },
            { AH_UNIT_CTX, "0e+0", AH_ENONE, 0 },
            { AH_UNIT_CTX, "12E-0", AH_ENONE, 12 },
            { AH_UNIT_CTX, "54E00001", AH_ENONE, 540 },
            { AH_UNIT_CTX, "1e9", AH_ENONE, 1000000000 },
            { AH_UNIT_CTX, "1.000000000e+9", AH_ENONE, 1000000000 },
            { AH_UNIT_CTX, "1.1e9", AH_EOPNOTSUPP, INT32_MIN },
            { AH_UNIT_CTX, "1.0e-0", AH_ENONE, 1 },
            { AH_UNIT_CTX, "1.0e0x", AH_ESYNTAX, INT32_MIN },
            { AH_UNIT_CTX, "1 ", AH_ESYNTAX, INT32_MIN },
            { AH_UNIT_CTX, " 1", AH_ESYNTAX, INT32_MIN },
            { AH_UNIT_CTX, "1234.0000e-0000", AH_ENONE, 1234 },
            { AH_UNIT_CTX, "1234.0000E+0000", AH_ENONE, 1234 },
            { AH_UNIT_CTX, "1234.567e+00000", AH_EDOM, 1234 },
            { { 0u } },
        });
}

void s_assert_json_num_validation_tests(ah_unit_res_t* res, struct s_json_num_validation_test* tests)
{
    for (struct s_json_num_validation_test* test = &tests[0u]; test->input != NULL; test = &test[1u]) {
        bool actual_result = ah_json_num_validate(test->input, strlen(test->input));
        if (actual_result != test->expected_result) {
            ah_unit_fail(test->ctx, res, "\n\tgot `%s`; expected `%s`",
                actual_result ? "true" : "false", test->expected_result ? "true" : "false");
            continue;
        }
        ah_unit_pass(res);
    }
}

void s_should_validate_utf8_strings(ah_unit_res_t* res)
{
    s_assert_json_num_validation_tests(res,
        (struct s_json_num_validation_test[]) {
            { AH_UNIT_CTX, "", false },
            { AH_UNIT_CTX, "a", false },
            { AH_UNIT_CTX, "0", true },
            { AH_UNIT_CTX, "1", true },
            { AH_UNIT_CTX, "11", true },
            { AH_UNIT_CTX, "01", false },
            { AH_UNIT_CTX, "203", true },
            { AH_UNIT_CTX, "-2147483648", true },
            { AH_UNIT_CTX, "-2147483649", true },
            { AH_UNIT_CTX, "2147483647", true },
            { AH_UNIT_CTX, "2147483648", true },
            { AH_UNIT_CTX, "456.", false },
            { AH_UNIT_CTX, "456.0", true },
            { AH_UNIT_CTX, "789.000", true },
            { AH_UNIT_CTX, "1234.567", true },
            { AH_UNIT_CTX, "0e0", true },
            { AH_UNIT_CTX, "12e-0", true },
            { AH_UNIT_CTX, "54E-1", true },
            { AH_UNIT_CTX, "1e+9", true },
            { AH_UNIT_CTX, "1.000000000E+9", true },
            { AH_UNIT_CTX, "1.1e9", true },
            { AH_UNIT_CTX, "1.0E0", true },
            { AH_UNIT_CTX, "1.0e0x", false },
            { AH_UNIT_CTX, "1 ", false },
            { AH_UNIT_CTX, " 1", false },
            { { 0u } },
        });
}
