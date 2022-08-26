// SPDX-License-Identifier: EPL-2.0

#include "ah/utf8.h"

#include <ah/err.h>
#include <ah/unit.h>
#include <string.h>

struct s_utf8_from_codepoint_test {
    uint32_t codepoint;
    ah_err_t expected_err;
    const char* expected_result;
};

struct s_utf8_validation_test {
    const char* input; // Terminated by \0.
    bool expected_result;
};

void s_should_produce_ut8_from_codepoints(ah_unit_t* unit);
void s_should_validate_utf8_strings(ah_unit_t* unit);

void test_utf8(ah_unit_t* unit)
{
    s_should_produce_ut8_from_codepoints(unit);
    s_should_validate_utf8_strings(unit);
}

void s_assert_utf8_from_codepoint_tests(ah_unit_t* unit, const char* label, struct s_utf8_from_codepoint_test* tests)
{
    size_t test_i = 0u;
    for (struct s_utf8_from_codepoint_test* test = &tests[0u]; test->codepoint != 0u; test = &test[1u], test_i += 1u) {
        char buf[6u] = {0u, 0u, 0u, 0u, 0u, 0u};
        size_t buf_size = sizeof(buf);

        ah_err_t err = ah_utf8_from_codepoint(test->codepoint, buf, &buf_size);
        if (err != test->expected_err) {
            char actual_err_buf[128u];
            ah_strerror_r(err, actual_err_buf, sizeof(actual_err_buf));

            char expected_err_buf[128u];
            ah_strerror_r(test->expected_err, expected_err_buf, sizeof(expected_err_buf));

            ah_unit_failf(unit, "%s [%zu]:\n\texpected error `%d: %s`; actual error is `%d: %s`",
                label, test_i, test->expected_err, expected_err_buf, err, actual_err_buf);
            continue;
        }
        ah_unit_pass(unit);

        if (err != AH_ENONE) {
            continue;
        }

        if (buf_size != strlen(test->expected_result) || memcmp(buf, test->expected_result, buf_size) != 0) {
            ah_unit_failf(unit, "%s [%zu]:\n\texpected `%s`; actual result is `%s`",
                label, test_i, test->expected_result, buf);
            continue;
        }
        ah_unit_pass(unit);
    }
}

void s_should_produce_ut8_from_codepoints(ah_unit_t* unit)
{
    s_assert_utf8_from_codepoint_tests(unit, __func__,
        (struct s_utf8_from_codepoint_test[]) {
            [0] = { 0x000020, AH_ENONE, " " },
            [1] = { 0x000040, AH_ENONE, "@" },
            [2] = { 0x0000C5, AH_ENONE, "Å" },
            [3] = { 0x000126, AH_ENONE, "Ħ" },
            [4] = { 0x000E01, AH_ENONE, "ก" },
            [5] = { 0x0010A0, AH_ENONE, "Ⴀ" },
            [6] = { 0x00D800, AH_EINVAL, "" },
            [7] = { 0x00DC43, AH_EINVAL, "" },
            [8] = { 0x00DFFF, AH_EINVAL, "" },
            [9] = { 0x00EFD7, AH_ENONE, "\uEFD7" },
            [10] = { 0x010900, AH_ENONE, "\xF0\x90\xA4\x80" },
            [11] = { 0x10FFFF, AH_ENONE, "\xF4\x8F\xBF\xBF" },
            [12] = { 0x110000, AH_EINVAL, "" },
            [13] = { 0xFFFFFF, AH_EINVAL, "" },
            [14] = { 0xFFFFFFFF, AH_EINVAL, "" },
            { 0u },
        });
}

void s_assert_utf8_validation_tests(ah_unit_t* unit, const char* label, struct s_utf8_validation_test* tests)
{
    size_t test_i = 0u;
    for (struct s_utf8_validation_test* test = &tests[0u]; test->input != NULL; test = &test[1u], test_i += 1u) {
        bool actual_result = ah_utf8_validate(test->input, strlen(test->input));
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
    s_assert_utf8_validation_tests(unit, __func__,
        (struct s_utf8_validation_test[]) {
            [0] = { "", true },
            [1] = { "\xC0\x80", false },
            [2] = { "\xC0\x22", false },
            [3] = { "1", true },
            [4] = { "A", true },
            [5] = { "Ö", true },
            [6] = { "猫", true },
            [7] = { "Beåutífül 猫!", true },
            [8] = { "\xE2\x82", false },
            [9] = { "\xE2\x82\xAC", true },
            [10] = { "€", true },
            [11] = { "\xE0\x82\xAC", false },
            [12] = { "\xF0\x90\x8D\x88", true },
            [13] = { "한", true },
            [14] = { "\xF0\x80\x8D\x88", false },
            [15] = { "\xF0\x80\x80\x80", false },
            [16] = { "This is a longer string with an invalid sequence here: '\xE0\x80\x80'.", false },
            { 0u },
        });
}
