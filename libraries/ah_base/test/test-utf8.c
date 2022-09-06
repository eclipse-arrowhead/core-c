// SPDX-License-Identifier: EPL-2.0

#include "ah/err.h"
#include "ah/utf8.h"

#include <ah/unit.h>
#include <string.h>

struct s_utf8_from_codepoint_test {
    ah_unit_ctx_t ctx;
    uint32_t codepoint;
    ah_err_t expected_err;
    const char* expected_result;
};

struct s_utf8_validation_test {
    ah_unit_ctx_t ctx;
    const char* input; // Terminated by \0.
    bool expected_result;
};

void s_should_produce_ut8_from_codepoints(ah_unit_res_t* res);
void s_should_validate_utf8_strings(ah_unit_res_t* res);

void test_utf8(ah_unit_res_t* res)
{
    s_should_produce_ut8_from_codepoints(res);
    s_should_validate_utf8_strings(res);
}

void s_assert_utf8_from_codepoint_tests(ah_unit_res_t* res, struct s_utf8_from_codepoint_test* tests)
{
    for (struct s_utf8_from_codepoint_test* test = &tests[0u]; test->codepoint != 0u; test = &test[1u]) {
        char buf[6u] = { 0u, 0u, 0u, 0u, 0u, 0u };
        size_t buf_size = sizeof(buf);

        ah_err_t err = ah_utf8_from_codepoint(test->codepoint, buf, &buf_size);
        if (ah_unit_assert_eq_err(test->ctx, res, err, test->expected_err) && err == AH_ENONE) {
            (void) ah_unit_assert_eq_str(test->ctx, res, buf, buf_size, test->expected_result, strlen(test->expected_result));
        }
    }
}

void s_should_produce_ut8_from_codepoints(ah_unit_res_t* res)
{
    s_assert_utf8_from_codepoint_tests(res,
        (struct s_utf8_from_codepoint_test[]) {
            { AH_UNIT_CTX, 0x000020, AH_ENONE, " " },
            { AH_UNIT_CTX, 0x000040, AH_ENONE, "@" },
            { AH_UNIT_CTX, 0x0000C5, AH_ENONE, "Å" },
            { AH_UNIT_CTX, 0x000126, AH_ENONE, "Ħ" },
            { AH_UNIT_CTX, 0x000E01, AH_ENONE, "ก" },
            { AH_UNIT_CTX, 0x0010A0, AH_ENONE, "Ⴀ" },
            { AH_UNIT_CTX, 0x00D800, AH_EINVAL, "" },
            { AH_UNIT_CTX, 0x00DC43, AH_EINVAL, "" },
            { AH_UNIT_CTX, 0x00DFFF, AH_EINVAL, "" },
            { AH_UNIT_CTX, 0x00EFD7, AH_ENONE, "\uEFD7" },
            { AH_UNIT_CTX, 0x010900, AH_ENONE, "\xF0\x90\xA4\x80" },
            { AH_UNIT_CTX, 0x10FFFF, AH_ENONE, "\xF4\x8F\xBF\xBF" },
            { AH_UNIT_CTX, 0x110000, AH_EINVAL, "" },
            { AH_UNIT_CTX, 0xFFFFFF, AH_EINVAL, "" },
            { AH_UNIT_CTX, 0xFFFFFFFF, AH_EINVAL, "" },
            { { 0u }, 0u, 0u, NULL },
        });
}

void s_assert_utf8_validation_tests(ah_unit_res_t* res, struct s_utf8_validation_test* tests)
{
    for (struct s_utf8_validation_test* test = &tests[0u]; test->input != NULL; test = &test[1u]) {
        bool actual_result = ah_utf8_validate(test->input, strlen(test->input));
        if (actual_result != test->expected_result) {
            ah_unit_fail(test->ctx, res, "got `%s`; expected `%s`",
                actual_result ? "true" : "false", test->expected_result ? "true" : "false");
            continue;
        }
        ah_unit_pass(res);
    }
}

void s_should_validate_utf8_strings(ah_unit_res_t* res)
{
    s_assert_utf8_validation_tests(res,
        (struct s_utf8_validation_test[]) {
            { AH_UNIT_CTX, "", true },
            { AH_UNIT_CTX, "\xC0\x80", false },
            { AH_UNIT_CTX, "\xC0\x22", false },
            { AH_UNIT_CTX, "1", true },
            { AH_UNIT_CTX, "A", true },
            { AH_UNIT_CTX, "Ö", true },
            { AH_UNIT_CTX, "猫", true },
            { AH_UNIT_CTX, "Beåutífül 猫!", true },
            { AH_UNIT_CTX, "\xE2\x82", false },
            { AH_UNIT_CTX, "\xE2\x82\xAC", true },
            { AH_UNIT_CTX, "€", true },
            { AH_UNIT_CTX, "\xE0\x82\xAC", false },
            { AH_UNIT_CTX, "\xF0\x90\x8D\x88", true },
            { AH_UNIT_CTX, "한", true },
            { AH_UNIT_CTX, "\xF0\x80\x8D\x88", false },
            { AH_UNIT_CTX, "\xF0\x80\x80\x80", false },
            { AH_UNIT_CTX, "This is a longer string with an invalid sequence here: '\xE0\x80\x80'.", false },
            { { 0u }, 0u, false },
        });
}
