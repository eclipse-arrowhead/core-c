// SPDX-License-Identifier: EPL-2.0

#include "ah/json.h"

#include <ah/err.h>
#include <ah/unit.h>
#include <inttypes.h>

struct s_json_parse_test {
    ah_unit_ctx_t ctx;
    const char* source; // Terminated by \0.
    ah_err_t expected_err;
    ah_json_val_t* expected_val; // Terminated by value with NULL base.
};

static void s_should_fail_to_parse_invalid_sources(ah_unit_res_t* res);
static void s_should_parse_arrays(ah_unit_res_t* res);
static void s_should_parse_keywords(ah_unit_res_t* res);
static void s_should_parse_numbers(ah_unit_res_t* res);
static void s_should_parse_objects(ah_unit_res_t* res);
static void s_should_parse_strings(ah_unit_res_t* res);

void test_json_parse(ah_unit_res_t* res)
{
    s_should_fail_to_parse_invalid_sources(res);
    s_should_parse_arrays(res);
    s_should_parse_keywords(res);
    s_should_parse_numbers(res);
    s_should_parse_objects(res);
    s_should_parse_strings(res);
}

static void s_assert_json_parse_tests(ah_unit_res_t* res, struct s_json_parse_test* tests)
{
    for (struct s_json_parse_test* test = &tests[0u]; test->source != NULL; test = &test[1u]) {
        ah_json_buf_t buf = { .capacity = 16u, .length = 0u, .values = (ah_json_val_t[16u]) { { 0u } } };

        ah_err_t err = ah_json_parse(ah_buf_from((uint8_t*) test->source, strlen(test->source)), &buf);
        if (!ah_unit_assert_eq_err(test->ctx, res, err, test->expected_err)) {
            continue;
        }

        ah_json_val_t* expected_val = test->expected_val;
        ah_json_val_t* actual_val = &buf.values[0u];

        size_t expected_i = 0u;
        for (;; expected_val = &expected_val[1u], expected_i += 1u, actual_val = &actual_val[1u]) {
            if (expected_val->base == NULL) {
                break;
            }

            if (expected_i == buf.length) {
                ah_unit_fail(test->ctx, res, "expected another value of type `%" PRIuMAX "`; parse result contains no more values",
                    (uintmax_t) expected_val->type);
                break;
            }
            ah_unit_pass(res);

            if (expected_val->type != actual_val->type) {
                ah_unit_fail(test->ctx, res, "got type `%" PRIuMAX "`; expected type `%" PRIuMAX "`",
                    (uintmax_t) actual_val->type, (uintmax_t) expected_val->type);
                continue;
            }
            ah_unit_pass(res);

            if (expected_val->type != AH_JSON_TYPE_OBJECT && expected_val->type != AH_JSON_TYPE_ARRAY) {
                if (expected_val->length != actual_val->length || memcmp(expected_val->base, actual_val->base, expected_val->length) != 0) {
                    ah_unit_fail(test->ctx, res, "got value `%.*s`; expected value `%.*s`",
                        actual_val->length, actual_val->base, expected_val->length, expected_val->base);
                    continue;
                }
                ah_unit_pass(res);
            }
            else {
                if (expected_val->length != actual_val->length) {
                    ah_unit_fail(test->ctx, res, "got length `%" PRIuMAX "`; expected length `%" PRIuMAX "`",
                        (uintmax_t) actual_val->length, (uintmax_t) expected_val->length);
                    continue;
                }
                ah_unit_pass(res);
            }

            if (expected_val->level != actual_val->level) {
                ah_unit_fail(test->ctx, res, "got level `%" PRIuMAX "`; expected level `%" PRIuMAX "`",
                    (uintmax_t) actual_val->level, (uintmax_t) expected_val->level);
                continue;
            }
            ah_unit_pass(res);
        }

        if (expected_i != buf.length) {
            ah_unit_fail(test->ctx, res, "got value length `%zu`; expected value length `%zu`",
                buf.length, expected_i);
            continue;
        }
        ah_unit_pass(res);
    }
}

static void s_should_fail_to_parse_invalid_sources(ah_unit_res_t* res)
{
    s_assert_json_parse_tests(res,
        (struct s_json_parse_test[]) {
            {
                AH_UNIT_CTX,
                "",
                AH_EEOF,
                (ah_json_val_t[]) {
                    { 0u },
                },
            },
            {
                AH_UNIT_CTX,
                "\t",
                AH_EEOF,
                (ah_json_val_t[]) {
                    { 0u },
                },
            },
            {
                AH_UNIT_CTX,
                "[",
                AH_EEOF,
                (ah_json_val_t[]) {
                    { "[", AH_JSON_TYPE_ARRAY, 0u, 0u },
                    { 0u },
                },
            },
            {
                AH_UNIT_CTX,
                " 1 f",
                AH_ESYNTAX,
                (ah_json_val_t[]) {
                    { "1", AH_JSON_TYPE_NUMBER, 0u, 1u },
                    { "f", AH_JSON_TYPE_ERROR, 0u, 1u },
                    { 0u },
                },
            },
            {
                AH_UNIT_CTX,
                " [] bad",
                AH_ESYNTAX,
                (ah_json_val_t[]) {
                    { "[", AH_JSON_TYPE_ARRAY, 0u, 0u },
                    { "b", AH_JSON_TYPE_ERROR, 0u, 1u },
                    { 0u },
                },
            },
            {
                AH_UNIT_CTX,
                "{\"a\"}",
                AH_ESYNTAX,
                (ah_json_val_t[]) {
                    { "{", AH_JSON_TYPE_OBJECT, 0u, 2u },
                    { "a", AH_JSON_TYPE_STRING, 1u, 1u },
                    { "}", AH_JSON_TYPE_ERROR, 1u, 1u },
                    { 0u },
                },
            },
            { { 0u } },
        });
}

static void s_should_parse_arrays(ah_unit_res_t* res)
{
    s_assert_json_parse_tests(res,
        (struct s_json_parse_test[]) {
            {
                AH_UNIT_CTX,
                "[]",
                AH_ENONE,
                (ah_json_val_t[]) {
                    { "[", AH_JSON_TYPE_ARRAY, 0u, 0u },
                    { 0u },
                },
            },
            {
                AH_UNIT_CTX,
                " [\t ] ",
                AH_ENONE,
                (ah_json_val_t[]) {
                    { "[", AH_JSON_TYPE_ARRAY, 0u, 0u },
                    { 0u },
                },
            },
            {
                AH_UNIT_CTX,
                "[ 1] ",
                AH_ENONE,
                (ah_json_val_t[]) {
                    { "[", AH_JSON_TYPE_ARRAY, 0u, 1u },
                    { "1", AH_JSON_TYPE_NUMBER, 1u, 1u },
                    { 0u },
                },
            },
            {
                AH_UNIT_CTX,
                "\t[2 , []]",
                AH_ENONE,
                (ah_json_val_t[]) {
                    { "[", AH_JSON_TYPE_ARRAY, 0u, 2u },
                    { "2", AH_JSON_TYPE_NUMBER, 1u, 1u },
                    { "[", AH_JSON_TYPE_ARRAY, 1u, 0u },
                    { 0u },
                },
            },
            {
                AH_UNIT_CTX,
                "[{\"a\": [ [ ]] }, true, null, [[[] ]] ]",
                AH_ENONE,
                (ah_json_val_t[]) {
                    { "[", AH_JSON_TYPE_ARRAY, 0u, 4u },
                    { "{", AH_JSON_TYPE_OBJECT, 1u, 2u },
                    { "a", AH_JSON_TYPE_STRING, 2u, 1u },
                    { "[", AH_JSON_TYPE_ARRAY, 2u, 1u },
                    { "[", AH_JSON_TYPE_ARRAY, 3u, 0u },
                    { "true", AH_JSON_TYPE_TRUE, 1u, 4u },
                    { "null", AH_JSON_TYPE_NULL, 1u, 4u },
                    { "[", AH_JSON_TYPE_ARRAY, 1u, 1u },
                    { "[", AH_JSON_TYPE_ARRAY, 2u, 1u },
                    { "[", AH_JSON_TYPE_ARRAY, 3u, 0u },
                    { 0u },
                },
            },
            { { 0u } },
        });
}

static void s_should_parse_keywords(ah_unit_res_t* res)
{
    s_assert_json_parse_tests(res,
        (struct s_json_parse_test[]) {
            {
                AH_UNIT_CTX,
                "false ",
                AH_ENONE,
                (ah_json_val_t[]) { { "false", AH_JSON_TYPE_FALSE, 0u, 5u }, { 0u } },
            },
            {
                AH_UNIT_CTX,
                " null ",
                AH_ENONE,
                (ah_json_val_t[]) { { "null", AH_JSON_TYPE_NULL, 0u, 4u }, { 0u } },
            },
            {
                AH_UNIT_CTX,
                " true ",
                AH_ENONE,
                (ah_json_val_t[]) { { "true", AH_JSON_TYPE_TRUE, 0u, 4u }, { 0u } },
            },
            { { 0u } },
        });
}

static void s_should_parse_numbers(ah_unit_res_t* res)
{
    s_assert_json_parse_tests(res,
        (struct s_json_parse_test[]) {
            {
                AH_UNIT_CTX,
                "1      ",
                AH_ENONE,
                (ah_json_val_t[]) { { "1", AH_JSON_TYPE_NUMBER, 0u, 1u }, { 0u } },
            },
            {
                AH_UNIT_CTX,
                " -41   ",
                AH_ENONE,
                (ah_json_val_t[]) { { "-41", AH_JSON_TYPE_NUMBER, 0u, 3u }, { 0u } },
            },
            {
                AH_UNIT_CTX,
                "  3.67 ",
                AH_ENONE,
                (ah_json_val_t[]) { { "3.67", AH_JSON_TYPE_NUMBER, 0u, 4u }, { 0u } },
            },
            {
                AH_UNIT_CTX,
                "-0.53  ",
                AH_ENONE,
                (ah_json_val_t[]) { { "-0.53", AH_JSON_TYPE_NUMBER, 0u, 5u }, { 0u } },
            },
            {
                AH_UNIT_CTX,
                " 109E2 ",
                AH_ENONE,
                (ah_json_val_t[]) { { "109E2", AH_JSON_TYPE_NUMBER, 0u, 5u }, { 0u } },
            },
            {
                AH_UNIT_CTX,
                "\t7E+18",
                AH_ENONE,
                (ah_json_val_t[]) { { "7E+18", AH_JSON_TYPE_NUMBER, 0u, 5u }, { 0u } },
            },
            {
                AH_UNIT_CTX,
                "1.0e-24",
                AH_ENONE,
                (ah_json_val_t[]) { { "1.0e-24", AH_JSON_TYPE_NUMBER, 0u, 7u }, { 0u } },
            },
            { { 0u } },
        });
}

static void s_should_parse_objects(ah_unit_res_t* res)
{
    s_assert_json_parse_tests(res,
        (struct s_json_parse_test[]) {
            {
                AH_UNIT_CTX,
                "{}",
                AH_ENONE,
                (ah_json_val_t[]) {
                    { "{", AH_JSON_TYPE_OBJECT, 0u, 0u },
                    { 0u },
                },
            },
            {
                AH_UNIT_CTX,
                " {  \t} ",
                AH_ENONE,
                (ah_json_val_t[]) {
                    { "[", AH_JSON_TYPE_OBJECT, 0u, 0u },
                    { 0u },
                },
            },
            {
                AH_UNIT_CTX,
                "{ \"a\" : 1 }",
                AH_ENONE,
                (ah_json_val_t[]) {
                    { "{", AH_JSON_TYPE_OBJECT, 0u, 2u },
                    { "a", AH_JSON_TYPE_STRING, 1u, 1u },
                    { "1", AH_JSON_TYPE_NUMBER, 1u, 1u },
                    { 0u },
                },
            },
            {
                AH_UNIT_CTX,
                "\t{\"b\":[],\"c\":3}\t",
                AH_ENONE,
                (ah_json_val_t[]) {
                    { "{", AH_JSON_TYPE_OBJECT, 0u, 4u },
                    { "b", AH_JSON_TYPE_STRING, 1u, 1u },
                    { "[", AH_JSON_TYPE_ARRAY, 1u, 0u },
                    { "c", AH_JSON_TYPE_STRING, 1u, 1u },
                    { "3", AH_JSON_TYPE_NUMBER, 1u, 1u },
                    { 0u },
                },
            },
            {
                AH_UNIT_CTX,
                "{ \"d\": {\"e\":[]}, \"f\":[[[]]], \"gh\": 7 }",
                AH_ENONE,
                (ah_json_val_t[]) {
                    { "{", AH_JSON_TYPE_OBJECT, 0u, 6u },
                    { "d", AH_JSON_TYPE_STRING, 1u, 1u },
                    { "{", AH_JSON_TYPE_OBJECT, 1u, 2u },
                    { "e", AH_JSON_TYPE_STRING, 2u, 1u },
                    { "[", AH_JSON_TYPE_ARRAY, 2u, 0u },
                    { "f", AH_JSON_TYPE_STRING, 1u, 1u },
                    { "[", AH_JSON_TYPE_ARRAY, 1u, 1u },
                    { "[", AH_JSON_TYPE_ARRAY, 2u, 1u },
                    { "[", AH_JSON_TYPE_ARRAY, 3u, 0u },
                    { "gh", AH_JSON_TYPE_STRING, 1u, 2u },
                    { "7", AH_JSON_TYPE_NUMBER, 1u, 1u },
                    { 0u },
                },
            },
            { { 0u } },
        });
}

static void s_should_parse_strings(ah_unit_res_t* res)
{
    s_assert_json_parse_tests(res,
        (struct s_json_parse_test[]) {
            {
                AH_UNIT_CTX,
                "\"Hello, Arrowhead!\"",
                AH_ENONE,
                (ah_json_val_t[]) { { "Hello, Arrowhead!", AH_JSON_TYPE_STRING, 0u, 17u }, { 0u } },
            },
            {
                AH_UNIT_CTX,
                "\"Hello, UTF-8 ÅÄÖ!\"",
                AH_ENONE,
                (ah_json_val_t[]) { { "Hello, UTF-8 ÅÄÖ!", AH_JSON_TYPE_STRING, 0u, 20u }, { 0u } },
            },
            {
                AH_UNIT_CTX,
                "\"Space \\\"\\u0020\\\"\"",
                AH_ENONE,
                (ah_json_val_t[]) { { "Space \\\"\\u0020\\\"", AH_JSON_TYPE_STRING, 0u, 16u }, { 0u } },
            },
            { { 0u } },
        });
}
