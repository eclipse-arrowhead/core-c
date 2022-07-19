// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/json.h"

#include <ah/err.h>
#include <ah/unit.h>
#include <inttypes.h>

struct s_json_parse_test {
    const char* source; // Terminated by \0.
    ah_err_t expected_err;
    ah_json_val_t* expected_val; // Terminated by value with NULL base.
};

static void s_should_fail_to_parse_invalid_sources(ah_unit_t* unit);
static void s_should_parse_arrays(ah_unit_t* unit);
static void s_should_parse_keywords(ah_unit_t* unit);
static void s_should_parse_numbers(ah_unit_t* unit);
static void s_should_parse_objects(ah_unit_t* unit);
static void s_should_parse_strings(ah_unit_t* unit);

void test_json_parse(ah_unit_t* unit)
{
    s_should_fail_to_parse_invalid_sources(unit);
    s_should_parse_arrays(unit);
    s_should_parse_keywords(unit);
    s_should_parse_numbers(unit);
    s_should_parse_objects(unit);
    s_should_parse_strings(unit);
}

static void s_assert_json_parse_tests(ah_unit_t* unit, const char* label, struct s_json_parse_test* tests)
{
    size_t test_i = 0u;
    for (struct s_json_parse_test* test = &tests[0u]; test->source != NULL; test = &test[1u], test_i += 1u) {
        ah_json_buf_t buf = { .capacity = 16u, .length = 0u, .values = (ah_json_val_t[16u]) { { 0u } } };

        ah_err_t err = ah_json_parse(ah_buf_from((uint8_t*) test->source, strlen(test->source)), &buf);
        if (err != test->expected_err) {
            ah_unit_failf(unit, "%s [%zu]:\n\tparsing failed with error `%d: %s`; expected `%d: %s`",
                label, test_i, err, ah_strerror(err), test->expected_err, ah_strerror(test->expected_err));
            continue;
        }
        ah_unit_pass(unit);

        ah_json_val_t* expected_val = test->expected_val;
        ah_json_val_t* actual_val = &buf.values[0u];

        size_t expected_length = 0u;
        for (;; expected_val = &expected_val[1u], expected_length += 1u, actual_val = &actual_val[1u]) {
            if (expected_val->base == NULL || expected_length == buf.length) {
                break;
            }

            if (expected_val->type != actual_val->type) {
                ah_unit_failf(unit, "%s [%zu:%zu]:\n\texpected type `%" PRIuMAX "` not matching actual type `%" PRIuMAX "`",
                    label, test_i, expected_length, (uintmax_t) expected_val->type, (uintmax_t) actual_val->type);
                continue;
            }
            ah_unit_pass(unit);

            if (expected_val->type != AH_JSON_TYPE_OBJECT && expected_val->type != AH_JSON_TYPE_ARRAY) {
                if (expected_val->length != actual_val->length || memcmp(expected_val->base, actual_val->base, expected_val->length) != 0) {
                    ah_unit_failf(unit, "%s [%zu:%zu]:\n\texpected value `%.*s` not matching actual value `%.*s`",
                        label, test_i, expected_length, expected_val->length, expected_val->base, actual_val->length, actual_val->base);
                    continue;
                }
                ah_unit_pass(unit);
            }
            else {
                if (expected_val->length != actual_val->length) {
                    ah_unit_failf(unit, "%s [%zu:%zu]:\n\texpected length `%" PRIuMAX "` not matching actual length `%" PRIuMAX "`",
                        label, test_i, expected_length, (uintmax_t) expected_val->length, (uintmax_t) actual_val->length);
                    continue;
                }
                ah_unit_pass(unit);
            }

            if (expected_val->level != actual_val->level) {
                ah_unit_failf(unit, "%s [%zu:%zu]:\n\texpected level `%" PRIuMAX "` not matching actual level `%" PRIuMAX "`",
                    label, test_i, expected_length, (uintmax_t) expected_val->level, (uintmax_t) actual_val->level);
                continue;
            }
            ah_unit_pass(unit);
        }

        if (expected_length != buf.length) {
            ah_unit_failf(unit, "%s [%zu]:\n\texpected value length `%zu` not matching actual length `%zu`",
                label, test_i, expected_length, buf.length);
            continue;
        }
        ah_unit_pass(unit);
    }
}

static void s_should_fail_to_parse_invalid_sources(ah_unit_t* unit)
{
    s_assert_json_parse_tests(unit, __func__,
        (struct s_json_parse_test[]) {
            [0] = {
                "[",
                AH_EEOF,
                (ah_json_val_t[]) {
                    { "[", AH_JSON_TYPE_ARRAY, 0u, 0u },
                    { "", AH_JSON_TYPE_ERROR, 0u, 0u },
                    { 0u },
                },
            },
            [1] = {
                " 1 f",
                AH_EILSEQ,
                (ah_json_val_t[]) {
                    { "1", AH_JSON_TYPE_NUMBER, 0u, 1u },
                    { "f", AH_JSON_TYPE_ERROR, 0u, 1u },
                    { 0u },
                },
            },
            [2] = {
                " [] bad",
                AH_EILSEQ,
                (ah_json_val_t[]) {
                    { "[", AH_JSON_TYPE_ARRAY, 0u, 0u },
                    { "b", AH_JSON_TYPE_ERROR, 0u, 1u },
                    { 0u },
                },
            },
            [3] = {
                "\tx",
                AH_EILSEQ,
                (ah_json_val_t[]) {
                    { "x", AH_JSON_TYPE_ERROR, 0u, 1u },
                    { 0u },
                },
            },
            [4] = {
                "{\"a\"}",
                AH_EILSEQ,
                (ah_json_val_t[]) {
                    { "{", AH_JSON_TYPE_OBJECT, 0u, 2u },
                    { "a", AH_JSON_TYPE_STRING, 1u, 1u },
                    { "}", AH_JSON_TYPE_ERROR, 1u, 1u },
                    { 0u },
                },
            },
            { 0u },
        });
}

static void s_should_parse_arrays(ah_unit_t* unit)
{
    s_assert_json_parse_tests(unit, __func__,
        (struct s_json_parse_test[]) {
            [0] = {
                "[]",
                AH_ENONE,
                (ah_json_val_t[]) {
                    { "[", AH_JSON_TYPE_ARRAY, 0u, 0u },
                    { 0u },
                },
            },
            [1] = {
                " [\t ] ",
                AH_ENONE,
                (ah_json_val_t[]) {
                    { "[", AH_JSON_TYPE_ARRAY, 0u, 0u },
                    { 0u },
                },
            },
            [2] = {
                "[ 1] ",
                AH_ENONE,
                (ah_json_val_t[]) {
                    { "[", AH_JSON_TYPE_ARRAY, 0u, 1u },
                    { "1", AH_JSON_TYPE_NUMBER, 1u, 1u },
                    { 0u },
                },
            },
            [3] = {
                "\t[2 , []]",
                AH_ENONE,
                (ah_json_val_t[]) {
                    { "[", AH_JSON_TYPE_ARRAY, 0u, 2u },
                    { "2", AH_JSON_TYPE_NUMBER, 1u, 1u },
                    { "[", AH_JSON_TYPE_ARRAY, 1u, 0u },
                    { 0u },
                },
            },
            [4] = {
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
            { 0u },
        });
}

static void s_should_parse_keywords(ah_unit_t* unit)
{
    s_assert_json_parse_tests(unit, __func__,
        (struct s_json_parse_test[]) {
            [0] = {
                "false ",
                AH_ENONE,
                (ah_json_val_t[]) { { "false", AH_JSON_TYPE_FALSE, 0u, 5u }, { 0u } },
            },
            [1] = {
                " null ",
                AH_ENONE,
                (ah_json_val_t[]) { { "null", AH_JSON_TYPE_NULL, 0u, 4u }, { 0u } },
            },
            [2] = {
                " true ",
                AH_ENONE,
                (ah_json_val_t[]) { { "true", AH_JSON_TYPE_TRUE, 0u, 4u }, { 0u } },
            },
            { 0u },
        });
}

static void s_should_parse_numbers(ah_unit_t* unit)
{
    s_assert_json_parse_tests(unit, __func__,
        (struct s_json_parse_test[]) {
            [0] = {
                "1      ",
                AH_ENONE,
                (ah_json_val_t[]) { { "1", AH_JSON_TYPE_NUMBER, 0u, 1u }, { 0u } },
            },
            [1] = {
                " -41   ",
                AH_ENONE,
                (ah_json_val_t[]) { { "-41", AH_JSON_TYPE_NUMBER, 0u, 3u }, { 0u } },
            },
            [2] = {
                "  3.67 ",
                AH_ENONE,
                (ah_json_val_t[]) { { "3.67", AH_JSON_TYPE_NUMBER, 0u, 4u }, { 0u } },
            },
            [3] = {
                "-0.53  ",
                AH_ENONE,
                (ah_json_val_t[]) { { "-0.53", AH_JSON_TYPE_NUMBER, 0u, 5u }, { 0u } },
            },
            [4] = {
                " 109E2 ",
                AH_ENONE,
                (ah_json_val_t[]) { { "109E2", AH_JSON_TYPE_NUMBER, 0u, 5u }, { 0u } },
            },
            [5] = {
                "\t7E+18",
                AH_ENONE,
                (ah_json_val_t[]) { { "7E+18", AH_JSON_TYPE_NUMBER, 0u, 5u }, { 0u } },
            },
            [6] = {
                "1.0e-24",
                AH_ENONE,
                (ah_json_val_t[]) { { "1.0e-24", AH_JSON_TYPE_NUMBER, 0u, 7u }, { 0u } },
            },
            { 0u },
        });
}

static void s_should_parse_objects(ah_unit_t* unit)
{
    s_assert_json_parse_tests(unit, __func__,
        (struct s_json_parse_test[]) {
            [0] = {
                "{}",
                AH_ENONE,
                (ah_json_val_t[]) {
                    { "{", AH_JSON_TYPE_OBJECT, 0u, 0u },
                    { 0u },
                },
            },
            [1] = {
                " {  \t} ",
                AH_ENONE,
                (ah_json_val_t[]) {
                    { "[", AH_JSON_TYPE_OBJECT, 0u, 0u },
                    { 0u },
                },
            },
            [2] = {
                "{ \"a\" : 1 }",
                AH_ENONE,
                (ah_json_val_t[]) {
                    { "{", AH_JSON_TYPE_OBJECT, 0u, 2u },
                    { "a", AH_JSON_TYPE_STRING, 1u, 1u },
                    { "1", AH_JSON_TYPE_NUMBER, 1u, 1u },
                    { 0u },
                },
            },
            [3] = {
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
            [4] = {
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
            { 0u },
        });
}

static void s_should_parse_strings(ah_unit_t* unit)
{
    s_assert_json_parse_tests(unit, __func__,
        (struct s_json_parse_test[]) {
            [0] = {
                "\"Hello, Arrowhead!\"",
                AH_ENONE,
                (ah_json_val_t[]) { { "Hello, Arrowhead!", AH_JSON_TYPE_STRING, 0u, 17u }, { 0u } },
            },
            [1] = {
                "\"Hello, UTF-8 ÅÄÖ!\"",
                AH_ENONE,
                (ah_json_val_t[]) { { "Hello, UTF-8 ÅÄÖ!", AH_JSON_TYPE_STRING, 0u, 20u }, { 0u } },
            },
            [2] = {
                "\"Space \\\"\\u0020\\\"\"",
                AH_ENONE,
                (ah_json_val_t[]) { { "Space \\\"\\u0020\\\"", AH_JSON_TYPE_STRING, 0u, 16u }, { 0u } },
            },
            { 0u },
        });
}
