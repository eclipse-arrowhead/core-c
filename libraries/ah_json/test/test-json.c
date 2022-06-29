// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/json.h"

#include <ah/unit.h>

struct s_json_expected_value {
    const char* base;
    size_t length;
    unsigned type;
    unsigned level;
};

struct s_json_user_data {
    struct s_json_expected_value* expected_values; // Terminated by { .base = NULL }.
    size_t value_counter;
    ah_unit_t* unit;
};

static void s_should_parse_numbers(ah_unit_t* unit);

void test_json(ah_unit_t* unit)
{
    s_should_parse_numbers(unit);
}

static void* s_check_expectation(const char* base, size_t length, unsigned type, unsigned level, void* user_data_);

static void s_should_parse_numbers(ah_unit_t* unit)
{
    struct s_json_user_data test0_user_data = {
        .expected_values = (struct s_json_expected_value[]) {
            { "1", 1u, AH_JSON_TYPE_NUMBER, 0u },
            { NULL, 0u, 0u, 0u },
        },
        .value_counter = 0u,
        .unit = unit
    };
    ah_json_parse("1", 1u, &test0_user_data, s_check_expectation);
    ah_unit_assert_unsigned_eq(unit, 1u, test0_user_data.value_counter);

    struct s_json_user_data test1_user_data = {
        .expected_values = (struct s_json_expected_value[]) {
            { "-41", 3u, AH_JSON_TYPE_NUMBER, 0u },
            { NULL, 0u, 0u, 0u },
        },
        .value_counter = 0u,
        .unit = unit
    };
    ah_json_parse("-41  ", 6u, &test1_user_data, s_check_expectation);
    ah_unit_assert_unsigned_eq(unit, 1u, test1_user_data.value_counter);

    struct s_json_user_data test2_user_data = {
        .expected_values = (struct s_json_expected_value[]) {
            { "3.67", 4u, AH_JSON_TYPE_NUMBER, 0u },
            { NULL, 0u, 0u, 0u },
        },
        .value_counter = 0u,
        .unit = unit
    };
    ah_json_parse("3.67", 5u, &test2_user_data, s_check_expectation);
    ah_unit_assert_unsigned_eq(unit, 1u, test2_user_data.value_counter);

    struct s_json_user_data test3_user_data = {
        .expected_values = (struct s_json_expected_value[]) {
            { "1.0e-214", 8u, AH_JSON_TYPE_NUMBER, 0u },
            { NULL, 0u, 0u, 0u },
        },
        .value_counter = 0u,
        .unit = unit
    };
    ah_json_parse("1.0e-214", 8u, &test3_user_data, s_check_expectation);
    ah_unit_assert_unsigned_eq(unit, 1u, test3_user_data.value_counter);
}

static void* s_check_expectation(const char* base, size_t length, unsigned type, unsigned level, void* user_data_)
{
    struct s_json_user_data* user_data = user_data_;
    ah_unit_t* unit = user_data->unit;

    struct s_json_expected_value* expected_value = &user_data->expected_values[user_data->value_counter];

    if (ah_unit_assert_unsigned_eq(unit, expected_value->length, length)) {
        ah_unit_assert_cstr_eq(unit, expected_value->base, base);
    }
    ah_unit_assert_unsigned_eq(unit, expected_value->type, type);
    ah_unit_assert_unsigned_eq(unit, expected_value->level, level);

    user_data->value_counter += 1u;
    return NULL;
}
