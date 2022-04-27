// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "../src/http-hmap.h"

#include <ah/err.h>
#include <ah/unit.h>
#include <stdlib.h>

static void s_should_add_and_get_headers(ah_unit_t* unit);
static void s_should_add_same_header_name_multiple_times(ah_unit_t* unit);

void test_http_hmap(ah_unit_t* unit)
{
    s_should_add_and_get_headers(unit);
    s_should_add_same_header_name_multiple_times(unit);
}

static void s_should_add_and_get_headers(ah_unit_t* unit)
{
    ah_err_t err;

    ah_http_hmap_t headers;
    err = ah_i_http_hmap_init(&headers, realloc, 2u);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    // Add headers.

    err = ah_i_http_hmap_add(&headers, ah_str_nt("host"), ah_str_nt("192.168.40.40:40404"));
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        goto term;
    }

    err = ah_i_http_hmap_add(&headers, ah_str_nt("content-type"), ah_str_nt("application/json"));
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        goto term;
    }

    // Capacity is 2; this should fail.
    err = ah_i_http_hmap_add(&headers, ah_str_nt("content-length"), ah_str_nt("16"));
    if (!ah_unit_assert_err_eq(unit, AH_ENOBUFS, err)) {
        goto term;
    }

    // Get headers.

    bool has_next;
    const ah_str_t* value;

    value = ah_http_hmap_get_value(&headers, ah_str_nt("Host"), &has_next);
    if (!ah_unit_assert(unit, !has_next, "there should only exist one host name/value pair")) {
        goto term;
    }
    if (!ah_unit_assert_str_eq(unit, ah_str_nt("192.168.40.40:40404"), *value)) {
        goto term;
    }

    value = ah_http_hmap_get_value(&headers, ah_str_nt("Content-Type"), &has_next);
    if (!ah_unit_assert(unit, !has_next, "there should only exist one host name/value pair")) {
        goto term;
    }
    if (!ah_unit_assert_str_eq(unit, ah_str_nt("application/json"), *value)) {
        goto term;
    }

    // This header should not be present.
    value = ah_http_hmap_get_value(&headers, ah_str_nt("Content-Length"), &has_next);
    if (!ah_unit_assert(unit, value == NULL, "expected value to be NULL")) {
        goto term;
    }

term:
    ah_i_http_hmap_term(&headers, realloc);
}

static void s_should_add_same_header_name_multiple_times(ah_unit_t* unit)
{
    ah_err_t err;

    ah_http_hmap_t headers;
    err = ah_i_http_hmap_init(&headers, realloc, 4u);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    // Add headers.

    err = ah_i_http_hmap_add(&headers, ah_str_nt("set-cookie"), ah_str_nt("munchy"));
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        goto term;
    }

    err = ah_i_http_hmap_add(&headers, ah_str_nt("SET-CookIe"), ah_str_nt("crispy"));
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        goto term;
    }

    err = ah_i_http_hmap_add(&headers, ah_str_nt("Host"), ah_str_nt("[::1]:12345"));
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        goto term;
    }

    err = ah_i_http_hmap_add(&headers, ah_str_nt("Set-Cookie"), ah_str_nt("sweet"));
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        goto term;
    }

    // Get headers.

    ah_http_hmap_value_iter_t iter = ah_http_hmap_get_values(&headers, ah_str_nt("Set-Cookie"));

    const ah_str_t* value;

    value = ah_http_hmap_next_value(&iter);
    if (!ah_unit_assert_str_eq(unit, ah_str_nt("munchy"), *value)) {
        goto term;
    }

    value = ah_http_hmap_next_value(&iter);
    if (!ah_unit_assert_str_eq(unit, ah_str_nt("crispy"), *value)) {
        goto term;
    }

    value = ah_http_hmap_next_value(&iter);
    if (!ah_unit_assert_str_eq(unit, ah_str_nt("sweet"), *value)) {
        goto term;
    }

    value = ah_http_hmap_next_value(&iter);
    if (!ah_unit_assert(unit, value == NULL, "expected value to be NULL")) {
        goto term;
    }

term:
    ah_i_http_hmap_term(&headers, realloc);
}
