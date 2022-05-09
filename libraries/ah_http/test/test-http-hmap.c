// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include <ah/err.h>
#include <ah/unit.h>

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
    err = ah_i_http_hmap_init(&headers, (struct ah_i_http_hmap_header[4u]) { 0u }, 2u);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    // Add headers.

    err = ah_http_hmap_add(&headers, ah_str_from_cstr("host"), ah_str_from_cstr("192.168.40.40:40404"));
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    err = ah_http_hmap_add(&headers, ah_str_from_cstr("content-type"), ah_str_from_cstr("application/json"));
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    // Capacity is 2; this should fail.
    err = ah_http_hmap_add(&headers, ah_str_from_cstr("content-length"), ah_str_from_cstr("16"));
    if (!ah_unit_assert_err_eq(unit, AH_ENOBUFS, err)) {
        return;
    }

    // Get headers.

    bool has_next;
    const ah_str_t* value;

    value = ah_http_hmap_get_value(&headers, ah_str_from_cstr("Host"), &has_next);
    if (!ah_unit_assert(unit, !has_next, "there should only exist one host name/value pair")) {
        return;
    }
    if (!ah_unit_assert_str_eq(unit, ah_str_from_cstr("192.168.40.40:40404"), *value)) {
        return;
    }

    value = ah_http_hmap_get_value(&headers, ah_str_from_cstr("Content-Type"), &has_next);
    if (!ah_unit_assert(unit, !has_next, "there should only exist one host name/value pair")) {
        return;
    }
    if (!ah_unit_assert_str_eq(unit, ah_str_from_cstr("application/json"), *value)) {
        return;
    }

    // This header should not be present.
    value = ah_http_hmap_get_value(&headers, ah_str_from_cstr("Content-Length"), &has_next);
    if (!ah_unit_assert(unit, value == NULL, "expected value to be NULL")) {
        return;
    }
}

static void s_should_add_same_header_name_multiple_times(ah_unit_t* unit)
{
    ah_err_t err;

    ah_http_hmap_t headers;
    err = ah_i_http_hmap_init(&headers, (struct ah_i_http_hmap_header[4u]) { 0u }, 4u);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    // Add headers.

    err = ah_http_hmap_add(&headers, ah_str_from_cstr("set-cookie"), ah_str_from_cstr("munchy"));
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    err = ah_http_hmap_add(&headers, ah_str_from_cstr("SET-CookIe"), ah_str_from_cstr("crispy"));
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    err = ah_http_hmap_add(&headers, ah_str_from_cstr("Host"), ah_str_from_cstr("[::1]:12345"));
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    err = ah_http_hmap_add(&headers, ah_str_from_cstr("Set-Cookie"), ah_str_from_cstr("sweet"));
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    // Get headers.

    ah_http_hmap_value_iter_t iter = ah_http_hmap_get_iter(&headers, ah_str_from_cstr("Set-Cookie"));

    const ah_str_t* value;

    value = ah_http_hmap_next_fiv(&iter);
    if (!ah_unit_assert_str_eq(unit, ah_str_from_cstr("munchy"), *value)) {
        return;
    }

    value = ah_http_hmap_next_fiv(&iter);
    if (!ah_unit_assert_str_eq(unit, ah_str_from_cstr("crispy"), *value)) {
        return;
    }

    value = ah_http_hmap_next_fiv(&iter);
    if (!ah_unit_assert_str_eq(unit, ah_str_from_cstr("sweet"), *value)) {
        return;
    }

    value = ah_http_hmap_next_fiv(&iter);
    if (!ah_unit_assert(unit, value == NULL, "expected value to be NULL")) {
        return;
    }
}
