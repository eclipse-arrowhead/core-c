// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "../src/http-parser.h"

#include "../src/http-hmap.h"

#include <ah/err.h>
#include <ah/unit.h>

static void s_should_parse_headers(ah_unit_t* unit);
static void s_should_parse_request_lines(ah_unit_t* unit);
static void s_should_parse_status_lines(ah_unit_t* unit);

static ah_i_http_reader_t s_reader_of(const char* str);

void test_http_parser(ah_unit_t* unit)
{
    s_should_parse_headers(unit);
    s_should_parse_request_lines(unit);
    s_should_parse_status_lines(unit);
}

static void s_should_parse_headers(ah_unit_t* unit)
{
    ah_err_t err;
    ah_i_http_reader_t r;

    ah_http_hmap_t headers;
    err = ah_i_http_hmap_init(&headers, (struct ah_i_http_hmap_header[4u]) { 0u }, 4u);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    r = s_reader_of("Accept: application/json, application/cbor\r\n"
                    "Content-Type: application/json; charset=utf-8\r\n"
                    "Content-Length:   143  \r\n"
                    "Host:  192.168.4.44:44444 \r\n"
                    "\r\n");

    err = ah_i_http_parse_headers(&r, &headers);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    bool has_next;
    const ah_str_t* value;

    value = ah_http_hmap_get_value(&headers, ah_str_from_cstr("Host"), &has_next);
    if (!ah_unit_assert(unit, !has_next, "there should only exist one host header")) {
        return;
    }
    if (!ah_unit_assert(unit, value != NULL, "no host header exists")) {
        return;
    }
    if (!ah_unit_assert_str_eq(unit, ah_str_from_cstr("192.168.4.44:44444"), *value)) {
        return;
    }

    value = ah_http_hmap_get_value(&headers, ah_str_from_cstr("Content-Type"), &has_next);
    if (!ah_unit_assert(unit, !has_next, "there should only exist one content-type header")) {
        return;
    }
    if (!ah_unit_assert(unit, value != NULL, "no content-type header exists")) {
        return;
    }
    if (!ah_unit_assert_str_eq(unit, ah_str_from_cstr("application/json; charset=utf-8"), *value)) {
        return;
    }

    value = ah_http_hmap_get_value(&headers, ah_str_from_cstr("CONTENT-LENGTH"), &has_next);
    if (!ah_unit_assert(unit, !has_next, "there should only exist one content-length header")) {
        return;
    }
    if (!ah_unit_assert(unit, value != NULL, "no content-length header exists")) {
        return;
    }
    if (!ah_unit_assert_str_eq(unit, ah_str_from_cstr("143"), *value)) {
        return;
    }

    value = ah_http_hmap_get_value(&headers, ah_str_from_cstr("Accept"), &has_next);
    if (!ah_unit_assert(unit, !has_next, "there should only exist one accept header")) {
        return;
    }
    if (!ah_unit_assert(unit, value != NULL, "no accept header exists")) {
        return;
    }
    if (!ah_unit_assert_str_eq(unit, ah_str_from_cstr("application/json, application/cbor"), *value)) {
        return;
    }
}

static ah_i_http_reader_t s_reader_of(const char* str)
{
    ah_i_http_reader_t r;
    r._off = &((const uint8_t*) str)[0u];
    r._end = &((const uint8_t*) str)[strlen(str)];
    return r;
}

static void s_should_parse_request_lines(ah_unit_t* unit)
{
    ah_err_t err;
    ah_i_http_reader_t r;
    ah_http_req_line_t req_line;

    r = s_reader_of("GET /things/132 HTTP/1.1\r\n");
    err = ah_i_http_parse_req_line(&r, &req_line);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    (void) ah_unit_assert_str_eq(unit, ah_str_from_cstr("GET"), req_line.method);
    (void) ah_unit_assert_str_eq(unit, ah_str_from_cstr("/things/132"), req_line.target);
    (void) ah_unit_assert_unsigned_eq(unit, 1u, req_line.version.major);
    (void) ah_unit_assert_unsigned_eq(unit, 1u, req_line.version.minor);

    r = s_reader_of("OPTIONS * HTTP/1.0\r\n");
    err = ah_i_http_parse_req_line(&r, &req_line);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    (void) ah_unit_assert_str_eq(unit, ah_str_from_cstr("OPTIONS"), req_line.method);
    (void) ah_unit_assert_str_eq(unit, ah_str_from_cstr("*"), req_line.target);
    (void) ah_unit_assert_unsigned_eq(unit, 1u, req_line.version.major);
    (void) ah_unit_assert_unsigned_eq(unit, 0u, req_line.version.minor);

    r = s_reader_of("CONNECT [::1]:44444 HTTP/1.1\r\n");
    err = ah_i_http_parse_req_line(&r, &req_line);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    (void) ah_unit_assert_str_eq(unit, ah_str_from_cstr("CONNECT"), req_line.method);
    (void) ah_unit_assert_str_eq(unit, ah_str_from_cstr("[::1]:44444"), req_line.target);
    (void) ah_unit_assert_unsigned_eq(unit, 1u, req_line.version.major);
    (void) ah_unit_assert_unsigned_eq(unit, 1u, req_line.version.minor);
}

static void s_should_parse_status_lines(ah_unit_t* unit)
{
    ah_err_t err;
    ah_i_http_reader_t r;
    ah_http_stat_line_t stat_line;

    r = s_reader_of("HTTP/1.1 200 OK\r\n");
    err = ah_i_http_parse_stat_line(&r, &stat_line);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    (void) ah_unit_assert_unsigned_eq(unit, 1u, stat_line.version.major);
    (void) ah_unit_assert_unsigned_eq(unit, 1u, stat_line.version.minor);
    (void) ah_unit_assert_unsigned_eq(unit, 200u, stat_line.code);
    (void) ah_unit_assert_str_eq(unit, ah_str_from_cstr("OK"), stat_line.reason);

    r = s_reader_of("HTTP/1.0 201 \r\n");
    err = ah_i_http_parse_stat_line(&r, &stat_line);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    (void) ah_unit_assert_unsigned_eq(unit, 1u, stat_line.version.major);
    (void) ah_unit_assert_unsigned_eq(unit, 0u, stat_line.version.minor);
    (void) ah_unit_assert_unsigned_eq(unit, 201u, stat_line.code);
    (void) ah_unit_assert_str_eq(unit, ah_str_from_cstr(""), stat_line.reason);

    r = s_reader_of("HTTP/1.1 500 Internal server errör \r\n");
    err = ah_i_http_parse_stat_line(&r, &stat_line);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    (void) ah_unit_assert_unsigned_eq(unit, 1u, stat_line.version.major);
    (void) ah_unit_assert_unsigned_eq(unit, 1u, stat_line.version.minor);
    (void) ah_unit_assert_unsigned_eq(unit, 500u, stat_line.code);
    (void) ah_unit_assert_str_eq(unit, ah_str_from_cstr("Internal server errör "), stat_line.reason);
}
