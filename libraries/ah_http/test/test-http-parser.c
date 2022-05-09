// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "../src/http-parser.h"

#include "ah/http.h"

#include <ah/err.h>
#include <ah/unit.h>

static void s_should_parse_chunks(ah_unit_t* unit);
static void s_should_parse_headers(ah_unit_t* unit);
static void s_should_parse_request_lines(ah_unit_t* unit);
static void s_should_parse_status_lines(ah_unit_t* unit);

static ah_buf_t s_buf_from(char* str);

void test_http_parser(ah_unit_t* unit)
{
    s_should_parse_chunks(unit);
    s_should_parse_headers(unit);
    s_should_parse_request_lines(unit);
    s_should_parse_status_lines(unit);
}

static void s_should_parse_chunks(ah_unit_t* unit)
{
    ah_err_t err;
    ah_buf_t buf;
    ah_http_chunk_line_t chunk;

    buf = s_buf_from("FEBA9810\r\n");
    err = ah_i_http_parse_chunk(&buf, NULL, &chunk);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    (void) ah_unit_assert_unsigned_eq(unit, 0xFEBA9810, chunk.size);
    (void) ah_unit_assert_str_eq(unit, ah_str_from_cstr(""), chunk.ext);

    buf = s_buf_from("AABBC;key0=val0;key1=val1\r\n");
    err = ah_i_http_parse_chunk(&buf, NULL, &chunk);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    (void) ah_unit_assert_unsigned_eq(unit, 0xAABBC, chunk.size);
    (void) ah_unit_assert_str_eq(unit, ah_str_from_cstr(";key0=val0;key1=val1"), chunk.ext);

    buf = s_buf_from("10;key0=\" val0 \";key1=\"\tval1\t\"\r\n");
    err = ah_i_http_parse_chunk(&buf, NULL, &chunk);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    (void) ah_unit_assert_unsigned_eq(unit, 0x10, chunk.size);
    (void) ah_unit_assert_str_eq(unit, ah_str_from_cstr(";key0=\" val0 \";key1=\"\tval1\t\""), chunk.ext);
}

static void s_should_parse_headers(ah_unit_t* unit)
{
    ah_err_t err;

    ah_http_hmap_t headers;
    err = ah_i_http_hmap_init(&headers, (struct ah_i_http_hmap_header[4u]) { 0u }, 4u);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    ah_buf_t buf = s_buf_from(
        "Accept: application/json, application/cbor\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Content-Length:   143  \r\n"
        "Host:  192.168.4.44:44444 \r\n"
        "\r\n");

    err = ah_i_http_parse_headers(&buf, NULL, &headers);
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
    if (value != NULL && !ah_unit_assert_str_eq(unit, ah_str_from_cstr("192.168.4.44:44444"), *value)) {
        return;
    }

    value = ah_http_hmap_get_value(&headers, ah_str_from_cstr("Content-Type"), &has_next);
    if (!ah_unit_assert(unit, !has_next, "there should only exist one content-type header")) {
        return;
    }
    if (!ah_unit_assert(unit, value != NULL, "no content-type header exists")) {
        return;
    }
    if (value != NULL && !ah_unit_assert_str_eq(unit, ah_str_from_cstr("application/json; charset=utf-8"), *value)) {
        return;
    }

    value = ah_http_hmap_get_value(&headers, ah_str_from_cstr("CONTENT-LENGTH"), &has_next);
    if (!ah_unit_assert(unit, !has_next, "there should only exist one content-length header")) {
        return;
    }
    if (!ah_unit_assert(unit, value != NULL, "no content-length header exists")) {
        return;
    }
    if (value != NULL && !ah_unit_assert_str_eq(unit, ah_str_from_cstr("143"), *value)) {
        return;
    }

    value = ah_http_hmap_get_value(&headers, ah_str_from_cstr("Accept"), &has_next);
    if (!ah_unit_assert(unit, !has_next, "there should only exist one accept header")) {
        return;
    }
    if (!ah_unit_assert(unit, value != NULL, "no accept header exists")) {
        return;
    }
    if (value != NULL && !ah_unit_assert_str_eq(unit, ah_str_from_cstr("application/json, application/cbor"), *value)) {
        return;
    }
}

static ah_buf_t s_buf_from(char* str)
{
    ah_buf_t buf;
    ah_err_t err = ah_buf_init(&buf, (uint8_t*) str, strlen(str));
    ah_assert(err == AH_ENONE);
    return buf;
}

static void s_should_parse_request_lines(ah_unit_t* unit)
{
    bool res;
    ah_buf_t buf;
    ah_http_req_line_t req_line;

    buf = s_buf_from("GET /things/132 HTTP/1.1\r\n");
    res = ah_i_http_parse_req_line(&buf, NULL, &req_line);
    if (!ah_unit_assert(unit, res, "parse failed unexpectedly")) {
        return;
    }
    (void) ah_unit_assert_str_eq(unit, ah_str_from_cstr("GET"), req_line.method);
    (void) ah_unit_assert_str_eq(unit, ah_str_from_cstr("/things/132"), req_line.target);
    (void) ah_unit_assert_unsigned_eq(unit, 1u, req_line.version.major);
    (void) ah_unit_assert_unsigned_eq(unit, 1u, req_line.version.minor);

    buf = s_buf_from("OPTIONS * HTTP/1.0\r\n");
    res = ah_i_http_parse_req_line(&buf, NULL, &req_line);
    if (!ah_unit_assert(unit, res, "parse failed unexpectedly")) {
        return;
    }
    (void) ah_unit_assert_str_eq(unit, ah_str_from_cstr("OPTIONS"), req_line.method);
    (void) ah_unit_assert_str_eq(unit, ah_str_from_cstr("*"), req_line.target);
    (void) ah_unit_assert_unsigned_eq(unit, 1u, req_line.version.major);
    (void) ah_unit_assert_unsigned_eq(unit, 0u, req_line.version.minor);

    buf = s_buf_from("CONNECT [::1]:44444 HTTP/1.1\r\n");
    res = ah_i_http_parse_req_line(&buf, NULL, &req_line);
    if (!ah_unit_assert(unit, res, "parse failed unexpectedly")) {
        return;
    }
    (void) ah_unit_assert_str_eq(unit, ah_str_from_cstr("CONNECT"), req_line.method);
    (void) ah_unit_assert_str_eq(unit, ah_str_from_cstr("[::1]:44444"), req_line.target);
    (void) ah_unit_assert_unsigned_eq(unit, 1u, req_line.version.major);
    (void) ah_unit_assert_unsigned_eq(unit, 1u, req_line.version.minor);
}

static void s_should_parse_status_lines(ah_unit_t* unit)
{
    bool res;
    ah_buf_t buf;
    ah_http_stat_line_t stat_line;

    buf = s_buf_from("HTTP/1.1 200 OK\r\n");
    res = ah_i_http_parse_stat_line(&buf, NULL, &stat_line);
    if (!ah_unit_assert(unit, res, "parse failed unexpectedly")) {
        return;
    }
    (void) ah_unit_assert_unsigned_eq(unit, 1u, stat_line.version.major);
    (void) ah_unit_assert_unsigned_eq(unit, 1u, stat_line.version.minor);
    (void) ah_unit_assert_unsigned_eq(unit, 200u, stat_line.code);
    (void) ah_unit_assert_str_eq(unit, ah_str_from_cstr("OK"), stat_line.reason);

    buf = s_buf_from("HTTP/1.0 201 \r\n");
    res = ah_i_http_parse_stat_line(&buf, NULL, &stat_line);
    if (!ah_unit_assert(unit, res, "parse failed unexpectedly")) {
        return;
    }
    (void) ah_unit_assert_unsigned_eq(unit, 1u, stat_line.version.major);
    (void) ah_unit_assert_unsigned_eq(unit, 0u, stat_line.version.minor);
    (void) ah_unit_assert_unsigned_eq(unit, 201u, stat_line.code);
    (void) ah_unit_assert_str_eq(unit, ah_str_from_cstr(""), stat_line.reason);

    buf = s_buf_from("HTTP/1.1 500 Internal server errör \r\n");
    res = ah_i_http_parse_stat_line(&buf, NULL, &stat_line);
    if (!ah_unit_assert(unit, res, "parse failed unexpectedly")) {
        return;
    }
    (void) ah_unit_assert_unsigned_eq(unit, 1u, stat_line.version.major);
    (void) ah_unit_assert_unsigned_eq(unit, 1u, stat_line.version.minor);
    (void) ah_unit_assert_unsigned_eq(unit, 500u, stat_line.code);
    (void) ah_unit_assert_str_eq(unit, ah_str_from_cstr("Internal server errör "), stat_line.reason);
}
