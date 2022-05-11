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

static ah_buf_rw_t s_buf_rw_from(char* str, void* writable_memory, size_t writable_memory_size);

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
    uint8_t rw_mem[48u];
    ah_buf_rw_t rw;
    ah_http_chunk_line_t chunk_line;

    rw = s_buf_rw_from("FEBA9810\r\n", rw_mem, sizeof(rw_mem));
    err = ah_i_http_parse_chunk_line(&rw, &chunk_line);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    (void) ah_unit_assert_unsigned_eq(unit, 0xFEBA9810, chunk_line.size);
    (void) ah_unit_assert_cstr_eq(unit, NULL, chunk_line.ext);

    rw = s_buf_rw_from("AABBC;key0=val0;key1=val1\r\n", rw_mem, sizeof(rw_mem));
    err = ah_i_http_parse_chunk_line(&rw, &chunk_line);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    (void) ah_unit_assert_unsigned_eq(unit, 0xAABBC, chunk_line.size);
    (void) ah_unit_assert_cstr_eq(unit, ";key0=val0;key1=val1", chunk_line.ext);

    rw = s_buf_rw_from("10;key0=\" val0 \";key1=\"\tval1\\\"\t\"\r\n", rw_mem, sizeof(rw_mem));
    err = ah_i_http_parse_chunk_line(&rw, &chunk_line);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    (void) ah_unit_assert_unsigned_eq(unit, 0x10, chunk_line.size);
    (void) ah_unit_assert_cstr_eq(unit, ";key0=\" val0 \";key1=\"\tval1\\\"\t\"", chunk_line.ext);
}

static ah_buf_rw_t s_buf_rw_from(char* str, void* writable_memory, size_t writable_memory_size)
{
    ah_assert_if_debug(str != NULL);

    const size_t len = strlen(str);
    ah_assert_if_debug(len < writable_memory_size);

    uint8_t* off = (uint8_t*) strncpy(writable_memory, str, len + 1u);
    uint8_t* end = &off[len];

    return (ah_buf_rw_t) {
        .rd = off,
        .wr = end,
        .end = end,
    };
}

static void s_should_parse_headers(ah_unit_t* unit)
{
    ah_err_t err;
    ah_http_header_t header;
    uint8_t rw_mem[192u];
    ah_buf_rw_t rw = s_buf_rw_from(
        "Accept: application/json, application/cbor\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Content-Length:   143  \r\n"
        "Host:  192.168.4.44:44444 \r\n"
        "\r\n",
        rw_mem, sizeof(rw_mem));

    ah_http_header_t expected_headers[] = {
        { "Accept", "application/json, application/cbor" },
        { "Content-Type", "application/json; charset=utf-8" },
        { "Content-Length", "143" },
        { "Host", "192.168.4.44:44444" },
        { NULL, NULL },
    };

    for (size_t i = 0u;; i += 1u) {
        err = ah_i_http_parse_header(&rw, &header);
        if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
            return;
        }

        if (!ah_unit_assert_cstr_eq(unit, expected_headers[i].name, header.name)) {
            return;
        }
        if (!ah_unit_assert_cstr_eq(unit, expected_headers[i].value, header.value)) {
            return;
        }

        if (header.name == NULL) {
            break;
        }
    }
}

static void s_should_parse_request_lines(ah_unit_t* unit)
{
    ah_err_t err;
    uint8_t rw_mem[48u];
    ah_buf_rw_t rw;
    ah_http_req_line_t req_line;

    rw = s_buf_rw_from("GET /things/132 HTTP/1.1\r\n", rw_mem, sizeof(rw_mem));
    err = ah_i_http_parse_req_line(&rw, &req_line);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    (void) ah_unit_assert_cstr_eq(unit, "GET", req_line.method);
    (void) ah_unit_assert_cstr_eq(unit, "/things/132", req_line.target);
    (void) ah_unit_assert_unsigned_eq(unit, 1u, req_line.version.major);
    (void) ah_unit_assert_unsigned_eq(unit, 1u, req_line.version.minor);

    rw = s_buf_rw_from("OPTIONS * HTTP/1.0\r\n", rw_mem, sizeof(rw_mem));
    err = ah_i_http_parse_req_line(&rw, &req_line);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    (void) ah_unit_assert_cstr_eq(unit, "OPTIONS", req_line.method);
    (void) ah_unit_assert_cstr_eq(unit, "*", req_line.target);
    (void) ah_unit_assert_unsigned_eq(unit, 1u, req_line.version.major);
    (void) ah_unit_assert_unsigned_eq(unit, 0u, req_line.version.minor);

    rw = s_buf_rw_from("CONNECT [::1]:44444 HTTP/1.1\r\n", rw_mem, sizeof(rw_mem));
    err = ah_i_http_parse_req_line(&rw, &req_line);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    (void) ah_unit_assert_cstr_eq(unit, "CONNECT", req_line.method);
    (void) ah_unit_assert_cstr_eq(unit, "[::1]:44444", req_line.target);
    (void) ah_unit_assert_unsigned_eq(unit, 1u, req_line.version.major);
    (void) ah_unit_assert_unsigned_eq(unit, 1u, req_line.version.minor);
}

static void s_should_parse_status_lines(ah_unit_t* unit)
{
    ah_err_t err;
    uint8_t rw_mem[48u];
    ah_buf_rw_t rw;
    ah_http_stat_line_t stat_line;

    rw = s_buf_rw_from("HTTP/1.1 200 OK\r\n", rw_mem, sizeof(rw_mem));
    err = ah_i_http_parse_stat_line(&rw, &stat_line);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    (void) ah_unit_assert_unsigned_eq(unit, 1u, stat_line.version.major);
    (void) ah_unit_assert_unsigned_eq(unit, 1u, stat_line.version.minor);
    (void) ah_unit_assert_unsigned_eq(unit, 200u, stat_line.code);
    (void) ah_unit_assert_cstr_eq(unit, "OK", stat_line.reason);

    rw = s_buf_rw_from("HTTP/1.0 201 \r\n", rw_mem, sizeof(rw_mem));
    err = ah_i_http_parse_stat_line(&rw, &stat_line);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    (void) ah_unit_assert_unsigned_eq(unit, 1u, stat_line.version.major);
    (void) ah_unit_assert_unsigned_eq(unit, 0u, stat_line.version.minor);
    (void) ah_unit_assert_unsigned_eq(unit, 201u, stat_line.code);
    (void) ah_unit_assert_cstr_eq(unit, "", stat_line.reason);

    rw = s_buf_rw_from("HTTP/1.1 500 Internal server errör \r\n", rw_mem, sizeof(rw_mem));
    err = ah_i_http_parse_stat_line(&rw, &stat_line);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    (void) ah_unit_assert_unsigned_eq(unit, 1u, stat_line.version.major);
    (void) ah_unit_assert_unsigned_eq(unit, 1u, stat_line.version.minor);
    (void) ah_unit_assert_unsigned_eq(unit, 500u, stat_line.code);
    (void) ah_unit_assert_cstr_eq(unit, "Internal server errör ", stat_line.reason);
}
