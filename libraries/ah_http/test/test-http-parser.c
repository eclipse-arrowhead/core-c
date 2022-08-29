// SPDX-License-Identifier: EPL-2.0

#include "../src/http-parser.h"
#include "ah/http.h"

#include <ah/assert.h>
#include <ah/err.h>
#include <ah/unit.h>

static void s_should_parse_chunks(ah_unit_res_t* res);
static void s_should_parse_headers(ah_unit_res_t* res);
static void s_should_parse_request_lines(ah_unit_res_t* res);
static void s_should_parse_status_lines(ah_unit_res_t* res);

static ah_rw_t s_rw_from(char* str, void* writable_memory, size_t writable_memory_size);

void test_http_parser(ah_unit_res_t* res)
{
    s_should_parse_chunks(res);
    s_should_parse_headers(res);
    s_should_parse_request_lines(res);
    s_should_parse_status_lines(res);
}

static void s_should_parse_chunks(ah_unit_res_t* res)
{
    ah_err_t err;
    uint8_t rw_mem[48u];
    ah_rw_t rw;

    size_t size;
    const char* ext;

    rw = s_rw_from("FEBA9810\r\n", rw_mem, sizeof(rw_mem));
    err = ah_i_http_parse_chunk_line(&rw, &size, &ext);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, size, 0xFEBA9810);
    (void) ah_unit_assert_eq_cstr(AH_UNIT_CTX, res, ext, NULL);

    rw = s_rw_from("AABBC;key0=val0;key1=val1\r\n", rw_mem, sizeof(rw_mem));
    err = ah_i_http_parse_chunk_line(&rw, &size, &ext);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, size, 0xAABBC);
    (void) ah_unit_assert_eq_cstr(AH_UNIT_CTX, res, ext, ";key0=val0;key1=val1");

    rw = s_rw_from("10;key0=\" val0 \";key1=\"\tval1\\\"\t\"\r\n", rw_mem, sizeof(rw_mem));
    err = ah_i_http_parse_chunk_line(&rw, &size, &ext);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, size, 0x10);
    (void) ah_unit_assert_eq_cstr(AH_UNIT_CTX, res, ext, ";key0=\" val0 \";key1=\"\tval1\\\"\t\"");
}

static ah_rw_t s_rw_from(char* str, void* writable_memory, size_t writable_memory_size)
{
    ah_assert_if_debug(str != NULL);

    const size_t len = strlen(str);
    ah_assert_always(len < writable_memory_size);

    uint8_t* off = (uint8_t*) memcpy(writable_memory, str, len + 1u);
    uint8_t* end = &off[len];

    return (ah_rw_t) {
        .r = off,
        .w = end,
        .e = end,
    };
}

static void s_should_parse_headers(ah_unit_res_t* res)
{
    ah_err_t err;
    ah_http_header_t header;
    uint8_t rw_mem[192u];
    ah_rw_t rw = s_rw_from(
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
        if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
            return;
        }

        if (!ah_unit_assert_eq_cstr(AH_UNIT_CTX, res, header.name, expected_headers[i].name)) {
            return;
        }
        if (!ah_unit_assert_eq_cstr(AH_UNIT_CTX, res, header.value, expected_headers[i].value)) {
            return;
        }

        if (header.name == NULL) {
            break;
        }
    }
}

static void s_should_parse_request_lines(ah_unit_res_t* res)
{
    ah_err_t err;
    uint8_t rw_mem[48u];
    ah_rw_t rw;

    const char* line;
    ah_http_ver_t version;

    rw = s_rw_from("GET /things/132 HTTP/1.1\r\n", rw_mem, sizeof(rw_mem));
    err = ah_i_http_parse_req_line(&rw, &line, &version);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }
    (void) ah_unit_assert_eq_cstr(AH_UNIT_CTX, res, line, "GET /things/132");
    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, version.major, 1u);
    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, version.minor, 1u);

    rw = s_rw_from("OPTIONS * HTTP/1.0\r\n", rw_mem, sizeof(rw_mem));
    err = ah_i_http_parse_req_line(&rw, &line, &version);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }
    (void) ah_unit_assert_eq_cstr(AH_UNIT_CTX, res, line, "OPTIONS *");
    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, version.major, 1u);
    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, version.minor, 0u);

    rw = s_rw_from("CONNECT [::1]:44444 HTTP/1.1\r\n", rw_mem, sizeof(rw_mem));
    err = ah_i_http_parse_req_line(&rw, &line, &version);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }
    (void) ah_unit_assert_eq_cstr(AH_UNIT_CTX, res, "CONNECT [::1]:44444", line);
    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, version.major, 1u);
    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, version.minor, 1u);
}

static void s_should_parse_status_lines(ah_unit_res_t* res)
{
    ah_err_t err;
    uint8_t rw_mem[48u];
    ah_rw_t rw;

    const char* line;
    ah_http_ver_t version;

    rw = s_rw_from("HTTP/1.1 200 OK\r\n", rw_mem, sizeof(rw_mem));
    err = ah_i_http_parse_stat_line(&rw, &line, &version);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }
    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, version.major, 1u);
    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, version.minor, 1u);
    (void) ah_unit_assert_eq_cstr(AH_UNIT_CTX, res, line, "200 OK");

    rw = s_rw_from("HTTP/1.0 201 \r\n", rw_mem, sizeof(rw_mem));
    err = ah_i_http_parse_stat_line(&rw, &line, &version);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }
    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, version.major, 1u);
    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, version.minor, 0u);
    (void) ah_unit_assert_eq_cstr(AH_UNIT_CTX, res, line, "201 ");

    rw = s_rw_from("HTTP/1.1 500 Internal server errör \r\n", rw_mem, sizeof(rw_mem));
    err = ah_i_http_parse_stat_line(&rw, &line, &version);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }
    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, version.major, 1u);
    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, version.minor, 1u);
    (void) ah_unit_assert_eq_cstr(AH_UNIT_CTX, res, line, "500 Internal server errör ");
}
