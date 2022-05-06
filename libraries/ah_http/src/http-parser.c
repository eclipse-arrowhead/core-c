// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "http-parser.h"

#include <ah/err.h>
#include <ah/math.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

typedef struct s_reader s_reader_t;

struct s_reader {
    uint8_t* _off;
    uint8_t* const _end;
};

static s_reader_t s_reader_from_buf(ah_buf_t* buf);

static bool s_parse_status_code(s_reader_t* r, uint16_t* code);
static bool s_parse_version(s_reader_t* r, ah_http_ver_t* version);

static bool s_is_digit(uint8_t ch);
static bool s_is_ows(uint8_t ch);
static bool s_is_rchar(uint8_t ch);
static bool s_is_tchar(uint8_t ch);
static bool s_is_vchar_obs_text_htab_sp(uint8_t ch);
static bool s_is_vchar_obs_text(uint8_t ch);

static bool s_skip_ch(s_reader_t* r, char ch);
static bool s_skip_crlf(s_reader_t* r);
static void s_skip_ows(s_reader_t* r);

static ah_str_t s_take_while(s_reader_t* r, bool (*pred)(uint8_t));

bool ah_i_http_buf_has_crlf(const ah_buf_t* buf)
{
    ah_assert_if_debug(buf != NULL);

    const uint8_t* off = ah_buf_get_base_const(buf);
    const uint8_t* const end = &off[ah_buf_get_size(buf)];

    for (; off != end; off = &off[1u]) {
        if (*off != '\r') {
            continue;
        }
        off = &off[1u];
        if (off == end) {
            return false;
        }
        if (*off != '\n') {
            continue;
        }
        return true;
    }

    return false;
}

bool ah_i_http_buf_has_crlfx2(const ah_buf_t* buf)
{
    ah_assert_if_debug(buf != NULL);

    const uint8_t* off = ah_buf_get_base_const(buf);
    const uint8_t* const end = &off[ah_buf_get_size(buf)];

    for (; off != end; off = &off[1u]) {
        if (*off != '\r') {
            continue;
        }
        off = &off[1u];
        if ((end - off) < 3) {
            return false;
        }
        if (memcmp(off, (uint8_t[]) { '\n', '\r', '\n' }, 3u) != 0u) {
            continue;
        }
        return true;
    }

    return false;
}

ah_err_t ah_i_http_parse_chunk(ah_buf_t* src, ah_http_chunk_t* chunk)
{
    ah_assert_if_debug(src != NULL);
    ah_assert_if_debug(chunk != NULL);

    s_reader_t r = s_reader_from_buf(src);

    ah_err_t err;

    size_t size = 0u;
    ah_str_t ext = (ah_str_t) { 0u };

    uint8_t* ext_start;

    for (; r._off != r._end; r._off = &r._off[1u]) {
        const uint8_t ch = r._off[0u];

        size_t inc;
        if (ch >= '0' && ch <= '9') {
            inc = ch - '0';
        }
        else if (ch >= 'A' && ch <= 'F') {
            inc = (ch - 'A') + 10u;
        }
        else if (ch >= 'a' && ch <= 'f') {
            inc = (ch - 'a') + 10u;
        }
        else if (ch == '\r' && r._off != r._end && r._off[1u] == '\n') {
            goto finish;
        }
        else if (ch == ';') {
            goto parse_ext;
        }
        else {
            return AH_EILSEQ;
        }

        err = ah_mul_size(size, 16u, &size);
        if (err != AH_ENONE) {
            return err;
        }

        err = ah_add_size(size, inc, &size);
        if (err != AH_ENONE) {
            return err;
        }
    }

    return AH_EEOF;

parse_ext:

    ext_start = r._off;

    for (; r._off != r._end; r._off = &r._off[1u]) {
        if (r._off[0u] != '\r') {
            continue;
        }
        r._off = &r._off[1u];
        if (r._off == r._end) {
            return AH_EEOF;
        }
        if (r._off[0u] != '\n') {
            return AH_EILSEQ;
        }
        break;
    }

    ext = ah_str_from(ext_start, &r._end[-2] - ext_start);

finish:
    (void) ah_buf_init(src, r._off, r._end - r._off);
    *chunk = (ah_http_chunk_t) {
        .size = size,
        .ext = ext,
    };

    return AH_ENONE;
}

ah_err_t ah_i_http_parse_headers(ah_buf_t* src, ah_http_hmap_t* hmap)
{
    ah_assert_if_debug(src != NULL);
    ah_assert_if_debug(hmap != NULL);

    s_reader_t r = s_reader_from_buf(src);

    for (;;) {
        if (s_skip_crlf(&r)) {
            return AH_ENONE;
        }

        // Read name.

        ah_str_t name = s_take_while(&r, s_is_tchar);
        if (ah_str_get_len(&name) == 0u || !s_skip_ch(&r, ':')) {
            return AH_EILSEQ;
        }

        // Read value.

        s_skip_ows(&r);

        if (r._off == r._end || !s_is_vchar_obs_text(r._off[0u])) {
            return AH_EILSEQ;
        }

        uint8_t* field_value_start = r._off;

        do {
            r._off = &r._off[1u];
        } while (s_is_vchar_obs_text_htab_sp(r._off[0u]));

        uint8_t* field_value_end = r._off;

        if (!s_skip_crlf(&r)) {
            return AH_EILSEQ;
        }

        // Remove trailing optional whitespace.
        while (field_value_end != field_value_start && s_is_ows(field_value_end[-1])) {
            field_value_end = &field_value_end[-1];
        }

        ah_str_t value = ah_str_from(field_value_start, field_value_end - field_value_start);

        ah_err_t err = ah_http_hmap_add(hmap, name, value);
        if (err != AH_ENONE) {
            return err;
        }
    }
}

bool ah_i_http_parse_req_line(ah_buf_t* src, ah_http_req_line_t* req_line)
{
    ah_assert_if_debug(src != NULL);
    ah_assert_if_debug(req_line != NULL);

    s_reader_t r = s_reader_from_buf(src);

    req_line->method = s_take_while(&r, s_is_tchar);
    if (ah_str_get_len(&req_line->method) == 0u || !s_skip_ch(&r, ' ')) {
        return false;
    }

    req_line->target = s_take_while(&r, s_is_rchar);
    if (ah_str_get_len(&req_line->target) == 0u || !s_skip_ch(&r, ' ')) {
        return false;
    }

    if (!s_parse_version(&r, &req_line->version) || !s_skip_crlf(&r)) {
        return false;
    }

    (void) ah_buf_init(src, r._off, r._end - r._off);

    return true;
}

static bool s_parse_version(s_reader_t* r, ah_http_ver_t* version)
{
    if (r->_end - r->_off < 8u) {
        return false;
    }
    if (memcmp(r->_off, "HTTP/", 5u) != 0) {
        return false;
    }
    if (!s_is_digit(r->_off[5u]) || r->_off[6u] != '.' || !s_is_digit(r->_off[7u])) {
        return false;
    }

    version->major = r->_off[5u] - '0';
    version->minor = r->_off[7u] - '0';

    r->_off = &r->_off[8u];

    return true;
}

bool ah_i_http_parse_stat_line(ah_buf_t* src, ah_http_stat_line_t* stat_line)
{
    ah_assert_if_debug(src != NULL);
    ah_assert_if_debug(stat_line != NULL);

    s_reader_t r = s_reader_from_buf(src);

    if (!s_parse_version(&r, &stat_line->version) || !s_skip_ch(&r, ' ')) {
        return false;
    }

    if (!s_parse_status_code(&r, &stat_line->code) || !s_skip_ch(&r, ' ')) {
        return false;
    }

    stat_line->reason = s_take_while(&r, s_is_vchar_obs_text_htab_sp);

    if (!s_skip_crlf(&r)) {
        return false;
    }

    (void) ah_buf_init(src, r._off, r._end - r._off);

    return true;
}

static bool s_parse_status_code(s_reader_t* r, uint16_t* code)
{
    if (r->_end - r->_off < 3u) {
        return false;
    }
    if (!s_is_digit(r->_off[0u]) || !s_is_digit(r->_off[1u]) || !s_is_digit(r->_off[2u])) {
        return false;
    }

    *code = ((r->_off[0u] - '0') * 100) + ((r->_off[1u] - '0') * 10) + (r->_off[2u] - '0');

    r->_off = &r->_off[3u];

    return true;
}

static s_reader_t s_reader_from_buf(ah_buf_t* buf)
{
    uint8_t* off = ah_buf_get_base(buf);
    return (s_reader_t) { off, &off[ah_buf_get_size(buf)] };
}

static bool s_is_digit(uint8_t ch)
{
    return ch >= '0' && ch <= '9';
}

static bool s_is_ows(uint8_t ch)
{
    return ch == ' ' || ch == '\t';
}

static bool s_is_rchar(uint8_t ch)
{
    // Every set bit in this table denotes a character that may occur in an
    // RFC7230 request-target. Those characters are '!', '$', '%', '&', '\'',
    // '(', ')', '*', '+', ',', '-', '.', '/', [0-9], ':', ';', '=', '?', '@',
    // [A-Z], '[', ']', '_', [a-z] and '~'.
    static const uint32_t tab[] = {
        0x00000000,
        0xAFFFFFF2,
        0xAFFFFFFF,
        0x47FFFFFE,
    };
    return (ch & 0x80) == 0u && ((tab[ch >> 5u] >> (ch & 0x1F)) & 1u) == 1u;
}

static bool s_is_tchar(uint8_t ch)
{
    // Every set bit in this table denotes a token character (TCHAR) of RFC7230.
    // Those characters are '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.',
    // [0-9], [A-Z], '^', '_', '`', [a-z], '|' and '~'.
    static const uint32_t tab[] = {
        0x00000000,
        0x03FF6CFA,
        0xC7FFFFFE,
        0x57FFFFFE,
    };
    return (ch & 0x80) == 0u && ((tab[ch >> 5u] >> (ch & 0x1F)) & 1u) == 1u;
}

static bool s_is_vchar_obs_text(uint8_t ch)
{
    return ch > 0x20 && ch != 0x7F;
}

static bool s_is_vchar_obs_text_htab_sp(uint8_t ch)
{
    return (ch >= 0x20 && ch != 0x7F) || ch == '\t';
}

static bool s_skip_ch(s_reader_t* r, char ch)
{
    if (r->_off == r->_end || r->_off[0u] != ch) {
        return false;
    }

    r->_off = &r->_off[1u];

    return true;
}

static bool s_skip_crlf(s_reader_t* r)
{
    if ((size_t) (r->_end - r->_off) < 2u) {
        return false;
    }
    if (memcmp(r->_off, (uint8_t[]) { '\r', '\n' }, 2u) != 0) {
        return false;
    }

    r->_off = &r->_off[2u];

    return true;
}

static void s_skip_ows(s_reader_t* r)
{
    while (r->_off != r->_end && s_is_ows(r->_off[0u])) {
        r->_off = &r->_off[1u];
    }
}

static ah_str_t s_take_while(s_reader_t* r, bool (*pred)(uint8_t))
{
    uint8_t* off = r->_off;

    for (; off != r->_end; off = &off[1u]) {
        if (!pred(off[0u])) {
            break;
        }
    }

    uint8_t* ptr = r->_off;
    size_t len = (size_t) (off - r->_off);

    r->_off = off;

    return ah_str_from(ptr, len);
}
