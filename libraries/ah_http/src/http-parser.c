// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "http-parser.h"

#include "http-hmap.h"

#include <ah/err.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

static bool s_parse_status_code(ah_i_reader_t* r, uint16_t* code);
static bool s_parse_version(ah_i_reader_t* r, ah_http_ver_t* version);

static bool s_is_digit(uint8_t ch);
static bool s_is_ows(uint8_t ch);
static bool s_is_vchar(uint8_t ch);
static bool s_is_vchar_not_colon(uint8_t ch);
static bool s_is_vchar_obs_text_htab_sp(uint8_t ch);
static bool s_is_vchar_obs_text(uint8_t ch);

static bool s_skip_ch(ah_i_reader_t* r, char ch);
static bool s_skip_crlf(ah_i_reader_t* r);
static void s_skip_ows(ah_i_reader_t* r);

static ah_str_t s_take_while(ah_i_reader_t* r, bool (*pred)(uint8_t));

ah_err_t ah_i_http_parse_headers(ah_i_reader_t* r, ah_http_hmap_t* hmap)
{
    ah_assert_if_debug(r != NULL);
    ah_assert_if_debug(hmap != NULL);

    for (;;) {
        if (s_skip_crlf(r)) {
            return AH_ENONE;
        }

        // Read name.

        ah_str_t name = s_take_while(r, s_is_vchar_not_colon);
        if (ah_str_len(&name) == 0u || !s_skip_ch(r, ':')) {
            return AH_EILSEQ;
        }

        // Read value.

        s_skip_ows(r);

        if (r->off == r->end || !s_is_vchar_obs_text(r->off[0u])) {
            return AH_EILSEQ;
        }

        uint8_t* field_value_start = r->off;

        do {
            r->off = &r->off[1u];
        } while (s_is_vchar_obs_text_htab_sp(r->off[0u]));

        uint8_t* field_value_end = r->off;

        if (!s_skip_crlf(r)) {
            return AH_EILSEQ;
        }

        // Remove trailing optional whitespace.
        while (field_value_end != field_value_start && s_is_ows(field_value_end[-1])) {
            field_value_end = &field_value_end[-1];
        }

        ah_str_t value = ah_str_from(field_value_start, field_value_end - field_value_start);

        ah_err_t err = ah_i_http_hmap_add(hmap, name, value);
        if (err != AH_ENONE) {
            return err;
        }
    }
}

ah_err_t ah_i_http_parse_req_line(ah_i_reader_t* r, ah_http_req_line_t* req_line)
{
    ah_assert_if_debug(r != NULL);
    ah_assert_if_debug(req_line != NULL);

    req_line->method = s_take_while(r, s_is_vchar);
    if (ah_str_len(&req_line->method) == 0u || !s_skip_ch(r, ' ')) {
        return AH_EILSEQ;
    }

    req_line->target = s_take_while(r, s_is_vchar);
    if (ah_str_len(&req_line->target) == 0u || !s_skip_ch(r, ' ')) {
        return AH_EILSEQ;
    }

    if (!s_parse_version(r, &req_line->version) || !s_skip_crlf(r)) {
        return AH_EILSEQ;
    }

    return AH_ENONE;
}

static bool s_parse_version(ah_i_reader_t* r, ah_http_ver_t* version)
{
    if (r->end - r->off < 8u) {
        return false;
    }
    if (memcmp(r->off, "HTTP/", 5u) != 0) {
        return false;
    }
    if (!s_is_digit(r->off[5u]) || r->off[6u] != '.' || !s_is_digit(r->off[7u])) {
        return false;
    }

    version->major = '0' - r->off[5u];
    version->minor = '0' - r->off[7u];

    r->off = &r->off[8u];

    return true;
}

ah_err_t ah_i_http_parse_stat_line(ah_i_reader_t* r, ah_http_stat_line_t* stat_line)
{
    ah_assert_if_debug(r != NULL);
    ah_assert_if_debug(stat_line != NULL);

    if (!s_parse_version(r, &stat_line->version) || !s_skip_ch(r, ' ')) {
        return AH_EILSEQ;
    }

    if (!s_parse_status_code(r, &stat_line->code) || !s_skip_ch(r, ' ')) {
        return AH_EILSEQ;
    }

    stat_line->reason = s_take_while(r, s_is_vchar_obs_text_htab_sp);

    if (!s_skip_crlf(r)) {
        return AH_EILSEQ;
    }

    return AH_ENONE;
}

static bool s_parse_status_code(ah_i_reader_t* r, uint16_t* code)
{
    if (r->end - r->off < 3u) {
        return false;
    }
    if (!s_is_digit(r->off[0u]) || !s_is_digit(r->off[1u]) || !s_is_digit(r->off[2u])) {
        return false;
    }

    *code = (('0' - r->off[0u]) * 100) + (('0' - r->off[1u]) * 10) + ('0' - r->off[2u]);

    r->off = &r->off[3u];

    return true;
}

static bool s_is_digit(uint8_t ch)
{
    return ch >= '0' && ch <= '9';
}

static bool s_is_ows(uint8_t ch)
{
    return ch == ' ' || ch == '\t';
}

static bool s_is_vchar(uint8_t ch)
{
    return ch > ' ' && ch < 0x7F;
}

static bool s_is_vchar_not_colon(uint8_t ch)
{
    return s_is_vchar(ch) && ch != ':';
}

static bool s_is_vchar_obs_text(uint8_t ch)
{
    return ch > 0x20 && ch != 0x7F;
}

static bool s_is_vchar_obs_text_htab_sp(uint8_t ch)
{
    return (ch >= 0x20 && ch != 0x7F) || ch == '\t';
}

static bool s_skip_ch(ah_i_reader_t* r, char ch)
{
    if (r->off == r->end || r->off[0u] != ch) {
        return false;
    }

    r->off = &r->off[1u];

    return true;
}

static bool s_skip_crlf(ah_i_reader_t* r)
{
    if ((size_t) (r->end - r->off) < 2u) {
        return false;
    }
    if (memcmp(r->off, (uint8_t[]) { '\r', '\n' }, 2u) != 0) {
        return false;
    }

    r->off = &r->off[2u];

    return true;
}

static void s_skip_ows(ah_i_reader_t* r)
{
    while (r->off != r->end && s_is_ows(r->off[0u])) {
        r->off = &r->off[1u];
    }
}

static ah_str_t s_take_while(ah_i_reader_t* r, bool (*pred)(uint8_t))
{
    uint8_t* off = r->off;

    for (; off != r->end; off = &off[1u]) {
        if (!pred(off[0u])) {
            break;
        }
    }

    size_t len = (size_t) (off - r->off);
    r->off = off;

    return ah_str_from(off, len);
}
