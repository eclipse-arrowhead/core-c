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

static ah_err_t s_parse_status_code(ah_buf_rw_t* rw, uint16_t* code);
static ah_err_t s_parse_version(ah_buf_rw_t* rw, ah_http_ver_t* version);

static bool s_is_digit(uint8_t ch);
static bool s_is_ows(uint8_t ch);
static bool s_is_rchar(uint8_t ch);
static bool s_is_tchar(uint8_t ch);
static bool s_is_vchar_obs_text_htab_sp(uint8_t ch);
static bool s_is_vchar_obs_text(uint8_t ch);

static ah_err_t s_skip_ch(ah_buf_rw_t* rw, char ch);
static ah_err_t s_skip_crlf(ah_buf_rw_t* rw);
static void s_skip_ows(ah_buf_rw_t* rw);

static const char* s_take_while(ah_buf_rw_t* rw, bool (*pred)(uint8_t));

ah_err_t ah_i_http_parse_chunk_line(ah_buf_rw_t* rw, ah_http_chunk_line_t* chunk_line)
{
    ah_assert_if_debug(rw != NULL);
    ah_assert_if_debug(chunk_line != NULL);

    ah_err_t err;

    size_t size = 0u;
    const char* ext = NULL;

    for (uint8_t ch; ah_buf_rw_read1(rw, &ch);) {
        size_t inc;
        if (ch >= '0' && ch <= '9') {
            inc = ch - '0';
        }
        else if (ch >= 'A' && ch <= 'F') {
            inc = ch - 'A' + 10u;
        }
        else if (ch >= 'a' && ch <= 'f') {
            inc = ch - 'a' + 10u;
        }
        else if (ch == '\r' && ah_buf_rw_peek1(rw, &ch) && ch == '\n') {
            rw->rd = &rw->rd[1u];
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

    ext = (const char*) &rw->rd[-1];

    for (uint8_t ch; ah_buf_rw_read1(rw, &ch);) {
        if (ch != '\r') {
            continue;
        }
        if (ah_buf_rw_peek1(rw, &ch) && ch == '\n') {
            rw->rd = &rw->rd[1u];

            // Terminate ext by replacing first CRLF character with '\0'.
            rw->rd[-2] = '\0';

            goto finish;
        }
        return AH_EILSEQ;
    }

    return AH_EEOF;

finish:

    *chunk_line = (ah_http_chunk_line_t) {
        .size = size,
        .ext = ext,
    };

    return AH_ENONE;
}

ah_err_t ah_i_http_parse_header(ah_buf_rw_t* rw, ah_http_header_t* header)
{
    ah_assert_if_debug(rw != NULL);
    ah_assert_if_debug(header != NULL);

    ah_err_t err;

    err = s_skip_crlf(rw);
    switch (err) {
    case AH_ENONE:
        header->name = NULL;
        header->value = NULL;
        return AH_ENONE;

    case AH_EILSEQ:
        break;

    default:
        return err;
    }

    // Read name.

    const char* name = s_take_while(rw, s_is_tchar);
    uint8_t* name_end = rw->rd;

    if (name[0u] == ':') {
        return AH_EILSEQ;
    }

    err = s_skip_ch(rw, ':');
    if (err != AH_ENONE) {
        return err;
    }

    // Terminate name by replacing ':' with '\0'.
    *name_end = '\0';

    // Read value.

    s_skip_ows(rw);

    const uint8_t* value = rw->rd;
    uint8_t* value_end;

    uint8_t ch;

    if (!ah_buf_rw_read1(rw, &ch)) {
        return AH_EEOF;
    }
    if (!s_is_vchar_obs_text(ch)) {
        return AH_EILSEQ;
    }

    while (ah_buf_rw_peek1(rw, &ch)) {
        if (!s_is_vchar_obs_text_htab_sp(ch)) {
            break;
        }
        rw->rd = &rw->rd[1u];
    }

    value_end = rw->rd;

    err = s_skip_crlf(rw);
    if (err != AH_ENONE) {
        return err;
    }

    // Remove trailing optional whitespace from value.
    while (value_end != value && s_is_ows(value_end[-1])) {
        value_end = &value_end[-1];
    }

    // Terminate value by replacing first CRLF or OWS character with '\0'.
    *value_end = '\0';

    *header = (ah_http_header_t) {
        .name = name,
        .value = (const char*) value,
    };

    return AH_ENONE;
}

ah_err_t ah_i_http_parse_req_line(ah_buf_rw_t* rw, ah_http_req_line_t* req_line)
{
    ah_assert_if_debug(rw != NULL);
    ah_assert_if_debug(req_line != NULL);

    ah_err_t err;

    req_line->method = s_take_while(rw, s_is_tchar);
    if (ah_buf_rw_get_readable_size(rw) == 0u) {
        return AH_EEOF;
    }
    if (req_line->method[0u] == ' ') {
        return AH_EILSEQ;
    }

    err = s_skip_ch(rw, ' ');
    if (err != AH_ENONE) {
        return err;
    }

    // Terminate method by replacing ' ' with '\0'.
    rw->rd[-1] = '\0';

    req_line->target = s_take_while(rw, s_is_rchar);
    if (ah_buf_rw_get_readable_size(rw) == 0u) {
        return AH_EEOF;
    }
    if (req_line->target[0u] == ' ') {
        return AH_EILSEQ;
    }

    err = s_skip_ch(rw, ' ');
    if (err != AH_ENONE) {
        return err;
    }

    // Terminate target by replacing ' ' with '\0'.
    rw->rd[-1] = '\0';

    err = s_parse_version(rw, &req_line->version);
    if (err != AH_ENONE) {
        return err;
    }

    return s_skip_crlf(rw);
}

ah_err_t ah_i_http_parse_stat_line(ah_buf_rw_t* rw, ah_http_stat_line_t* stat_line)
{
    ah_assert_if_debug(rw != NULL);
    ah_assert_if_debug(stat_line != NULL);

    ah_err_t err;

    err = s_parse_version(rw, &stat_line->version);
    if (err != AH_ENONE) {
        return err;
    }

    err = s_skip_ch(rw, ' ');
    if (err != AH_ENONE) {
        return err;
    }

    err = s_parse_status_code(rw, &stat_line->code);
    if (err != AH_ENONE) {
        return err;
    }

    err = s_skip_ch(rw, ' ');
    if (err != AH_ENONE) {
        return err;
    }

    stat_line->reason = s_take_while(rw, s_is_vchar_obs_text_htab_sp);

    err = s_skip_crlf(rw);
    if (err != AH_ENONE) {
        return err;
    }

    // Terminate reason phrase by replacing first CRLF character with '\0'.
    rw->rd[-2] = '\0';

    return AH_ENONE;
}

static ah_err_t s_parse_version(ah_buf_rw_t* rw, ah_http_ver_t* version)
{
    if (ah_buf_rw_get_readable_size(rw) < 8u) {
        return AH_EEOF;
    }
    if (memcmp(rw->rd, "HTTP/", 5u) != 0) {
        return AH_EILSEQ;
    }
    if (!s_is_digit(rw->rd[5u]) || rw->rd[6u] != '.' || !s_is_digit(rw->rd[7u])) {
        return AH_EILSEQ;
    }

    version->major = rw->rd[5u] - '0';
    version->minor = rw->rd[7u] - '0';

    rw->rd = &rw->rd[8u];

    return AH_ENONE;
}

static ah_err_t s_parse_status_code(ah_buf_rw_t* rw, uint16_t* code)
{
    if (ah_buf_rw_get_readable_size(rw) < 3u) {
        return AH_EEOF;
    }
    if (!s_is_digit(rw->rd[0u]) || !s_is_digit(rw->rd[1u]) || !s_is_digit(rw->rd[2u])) {
        return AH_EILSEQ;
    }

    *code = ((rw->rd[0u] - '0') * 100) + ((rw->rd[1u] - '0') * 10) + (rw->rd[2u] - '0');

    rw->rd = &rw->rd[3u];

    return AH_ENONE;
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

static ah_err_t s_skip_ch(ah_buf_rw_t* rw, char ch)
{
    uint8_t ch0;
    if (!ah_buf_rw_peek1(rw, &ch0)) {
        return AH_EEOF;
    }

    if (((uint8_t) ch) != ch0) {
        return AH_EILSEQ;
    }

    rw->rd = &rw->rd[1u];

    return AH_ENONE;
}

static ah_err_t s_skip_crlf(ah_buf_rw_t* rw)
{
    if (ah_buf_rw_get_readable_size(rw) < 2u) {
        return AH_EEOF;
    }
    if (memcmp(rw->rd, (uint8_t[]) { '\r', '\n' }, 2u) != 0) {
        return AH_EILSEQ;
    }

    rw->rd = &rw->rd[2u];

    return AH_ENONE;
}

static void s_skip_ows(ah_buf_rw_t* rw)
{
    uint8_t ch;
    while (ah_buf_rw_peek1(rw, &ch) && s_is_ows(ch)) {
        rw->rd = &rw->rd[1u];
    }
}

static const char* s_take_while(ah_buf_rw_t* rw, bool (*pred)(uint8_t))
{
    const char* str = (const char*) rw->rd;

    uint8_t ch;
    while (ah_buf_rw_peek1(rw, &ch) && pred(ch)) {
        rw->rd = &rw->rd[1u];
    }

    return str;
}
