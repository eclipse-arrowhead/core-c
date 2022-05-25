// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include "http-parser.h"

#include <ah/assert.h>
#include <ah/err.h>
#include <ah/math.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

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

static size_t s_skip_while(ah_buf_rw_t* rw, bool (*predicate)(uint8_t));
static const char* s_take_while(ah_buf_rw_t* rw, bool (*predicate)(uint8_t));
static uint8_t s_to_lower_ascii(uint8_t ch);

ah_err_t ah_i_http_parse_chunk_line(ah_buf_rw_t* rw, size_t* size, const char** ext)
{
    ah_assert_if_debug(rw != NULL);
    ah_assert_if_debug(size != NULL);
    ah_assert_if_debug(ext != NULL);

    ah_err_t err;

    size_t size0 = 0u;
    const char* ext0 = NULL;

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

        err = ah_mul_size(size0, 16u, &size0);
        if (err != AH_ENONE) {
            return err;
        }

        err = ah_add_size(size0, inc, &size0);
        if (err != AH_ENONE) {
            return err;
        }
    }

    return AH_EAGAIN;

parse_ext:

    ext0 = (const char*) &rw->rd[-1];

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

    return AH_EAGAIN;

finish:

    *size = size0;
    *ext = ext0;

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
        return AH_EAGAIN;
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

ah_err_t ah_i_http_parse_req_line(ah_buf_rw_t* rw, const char** line, ah_http_ver_t* version)
{
    ah_assert_if_debug(rw != NULL);
    ah_assert_if_debug(line != NULL);
    ah_assert_if_debug(version != NULL);

    ah_err_t err;

    const char* line_start = (char*) rw->rd;

    const size_t method_len = s_skip_while(rw, s_is_tchar);
    if (ah_buf_rw_get_readable_size(rw) == 0u) {
        return AH_EAGAIN;
    }
    if (method_len == 0u) {
        return AH_EILSEQ;
    }

    err = s_skip_ch(rw, ' ');
    if (err != AH_ENONE) {
        return err;
    }

    const size_t target_len = s_skip_while(rw, s_is_rchar);
    if (ah_buf_rw_get_readable_size(rw) == 0u) {
        return AH_EAGAIN;
    }
    if (target_len == 0u) {
        return AH_EILSEQ;
    }

    char* line_end = (char*) rw->rd;

    err = s_skip_ch(rw, ' ');
    if (err != AH_ENONE) {
        return err;
    }

    err = s_parse_version(rw, version);
    if (err != AH_ENONE) {
        return err;
    }

    err = s_skip_crlf(rw);
    if (err != AH_ENONE) {
        return err;
    }

    *line = line_start;
    *line_end = '\0'; // Terminate line by replacing space before version with '\0'.

    return AH_ENONE;
}

ah_err_t ah_i_http_parse_stat_line(ah_buf_rw_t* rw, const char** line, ah_http_ver_t* version)
{
    ah_assert_if_debug(rw != NULL);
    ah_assert_if_debug(line != NULL);
    ah_assert_if_debug(version != NULL);

    ah_err_t err;

    err = s_parse_version(rw, version);
    if (err != AH_ENONE) {
        return err;
    }

    err = s_skip_ch(rw, ' ');
    if (err != AH_ENONE) {
        return err;
    }

    const char* line_start = (char*) rw->rd;

    const size_t code_len = s_skip_while(rw, s_is_digit);
    if (ah_buf_rw_get_readable_size(rw) == 0u) {
        return AH_EAGAIN;
    }
    if (code_len != 3u) {
        return AH_EILSEQ;
    }

    err = s_skip_ch(rw, ' ');
    if (err != AH_ENONE) {
        return err;
    }

    (void) s_skip_while(rw, s_is_vchar_obs_text_htab_sp);

    char* line_end = (char*) rw->rd;

    err = s_skip_crlf(rw);
    if (err != AH_ENONE) {
        return err;
    }

    *line = line_start;
    *line_end = '\0'; // Terminate line by replacing first CRLF character with '\0'.

    return AH_ENONE;
}

static ah_err_t s_parse_version(ah_buf_rw_t* rw, ah_http_ver_t* version)
{
    if (ah_buf_rw_get_readable_size(rw) < 8u) {
        return AH_EAGAIN;
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

ah_err_t ah_i_http_header_name_eq(const char* expected_lowercase, const char* actual)
{
    ah_assert_if_debug(expected_lowercase != NULL);
    ah_assert_if_debug(actual != NULL);

    const uint8_t* a = (const uint8_t*) expected_lowercase;
    const uint8_t* b = (const uint8_t*) actual;

    while (a[0u] == s_to_lower_ascii(*b)) {
        if (a[0u] == '\0') {
            return true;
        }
        a = &a[1u];
        b = &b[1u];
    }

    return false;
}

ah_err_t ah_i_http_header_value_find_csv(const char* value, const char* csv_lowercase, const char** rest)
{
    ah_assert_if_debug(value != NULL);

    const uint8_t* v = (const uint8_t*) value;
    const uint8_t* c;

    // For each Comma-Separated Value (CSV).
    for (;;) {
        if (v[0u] == '\0') {
            return AH_ESRCH;
        }

        // Did we find it?
        c = (const uint8_t*) csv_lowercase;
        if (s_to_lower_ascii(v[0u]) == c[0u]) {
            for (;;) {
                if (c[0u] == '\0') {
                    // We did!
                    if (rest != NULL) {
                        *rest = (const char*) v;
                    }
                    return AH_ENONE;
                }
                v = &v[1u];
                c = &c[1u];
                if (s_to_lower_ascii(v[0u]) != c[0u]) {
                    break; // Nope.
                }
            }
        }

        // Skip until next CSV.
        for (;;) {
            if (v[0u] == ',') {
                break;
            }
            if (v[0u] == '"') { // Commas within double quotes do not count.
                do {
                    v = &v[1u];
                    if (v[0u] == '\0') {
                        return AH_ESRCH;
                    }
                    if (v[0u] == '\\') { // Double quotes may be escaped.
                        v = &v[1u];
                        if (v[0u] == '\0') {
                            return AH_ESRCH;
                        }
                    }
                } while (v[0u] != '"');
            }
            v = &v[1u];
            if (v[0u] == '\0') {
                return AH_ESRCH;
            }
        }

        // Skip any optional white-space.
        while (v[0u] == '\t' || v[0u] == ' ') {
            v = &v[1u];
            if (v[0u] == '\0') {
                return AH_ESRCH;
            }
        }
    }
}

ah_err_t ah_i_http_header_value_to_size(const char* value, size_t* size)
{
    ah_assert_if_debug(value != NULL);

    ah_err_t err;

    size_t size0 = 0u;
    for (;;) {
        const char ch = value[0u];
        if (ch <= '0' || ch >= '9') {
            if (ch == '\0') {
                break;
            }
            return AH_EILSEQ;
        }

        err = ah_mul_size(size0, 10u, &size0);
        if (err != AH_ENONE) {
            return err;
        }

        err = ah_add_size(size0, ch - '0', &size0);
        if (err != AH_ENONE) {
            return err;
        }

        value = &value[1u];
    }

    *size = size0;

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
        return AH_EAGAIN;
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
        return AH_EAGAIN;
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

static size_t s_skip_while(ah_buf_rw_t* rw, bool (*predicate)(uint8_t))
{
    uint8_t ch;
    size_t i = 0u;
    for (; ah_buf_rw_peek1(rw, &ch) && predicate(ch); i += 1u) {
        rw->rd = &rw->rd[1u];
    }
    return i;
}

static const char* s_take_while(ah_buf_rw_t* rw, bool (*predicate)(uint8_t))
{
    const char* str = (const char*) rw->rd;

    uint8_t ch;
    while (ah_buf_rw_peek1(rw, &ch) && predicate(ch)) {
        rw->rd = &rw->rd[1u];
    }

    return str;
}

static uint8_t s_to_lower_ascii(uint8_t ch)
{
    return (ch >= 'A' && ch <= 'Z') ? (ch | 0x20) : ch;
}
