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

static ah_err_t s_parse_version(ah_i_http_parser_t* p, ah_http_ver_t* version);

static bool s_is_digit(uint8_t ch);
static bool s_is_ows(uint8_t ch);
static bool s_is_rchar(uint8_t ch);
static bool s_is_tchar(uint8_t ch);
static bool s_is_vchar_obs_text(uint8_t ch);
static bool s_is_vchar_obs_text_htab_sp(uint8_t ch);

static bool s_peek1(ah_i_http_parser_t* p, uint8_t* ch);
static bool s_read1(ah_i_http_parser_t* p, uint8_t* ch);
static size_t s_size(ah_i_http_parser_t* p);

static ah_err_t s_skip_ch(ah_i_http_parser_t* p, char ch);
static ah_err_t s_skip_crlf(ah_i_http_parser_t* p);
static void s_skip_ows(ah_i_http_parser_t* p);
static size_t s_skip_while(ah_i_http_parser_t* p, bool (*predicate)(uint8_t));
static const char* s_take_while(ah_i_http_parser_t* p, bool (*predicate)(uint8_t));

static uint8_t s_to_lower_ascii(uint8_t ch);

ah_err_t ah_i_http_parser_init(struct ah_i_http_parser* p, ah_tcp_in_t* in, struct ah_i_http_in_scratchpad* scratchpad)
{
    ah_assert_if_debug(p != NULL);
    ah_assert_if_debug(in != NULL);
    ah_assert_if_debug(scratchpad != NULL);
    ah_assert_if_debug(scratchpad->page != NULL);

    uint8_t* base = ah_buf_get_base(&in->buf);

    // Scratchpad is empty; read directly from `in`.
    if (scratchpad->offset == 0u) {
        p->off = base;
        p->end = &base[in->nread];
        return AH_ENONE;
    }

    // Find CRLF or end in `src`.
    size_t i = 0u;
    bool has_crlf = false;
    for (; i < in->nread; i += 1u) {
        if (base[i] != '\r') {
            continue;
        }
        i += 1u;
        if (i == in->nread) {
            break;
        }
        if (base[i] != '\n') {
            continue;
        }
        i += 1u;
        has_crlf = true;
        break;
    }

    // Copy data from `src` to scratchpad, if possible, so we can read from there.
    if (i > (AH_PSIZE - scratchpad->offset)) {
        return AH_EOVERFLOW;
    }
    memcpy(&scratchpad->page[scratchpad->offset], base, i);
    scratchpad->offset += i;

    if (has_crlf) {
        p->off = &scratchpad->page[0u];
        p->end = &scratchpad->page[scratchpad->offset];
        return AH_ENONE;
    }

    // We never found CRLF and the scratchpad is not full; ask for more `src` data.
    return AH_EAGAIN;
}

ah_err_t ah_i_http_parse_chunk_line(ah_i_http_parser_t* p, size_t* size, const char** ext)
{
    ah_assert_if_debug(p != NULL);
    ah_assert_if_debug(size != NULL);
    ah_assert_if_debug(ext != NULL);

    ah_err_t err;

    size_t size0 = 0u;
    const char* ext0 = NULL;

    for (uint8_t ch; s_read1(p, &ch);) {
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
        else if (ch == '\r' && s_peek1(p, &ch) && ch == '\n') {
            p->off = &p->off[1u];
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

    ext0 = (const char*) &p->off[-1];

    for (uint8_t ch; s_read1(p, &ch);) {
        if (ch != '\r') {
            continue;
        }
        if (s_peek1(p, &ch) && ch == '\n') {
            p->off = &p->off[1u];

            // Terminate ext by replacing first CRLF character with '\0'.
            p->off[-2] = '\0';

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

ah_err_t ah_i_http_parse_header(ah_i_http_parser_t* p, ah_http_header_t* header)
{
    ah_assert_if_debug(p != NULL);
    ah_assert_if_debug(header != NULL);

    ah_err_t err;

    err = s_skip_crlf(p);
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

    const char* name = s_take_while(p, s_is_tchar);
    uint8_t* name_end = p->off;

    if (name[0u] == ':') {
        return AH_EILSEQ;
    }

    err = s_skip_ch(p, ':');
    if (err != AH_ENONE) {
        return err;
    }

    // Terminate name by replacing ':' with '\0'.
    *name_end = '\0';

    // Read value.

    s_skip_ows(p);

    const uint8_t* value = p->off;
    uint8_t* value_end;

    uint8_t ch;

    if (!s_read1(p, &ch)) {
        return AH_EAGAIN;
    }
    if (!s_is_vchar_obs_text(ch)) {
        return AH_EILSEQ;
    }

    while (s_peek1(p, &ch)) {
        if (!s_is_vchar_obs_text_htab_sp(ch)) {
            break;
        }
        p->off = &p->off[1u];
    }

    value_end = p->off;

    err = s_skip_crlf(p);
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

ah_err_t ah_i_http_parse_req_line(ah_i_http_parser_t* p, const char** line, ah_http_ver_t* version)
{
    ah_assert_if_debug(p != NULL);
    ah_assert_if_debug(line != NULL);
    ah_assert_if_debug(version != NULL);

    ah_err_t err;

    const char* line_start = (char*) p->off;

    const size_t method_len = s_skip_while(p, s_is_tchar);
    if (s_size(p) == 0u) {
        return AH_EAGAIN;
    }
    if (method_len == 0u) {
        return AH_EILSEQ;
    }

    err = s_skip_ch(p, ' ');
    if (err != AH_ENONE) {
        return err;
    }

    const size_t target_len = s_skip_while(p, s_is_rchar);
    if (s_size(p) == 0u) {
        return AH_EAGAIN;
    }
    if (target_len == 0u) {
        return AH_EILSEQ;
    }

    char* line_end = (char*) p->off;

    err = s_skip_ch(p, ' ');
    if (err != AH_ENONE) {
        return err;
    }

    err = s_parse_version(p, version);
    if (err != AH_ENONE) {
        return err;
    }

    err = s_skip_crlf(p);
    if (err != AH_ENONE) {
        return err;
    }

    *line = line_start;
    *line_end = '\0'; // Terminate line by replacing space before version with '\0'.

    return AH_ENONE;
}

ah_err_t ah_i_http_parse_stat_line(ah_i_http_parser_t* p, const char** line, ah_http_ver_t* version)
{
    ah_assert_if_debug(p != NULL);
    ah_assert_if_debug(line != NULL);
    ah_assert_if_debug(version != NULL);

    ah_err_t err;

    err = s_parse_version(p, version);
    if (err != AH_ENONE) {
        return err;
    }

    err = s_skip_ch(p, ' ');
    if (err != AH_ENONE) {
        return err;
    }

    const char* line_start = (char*) p->off;

    const size_t code_len = s_skip_while(p, s_is_digit);
    if (s_size(p) == 0u) {
        return AH_EAGAIN;
    }
    if (code_len != 3u) {
        return AH_EILSEQ;
    }

    err = s_skip_ch(p, ' ');
    if (err != AH_ENONE) {
        return err;
    }

    (void) s_skip_while(p, s_is_vchar_obs_text_htab_sp);

    char* line_end = (char*) p->off;

    err = s_skip_crlf(p);
    if (err != AH_ENONE) {
        return err;
    }

    *line = line_start;
    *line_end = '\0'; // Terminate line by replacing first CRLF character with '\0'.

    return AH_ENONE;
}

static ah_err_t s_parse_version(ah_i_http_parser_t* p, ah_http_ver_t* version)
{
    if (s_size(p) < 8u) {
        return AH_EAGAIN;
    }
    if (memcmp(p->off, "HTTP/", 5u) != 0) {
        return AH_EILSEQ;
    }
    if (!s_is_digit(p->off[5u]) || p->off[6u] != '.' || !s_is_digit(p->off[7u])) {
        return AH_EILSEQ;
    }

    version->major = p->off[5u] - '0';
    version->minor = p->off[7u] - '0';

    p->off = &p->off[8u];

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

static bool s_peek1(ah_i_http_parser_t* p, uint8_t* ch)
{
    if (p->off == p->end) {
        return false;
    }
    *ch = *p->off;
    return true;
}

static bool s_read1(ah_i_http_parser_t* p, uint8_t* ch)
{
    if (p->off == p->end) {
        return false;
    }
    *ch = *p->off;
    p->off = &p->off[1u];
    return true;
}

static size_t s_size(ah_i_http_parser_t* p)
{
    return p->end - p->off;
}

static ah_err_t s_skip_ch(ah_i_http_parser_t* p, char ch)
{
    uint8_t ch0;
    if (!s_peek1(p, &ch0)) {
        return AH_EAGAIN;
    }

    if (((uint8_t) ch) != ch0) {
        return AH_EILSEQ;
    }

    p->off = &p->off[1u];

    return AH_ENONE;
}

static ah_err_t s_skip_crlf(ah_i_http_parser_t* p)
{
    if (s_size(p) < 2u) {
        return AH_EAGAIN;
    }
    if (memcmp(p->off, (uint8_t[]) { '\r', '\n' }, 2u) != 0) {
        return AH_EILSEQ;
    }

    p->off = &p->off[2u];

    return AH_ENONE;
}

static void s_skip_ows(ah_i_http_parser_t* p)
{
    uint8_t ch;
    while (s_peek1(p, &ch) && s_is_ows(ch)) {
        p->off = &p->off[1u];
    }
}

static size_t s_skip_while(ah_i_http_parser_t* p, bool (*predicate)(uint8_t))
{
    uint8_t ch;
    size_t i = 0u;
    for (; s_peek1(p, &ch) && predicate(ch); i += 1u) {
        p->off = &p->off[1u];
    }
    return i;
}

static const char* s_take_while(ah_i_http_parser_t* p, bool (*predicate)(uint8_t))
{
    const char* str = (const char*) p->off;

    uint8_t ch;
    while (s_peek1(p, &ch) && predicate(ch)) {
        p->off = &p->off[1u];
    }

    return str;
}

static uint8_t s_to_lower_ascii(uint8_t ch)
{
    return (ch >= 'A' && ch <= 'Z') ? (ch | 0x20) : ch;
}
