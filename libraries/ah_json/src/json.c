// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/json.h"

#include <ah/assert.h>
#include <ah/err.h>

static uint8_t s_integer_from_hex_digit(char hex_digit);
static size_t s_escape_sequence_to_utf8(const char* src, size_t src_length, char* dst, size_t* dst_length);

ah_extern int ah_json_str_compare(const char* a, size_t a_length, const char* b, size_t b_length)
{
    while (a_length != 0u && b_length != 0u) {
        int diff = a[0u] - b[0u];

        if (diff == 0) {
            a = &a[1u];
            b = &b[1u];
            a_length -= 1u;
            b_length -= 1u;
            continue;
        }

        char buf[4u] = { 0u, 0u, 0u, 0u };

        if (a[0u] == '\\') {
            size_t buf_length = sizeof(buf);
            size_t n_read = s_escape_sequence_to_utf8(a, a_length, buf, &buf_length);
            diff = memcmp(buf, b, buf_length);
            if (diff == 0) {
                a = &a[n_read];
                b = &b[buf_length];
                a_length -= n_read;
                b_length -= buf_length;
                continue;
            }
        }

        if (b[0u] == '\\') {
            size_t buf_length = sizeof(buf);
            size_t n_read = s_escape_sequence_to_utf8(b, b_length, buf, &buf_length);
            diff = memcmp(a, buf, buf_length);
            if (diff == 0) {
                a = &a[buf_length];
                b = &b[n_read];
                a_length -= buf_length;
                b_length -= n_read;
                continue;
            }
        }

        return diff;
    }

    if (a_length > b_length) {
        return 1;
    }
    else if (a_length == b_length) {
        return 0;
    }
    else {
        return -1;
    }
}

static size_t s_escape_sequence_to_utf8(const char* src, size_t src_length, char* dst, size_t* dst_length)
{
    if (src_length < 2u) {
        *dst_length = 0u;
        return 0u;
    }

    ah_assert_if_debug(src[0u] == '\\');

    switch (src[1u]) {
    case '"':
    case '\\':
    case '/':
        dst[0u] = src[1u];
        *dst_length = 1u;
        return 2u;

    case 'b':
        dst[0u] = '\b';
        *dst_length = 1u;
        return 2u;

    case 'f':
        dst[0u] = '\f';
        *dst_length = 1u;
        return 2u;

    case 'n':
        dst[0u] = '\n';
        *dst_length = 1u;
        return 2u;

    case 'r':
        dst[0u] = '\r';
        *dst_length = 1u;
        return 2u;

    case 't':
        dst[0u] = '\t';
        *dst_length = 1u;
        return 2u;

    case 'u':
        if (src_length < 6) {
            *dst_length = 0u;
            return 0u;
        }

        uint16_t codepoint
            = (s_integer_from_hex_digit(src[2u]) << 12u)
            | (s_integer_from_hex_digit(src[3u]) << 8u)
            | (s_integer_from_hex_digit(src[4u]) << 4u)
            | (s_integer_from_hex_digit(src[5u]) << 0u);

        if (codepoint < 0x80) {
            // 0xxxxxxx
            dst[0u] = (char) (codepoint & 0xFF);
            *dst_length = 1u;
            return 6u;
        }

        if (codepoint < 0x800) {
            // 110xxxxx 10xxxxxx
            dst[0u] = (char) (0xC0 | ((codepoint >> 6u) & 0x1F));
            dst[1u] = (char) (0x80 | ((codepoint >> 0u) & 0x3F));
            *dst_length = 2u;
            return 6u;
        }

        // 1110xxxx 10xxxxxx 10xxxxxx
        dst[0u] = (char) (0xE0 | ((codepoint >> 12u) & 0x0F));
        dst[1u] = (char) (0x80 | ((codepoint >> 6u) & 0x3F));
        dst[2u] = (char) (0x80 | ((codepoint >> 0u) & 0x3F));
        *dst_length = 3u;
        return 6u;

    default:
        *dst_length = 0u;
        return 0u;
    }
}

static uint8_t s_integer_from_hex_digit(char hex_digit)
{
    if (hex_digit >= '0' && hex_digit <= '9') {
        return hex_digit - '0';
    }

    if (hex_digit >= 'A' && hex_digit <= 'F') {
        return (hex_digit - 'A') + 10u;
    }

    if (hex_digit >= 'a' && hex_digit <= 'f') {
        return (hex_digit - 'a') + 10u;
    }

    return 0;
}

ah_extern ah_err_t ah_json_str_unescape(const char* src, size_t src_length, char* dst, size_t* dst_length)
{
    (void) src;
    (void) src_length;
    (void) dst;
    (void) dst_length;

    return AH_EOPNOTSUPP;
}

ah_extern ah_err_t ah_json_parse(ah_buf_t src, ah_json_buf_t* dst)
{
    (void) src;
    (void) dst;

    return AH_EOPNOTSUPP;
}
