// SPDX-License-Identifier: EPL-2.0

#include "ah/json.h"

#include <ah/assert.h>
#include <ah/err.h>

static uint32_t s_integer_from_hex_digit(char hex_digit);
static char s_integer_into_hex_digit(char i);
static size_t s_escape_sequence_to_utf8(const char* src, size_t src_length, char* dst, size_t* dst_length);

ah_extern int ah_json_str_compare(const char* a, size_t a_length, const char* b, size_t b_length)
{
    ah_assert_if_debug(a != NULL || a_length == 0u);
    ah_assert_if_debug(b != NULL || b_length == 0u);

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
    ah_assert_if_debug(src != NULL || src_length == 0u);
    ah_assert_if_debug(dst_length != NULL);
    ah_assert_if_debug(dst != NULL || *dst_length == 0u);

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

        uint32_t codepoint
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

        if (codepoint < 0x100000) {
            // 1110xxxx 10xxxxxx 10xxxxxx
            dst[0u] = (char) (0xE0 | ((codepoint >> 12u) & 0x0F));
            dst[1u] = (char) (0x80 | ((codepoint >> 6u) & 0x3F));
            dst[2u] = (char) (0x80 | ((codepoint >> 0u) & 0x3F));
            *dst_length = 3u;
            return 6u;
        }

        // fallthrough

    default:
        *dst_length = 0u;
        return 0u;
    }
}

static uint32_t s_integer_from_hex_digit(char hex_digit)
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

    return 0xFFFFFFFF; // No valid UTF-16 codepoint has this code.
}

ah_extern ah_err_t ah_json_str_escape(const char* src, size_t src_length, char* dst, size_t* dst_length)
{
    if (src == NULL && src_length != 0u) {
        return AH_EINVAL;
    }
    if (dst_length == NULL) {
        return AH_EINVAL;
    }
    if (dst == NULL && *dst_length != 0u) {
        return AH_EINVAL;
    }

    ah_err_t err;

    size_t dst_length0 = *dst_length;

    while (src_length != 0u) {
        if (dst_length0 == 0u) {
            goto handle_overflow;
        }

        char ch = src[0u];

        src = &src[1u];
        src_length -= 1u;

        if (((unsigned char) ch) >= 0x20 && ch != '"' && ch != '\\') {
            dst[0u] = ch;
            dst = &dst[1u];
            dst_length0 -= 1u;
            continue;
        }

        switch (ch) {
        case '\b':
            ch = 'b';
            break;

        case '\f':
            ch = 'f';
            break;

        case '\n':
            ch = 'n';
            break;

        case '\r':
            ch = 'r';
            break;

        case '\t':
            ch = 't';
            break;

        case '"':
            ch = '"';
            break;

        case '\\':
            ch = '\\';
            break;

        default:
            if (dst_length0 < 6u) {
                goto handle_overflow;
            }

            dst[0u] = '\\';
            dst[1u] = 'u';
            dst[2u] = '0';
            dst[3u] = '0';
            dst[4u] = s_integer_into_hex_digit((char) ((ch & 0xf0) >> 4u));
            dst[5u] = s_integer_into_hex_digit((char) ((ch & 0x0f) >> 0u));

            dst = &dst[6u];
            dst_length0 -= 6u;

            continue;
        }


        if (dst_length0 < 2u) {
            goto handle_overflow;
        }

        dst[0u] = '\\';
        dst[1u] = ch;

        dst = &dst[2u];
        dst_length0 -= 2u;
    }

    err = AH_ENONE;
    goto end;

handle_overflow:
    err = AH_EOVERFLOW;

end:
    *dst_length -= dst_length0;

    return err;

}

static char s_integer_into_hex_digit(char i)
{
    if (i >= 0 && i <= 9) {
        return (char) ('0' + i);
    }

    if (i >= 10 && i <= 15) {
        return (char) ('A' + (i - 10));
    }

    ah_unreachable();
}

ah_extern ah_err_t ah_json_str_unescape(const char* src, size_t src_length, char* dst, size_t* dst_length)
{
    if (src == NULL && src_length != 0u) {
        return AH_EINVAL;
    }
    if (dst_length == NULL) {
        return AH_EINVAL;
    }
    if (dst == NULL && *dst_length != 0u) {
        return AH_EINVAL;
    }

    ah_err_t err;

    size_t dst_length0 = *dst_length;

    while (src_length != 0u) {
        if (dst_length0 == 0u) {
            err = AH_EOVERFLOW;
            goto handle_err;
        }

        char ch = src[0u];

        if (ch != '\\') {
            dst[0u] = ch;

            src = &src[1u];
            dst = &dst[1u];
            src_length -= 1u;
            dst_length0 -= 1u;
            continue;
        }

        char buf[4u];
        size_t buf_length = sizeof(buf);

        size_t n_read = s_escape_sequence_to_utf8(src, src_length, buf, &buf_length);
        if (n_read == 0u) {
            err = AH_EILSEQ;
            goto handle_err;
        }
        src = &src[n_read];
        src_length -= n_read;

        if (buf_length > dst_length0) {
            err = AH_EOVERFLOW;
            goto handle_err;
        }
        memcpy(dst, buf, buf_length);
        dst = &dst[buf_length];
        dst_length0 -= buf_length;
    }

    err = AH_ENONE;

handle_err:
    *dst_length -= dst_length0;

    return err;
}
