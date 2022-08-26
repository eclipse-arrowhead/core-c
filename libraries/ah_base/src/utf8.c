// SPDX-License-Identifier: EPL-2.0

#include "ah/utf8.h"

#include <ah/err.h>

ah_extern bool ah_utf8_validate(const char* src, size_t size)
{
    if (src == NULL && size != 0u) {
        return false;
    }

    // This implementation is based on the version made available under the MIT
    // license by Bjoern Hoehrmann <bjoern@hoehrmann.de> on his website,
    // available at http://bjoern.hoehrmann.de/utf-8/decoder/dfa/.

    // clang-format off

    static const uint8_t S_UTF8_CLASSES[] = {

        // To reduce space, we take advantage of that all bytes below 0x80 have
        // class 0 and remove them from the table. To reduce space further, we
        // also take advantage of that the largest class is 11. As 4 bits is
        // enough to represent every class, we can pair them together and halve
        // the size of this table.

        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, // 0x80..0x8F
        0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, // 0x90..0x9F
        0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, // 0xA0..0xAF
        0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, // 0xB0..0xBF
        0x88, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, // 0xC0..0xCF
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, // 0xD0..0xDF
        0xA3, 0x33, 0x33, 0x33, 0x33, 0x33, 0x34, 0x33, // 0xE0..0xEF
        0xB6, 0x66, 0x58, 0x88, 0x88, 0x88, 0x88, 0x88, // 0xF0..0xFF

    };

    static const uint8_t S_UTF8_TRANSITIONS[] = {

        // As the largest transition has number 8, we make use of the same
        // optimization as above and pack them together in pairs of two.

        0x01, 0x23, 0x58, 0x71, 0x11, 0x46, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x10, 0x11, 0x11, 0x10, 0x10, 0x11, 0x11, 0x11,
        0x12, 0x11, 0x11, 0x12, 0x12, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x12, 0x11, 0x11, 0x11, 0x11,
        0x12, 0x11, 0x11, 0x11, 0x12, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x13, 0x13, 0x11, 0x11, 0x11,
        0x13, 0x11, 0x11, 0x13, 0x13, 0x11, 0x11, 0x11,
        0x13, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    };

    // clang-format on

    uint8_t state = 0u;
    uint8_t class;

    while (size != 0u) {
        uint8_t byte = src[0u];

        src = &src[1u];
        size -= 1u;

        // The first 128 byte values all represent single-byte sequences, for
        // which reason they need no validation.
        if (byte < 0x80) {
            continue;
        }

        // Determine the class of the current byte.
        class = S_UTF8_CLASSES[(byte & 0x7F) >> 1u];
        class = (byte & 1u) == 0u
            ? (class >> 4u) & 0x0F
            : (class >> 0u) & 0x0F;

        // Transition the current state in relation to the byte's class.
        state = S_UTF8_TRANSITIONS[((state << 4u) + class) >> 1u];
        state = (class & 1u) == 0u
            ? (state >> 4u) & 0x0F
            : (state >> 0u) & 0x0F;

        // If the current state is 1, we have found a broken sequence or an
        // invalid codepoint.
        if (state == 1u) {
            return false;
        }
    }

    // If the current state is not 0, we ran out of data before we finished the
    // last started UTF-8 sequence.
    return state == 0u;
}

ah_extern ah_err_t ah_utf8_from_codepoint(uint32_t codepoint, char* dst, size_t* dst_length)
{
    if (dst_length == NULL || (dst == NULL && *dst_length != 0u)) {
        return AH_EINVAL;
    }

    size_t dst_length0 = *dst_length;

    if (codepoint <= 0x7F) {
        // 0xxxxxxx

        if (dst_length0 < 1u) {
            return AH_EOVERFLOW;
        }

        dst[0u] = (char) (codepoint & 0xFF);
        *dst_length = 1u;

        return AH_ENONE;
    }

    if (codepoint <= 0x7FF) {
        // 110xxxxx 10xxxxxx

        if (dst_length0 < 2u) {
            return AH_EOVERFLOW;
        }

        dst[0u] = (char) (0xC0 | ((codepoint >> 6u) & 0x1F));
        dst[1u] = (char) (0x80 | ((codepoint >> 0u) & 0x3F));
        *dst_length = 2u;

        return AH_ENONE;
    }

    if (codepoint <= 0xFFFF) {
        // 1110xxxx 10xxxxxx 10xxxxxx

        // These codepoints represent surrogate parts of pairs that may only be
        // used in UTF-16. See https://www.rfc-editor.org/rfc/rfc3629#section-3.
        if (codepoint >= 0xD800 && codepoint <= 0xDFFF) {
            return AH_EINVAL;
        }

        if (dst_length0 < 3u) {
            return AH_EOVERFLOW;
        }

        dst[0u] = (char) (0xE0 | ((codepoint >> 12u) & 0x0F));
        dst[1u] = (char) (0x80 | ((codepoint >> 6u) & 0x3F));
        dst[2u] = (char) (0x80 | ((codepoint >> 0u) & 0x3F));
        *dst_length = 3u;

        return AH_ENONE;
    }

    if (codepoint <= 0x10FFFF) {
        // 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx

        if (dst_length0 < 4u) {
            return AH_EOVERFLOW;
        }

        dst[0u] = (char) (0xF0 | ((codepoint >> 18u) & 0x07));
        dst[1u] = (char) (0x80 | ((codepoint >> 12u) & 0x3F));
        dst[2u] = (char) (0x80 | ((codepoint >> 6u) & 0x3F));
        dst[3u] = (char) (0x80 | ((codepoint >> 0u) & 0x3F));
        *dst_length = 4u;

        return AH_ENONE;
    }

    return AH_EINVAL;
}
