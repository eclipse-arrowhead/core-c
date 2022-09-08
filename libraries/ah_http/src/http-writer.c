// SPDX-License-Identifier: EPL-2.0

#include "http-writer.h"

#include <ah/assert.h>

bool ah_i_http_write_crlf(ah_rw_t* rw)
{
    ah_assert_if_debug(rw != NULL);

    if ((rw->e - rw->w) < 2u) {
        return false;
    }

    rw->w[0u] = '\r';
    rw->w[1u] = '\n';
    rw->w = &rw->w[2u];

    return true;
}

bool ah_i_http_write_cstr(ah_rw_t* rw, const char* cstr)
{
    ah_assert_if_debug(rw != NULL);

    const uint8_t* c = (const uint8_t*) cstr;
    uint8_t* wr = rw->w;

    while (wr != rw->e) {
        if (c[0u] == '\0') {
            rw->w = wr;
            return true;
        }

        wr[0u] = c[0u];

        wr = &wr[1u];
        c = &c[1u];
    }

    return false;
}

bool ah_i_http_write_size_as_string(ah_rw_t* rw, size_t size, unsigned base)
{
    ah_assert_if_debug(rw != NULL);
    ah_assert_if_debug(base >= 10u && base <= 16u);

    if (size == 0u) {
        return ah_rw_write1(rw, '0');
    }

    uint8_t buf[20];
    uint8_t* off = &buf[sizeof(buf) - 1u];
    const uint8_t* end = &buf[sizeof(buf)];

    uint64_t s = size;
    for (;;) {
        uint8_t digit = (uint8_t) (s % base);
        if (digit < 10u) {
            off[0u] = '0' + digit;
        }
        else {
            off[0u] = 'A' + digit - 10u;
        }
        s /= base;
        if (s == 0u) {
            break;
        }
        off = &off[-1];
    }

    return ah_rw_writen(rw, off, (size_t) (end - off));
}
