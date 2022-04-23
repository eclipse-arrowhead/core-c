// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

typedef struct s_reader s_reader_t;

struct s_reader {
    uint8_t* off;
    uint8_t* end;
};

static bool s_parse_request(s_reader_t* r, ah_http_req_t* request);

static bool s_is_digit(uint8_t ch);
static bool s_parse_method(s_reader_t* r, char** token);
static bool s_parse_target(s_reader_t* r, char** scheme, char** authority, char** path);
static bool s_parse_version(s_reader_t* r, ah_http_ver_t* version);
static bool s_skip_ch(s_reader_t* r, char ch);
static bool s_skip_str(s_reader_t* r, char* str, size_t len);

static bool s_parse_request(s_reader_t* r, ah_http_req_t* request)
{
    if (!s_parse_method(r, &request->method)) {
        return false;
    }

    if (!s_parse_target(r, &request->scheme, &request->authority, &request->path)) {
        return false;
    }

    // TODO: Check that the version is supported (i.e. is 1.0 or 1.1).
    if (!s_parse_version(r, &request->version)) {
        return false;
    }

    if (!s_skip_str(r, "\r\n", 2u)) {
        return false;
    }

    // TODO: Parse headers and body.

    return true;
}

static bool s_parse_method(s_reader_t* r, char** token)
{
    for (uint8_t* off = r->off; off != r->end; off = &off[1u]) {
        char ch = (char) *off;
        if (ch <= 0) {
            break;
        }
        if (ch != ' ') {
            continue;
        }

        off[0u] = '\0';
        *token = (char*) r->off;
        r->off = &off[1u];

        return true;
    }

    return false;
}

static bool s_parse_target(s_reader_t* r, char** scheme, char** authority, char** path)
{
    uint8_t* off = r->off;

    if (off == r->end) {
        return false;
    }

    // origin-form?
    if (*off == '/') {
        off = &off[1u];
        r->off = off; // Skip leading slash.
        goto parse_path;
    }

    // asterisk-form?
    if (*off == '*') {
        if (!s_skip_ch(r, ' ')) {
            return false;
        }

        off[0u] = '\0';
        *path = (char*) r->off;
        r->off = &off[1u];

        return true;
    }

    // If a scheme is present, absolute-form is used; authority-form otherwise.
    for (;;) {
        if (off == r->end) {
            return false;
        }

        char ch = (char) *off;
        if (ch <= 0) {
            return false;
        }
        if (ch != ':') {
            off = &off[1u];
            continue;
        }

        if ((size_t) (r->end - off) < 2u) {
            return false;
        }
        if (off[1u] == '/') {
            if (off[2u] != '/') {
                return false;
            }
            off[0u] = '\0';
            *scheme = (char*) r->off;
            r->off = &off[2u];
        }

        break;
    }

    // Parse authority.
    for (;;) {
        if (off == r->end) {
            return false;
        }

        char ch = (char) *off;
        if (ch <= 0) {
            return false;
        }
        if (ch != ' ' && ch != '/') {
            off = &off[1u];
            continue;
        }

        off[0u] = '\0';
        *authority = (char*) r->off;
        r->off = &off[1u];

        if (ch == ' ') {
            return true; // authority-form; we are done!
        }
    }

parse_path:
    for (;;) {
        if (off == r->end) {
            return false;
        }

        char ch = (char) *off;
        if (ch <= 0) {
            return false;
        }
        if (ch != ' ') {
            off = &off[1u];
            continue;
        }

        off[0u] = '\0';
        *path = (char*) r->off;
        r->off = &off[1u];

        return true;
    }
}

static bool s_skip_ch(s_reader_t* r, char ch)
{
    if (r->off == r->end || r->off[0u] != ch) {
        return false;
    }

    r->off = &r->off[1u];

    return true;
}

static bool s_parse_version(s_reader_t* r, ah_http_ver_t* version)
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

static bool s_is_digit(uint8_t ch)
{
    return ch >= '0' && ch <= '9';
}

static bool s_skip_str(s_reader_t* r, char* str, size_t len)
{
    if ((size_t) (r->end - r->off) < len) {
        return false;
    }
    if (memcmp(r->off, str, len) != 0) {
        return false;
    }

    r->off = &r->off[len];

    return true;
}
