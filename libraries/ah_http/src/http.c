// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include <stdbool.h>
#include <string.h>

typedef struct s_reader s_reader_t;

struct s_reader {
    uint8_t* off;
    uint8_t* end;
};

static bool s_expect_crlf(s_reader_t* r);
static bool s_expect_space(s_reader_t* r);
static bool s_parse_space_terminated_string(char** token, s_reader_t* r);
static bool s_parse_req_line(ah_http_req_line_t* req_line, s_reader_t* r);
static bool s_parse_version(ah_http_version_t* ver, s_reader_t* r);

bool s_parse_space_terminated_string(char** token, s_reader_t* r)
{
    uint8_t* off = r->off;
    while (off != r->end) {
        char ch = (char) *off;
        if (ch <= 0) {
            break;
        }
        if (ch != ' ') {
            off = &off[1u];
            continue;
        }
        *off = '\0';
        *token = (char*) r->off;
        r->off = &off[1u];
        return true;
    }

    return false;
}

static bool s_expect_space(s_reader_t* r)
{
    if (r->off == r->end || r->off[0u] != ' ') {
        return false;
    }
    r->off = &r->off[1u];
    return true;
}

static bool s_parse_req_line(ah_http_req_line_t* req_line, s_reader_t* r)
{
    if (!s_parse_space_terminated_string(&req_line->method, r)) {
        return false;
    }

    if (!s_expect_space(r)) {
        return false;
    }

    if (!s_parse_space_terminated_string(&req_line->target, r)) {
        return false;
    }

    if (!s_expect_space(r)) {
        return false;
    }

    if (!s_parse_version(&req_line->version, r)) {
        return false;
    }

    return s_expect_crlf(r);
}

static bool s_parse_version(ah_http_version_t* ver, s_reader_t* r)
{
    if (r->end - r->off < 8u) {
        return false;
    }
    if (memcmp(r->off, "HTTP/", 5u) != 0) {
        return false;
    }
    if (r->off[5u] < '0' || r->off[5u] > '9' || r->off[6u] != '.' || r->off[7u] < '0' || r->off[7u] > '9') {
        return false;
    }

    ver->major = '0' - r->off[5u];
    ver->minor = '0' - r->off[7u];

    r->off = &r->off[8u];

    return true;
}

static bool s_expect_crlf(s_reader_t* r)
{
    if (r->end - r->off < 2u) {
        return false;
    }
    if (memcmp(r->off, "\r\n", 2u) != 0) {
        return false;
    }

    r->off = &r->off[2u];

    return true;
}
