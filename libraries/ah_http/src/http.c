// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include <ah/assert.h>
#include <ah/err.h>
#include <stdbool.h>
#include <string.h>

typedef struct s_reader s_reader_t;

#define A 0x01
#define D 0x02
#define P 0x04
#define S 0x08
#define T 0x10

#define is_alpha(b) (s_chr_classes[(b)] == A)
#define is_digit(b) (s_chr_classes[(b)] == D)
#define is_tchar(b) ((s_chr_classes[(b)] & (A | D | T)) != 0u)

static uint8_t s_chr_classes[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    S, T, P, T, T, T, T, T, P, P, T, T, P, T, T, P,
    D, D, D, D, D, D, D, D, D, D, P, P, P, P, P, P,
    P, A, A, A, A, A, A, A, A, A, A, A, A, A, A, A,
    A, A, A, A, A, A, A, A, A, A, A, P, P, P, T, T,
    P, A, A, A, A, A, A, A, A, A, A, A, A, A, A, A,
    A, A, A, A, A, A, A, A, A, A, A, P, T, P, T, 0,
};

struct s_reader {
    size_t off;
    size_t len;
    uint8_t* src;
};

static ah_err_t s_parse_method(ah_http_method_t* method, s_reader_t* r);
static ah_err_t s_parse_req_line(ah_http_req_line_t* req_line, s_reader_t* r);
static ah_err_t s_parse_version(ah_http_version_t* ver, s_reader_t* r);

static ah_err_t s_parse_method(ah_http_method_t* method, s_reader_t* r)
{
    switch (r->src[0u]) {
    case 'C':
        if (memcmp(r->src, "CONNECT ", 8u) == 0) {
            *method = AH_HTTP_METHOD_CONNECT;
            r->src = &r->src[7u];
            return AH_ENONE;
        }

    case 'D':

    case 'G':

    case 'H':

    case 'O':

    case 'P':

    case 'T':

    default:
        break;
    }

    "CONNECT";
    "DELETE";
    "GET";
    "HEAD";
    "OPTIONS";
    "PATCH";
    "POST";
    "PUT";
    "TRACE";
}

static ah_err_t s_parse_req_line(ah_http_req_line_t* req_line, s_reader_t* r)
{
    ah_err_t err;

    while (r->src != r->end && is_tchar(r->src[0u])) {
        r->src = &r->src[1u];
    }

    if (r->src[0u] != ' ') {
        return AH_EILSEQ;
    }
    r->src = &r->src[1u];

    err = s_parse_version(&req_line->version, r);
    if (err != AH_ENONE) {
        return err;
    }

    if (r->src[0u] != ' ') {
        return AH_EILSEQ;
    }
    r->src = &r->src[1u];

    // TODO

    return AH_ENONE;
}

static ah_err_t s_parse_version(ah_http_version_t* ver, s_reader_t* r)
{
    ah_assert_if_debug(ver != NULL);
    ah_assert_if_debug(r != NULL);

    if (r->end - r->src < 8u) {
        return AH_EILSEQ;
    }
    if (memcmp(r->src, "HTTP", 4u) != 0 || r->src[4u] != '/') {
        return AH_EILSEQ;
    }
    if (!is_digit(r->src[5u]) || r->src[6u] != '.' || !is_digit(r->src[7u])) {
        return AH_EILSEQ;
    }

    ver->major = '0' - r->src[5u];
    ver->minor = '0' - r->src[7u];

    r->src = &r->src[8u];

    return AH_ENONE;
}
