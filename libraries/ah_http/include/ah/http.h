// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_HTTP_H_
#define AH_HTTP_H_

#include <stdint.h>

#define AH_HTTP_METHOD_OTHER   0u
#define AH_HTTP_METHOD_CONNECT 1u
#define AH_HTTP_METHOD_DELETE  2u
#define AH_HTTP_METHOD_GET     3u
#define AH_HTTP_METHOD_HEAD    4u
#define AH_HTTP_METHOD_OPTIONS 5u
#define AH_HTTP_METHOD_PATCH   6u
#define AH_HTTP_METHOD_POST    7u
#define AH_HTTP_METHOD_PUT     8u
#define AH_HTTP_METHOD_TRACE   9u

typedef uint16_t ah_http_method_t;

typedef struct ah_http_req_line ah_http_req_line_t;
typedef struct ah_http_res_line ah_http_res_line_t;
typedef struct ah_http_version ah_http_version_t;

struct ah_http_version {
    uint8_t major;
    uint8_t minor;
};

struct ah_http_req_line {
    ah_http_version_t version;
    ah_http_method_t method;
    uint16_t target_off;
    uint16_t target_len;
};

struct ah_http_res_line {
    ah_http_version_t version;
    uint16_t code;
    uint16_t reason_off;
};

#endif
