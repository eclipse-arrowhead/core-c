// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_HTTP_H_
#define AH_HTTP_H_

#include <stdint.h>

typedef struct ah_http_req_line ah_http_req_line_t;
typedef struct ah_http_res_line ah_http_res_line_t;
typedef struct ah_http_version ah_http_version_t;

struct ah_http_version {
    uint8_t major;
    uint8_t minor;
};

struct ah_http_req_line {
    char* method;
    char* target;
    ah_http_version_t version;
};

struct ah_http_res_line {
    ah_http_version_t version;
    uint16_t code;
    char* reason;
};

#endif
