// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_HTTP_H_
#define AH_HTTP_H_

#include <stdint.h>

typedef struct ah_http_req ah_http_req_t;
typedef struct ah_http_res ah_http_res_t;
typedef struct ah_http_ver ah_http_ver_t;

struct ah_http_ver {
    uint8_t major;
    uint8_t minor;
};

struct ah_http_req {
    char* method;
    char* scheme;
    char* authority;
    char* path;
    ah_http_ver_t version;
};

struct ah_http_res {
    ah_http_ver_t version;
    uint16_t code;
    char* reason;
};

#endif
