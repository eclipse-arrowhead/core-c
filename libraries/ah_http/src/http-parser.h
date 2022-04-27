// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_HTTP_PARSER_H
#define SRC_HTTP_PARSER_H

#include "ah/http.h"

typedef struct ah_i_reader ah_i_reader_t;

struct ah_i_reader {
    uint8_t* off; // Pointer to next byte to read in `buf`
    const uint8_t* end; // Pointer beyond last byte to read in `buf`.
};

ah_err_t ah_i_http_parse_req_line(ah_i_reader_t* r, ah_http_req_line_t* req_line);
ah_err_t ah_i_http_parse_headers(ah_i_reader_t* r, ah_http_hmap_t* hmap);

#endif
