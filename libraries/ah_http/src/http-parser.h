// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_HTTP_PARSER_H
#define SRC_HTTP_PARSER_H

#include "ah/http.h"

typedef struct ah_i_http_reader ah_i_http_reader_t;

struct ah_i_http_reader {
    const uint8_t* _off;
    const uint8_t* const _end;
};

ah_i_http_reader_t ah_i_http_reader_from(const ah_buf_t* buf, size_t limit);
void ah_i_http_reader_into_buf(const ah_i_http_reader_t* r, ah_buf_t* buf);

ah_err_t ah_i_http_skip_until_after_line_end(ah_buf_t* src, size_t* size);
ah_err_t ah_i_http_skip_until_after_headers_end(ah_buf_t* src, size_t* size);
ah_err_t ah_i_http_parse_chunk(ah_buf_t* src, size_t* size, ah_http_chunk_t* chunk);
ah_err_t ah_i_http_parse_headers(ah_buf_t* src, size_t* size, ah_http_hmap_t* hmap);
ah_err_t ah_i_http_parse_req_line(ah_buf_t* src, size_t* size, ah_http_req_line_t* req_line);
ah_err_t ah_i_http_parse_stat_line(ah_buf_t* src, size_t* size, ah_http_stat_line_t* stat_line);

#endif
