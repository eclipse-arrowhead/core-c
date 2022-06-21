// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_HTTP_PARSER_H_
#define SRC_HTTP_PARSER_H_

#include "ah/http.h"

typedef struct ah_i_http_parser {
    uint8_t* off;
    uint8_t* end;
} ah_i_http_parser_t;

ah_err_t ah_i_http_parser_init(struct ah_i_http_parser* parser, ah_tcp_in_t* in, struct ah_i_http_in_scratchpad* scratchpad);

ah_err_t ah_i_http_parse_chunk_line(ah_i_http_parser_t* p, size_t* size, const char** ext);
ah_err_t ah_i_http_parse_header(ah_i_http_parser_t* p, ah_http_header_t* header);
ah_err_t ah_i_http_parse_req_line(ah_i_http_parser_t* p, const char** line, ah_http_ver_t* version);
ah_err_t ah_i_http_parse_stat_line(ah_i_http_parser_t* p, const char** line, ah_http_ver_t* version);

ah_err_t ah_i_http_header_name_eq(const char* expected_lowercase, const char* actual);
ah_err_t ah_i_http_header_value_find_csv(const char* value, const char* csv_lowercase, const char** rest);
ah_err_t ah_i_http_header_value_to_size(const char* value, size_t* size);

#endif
