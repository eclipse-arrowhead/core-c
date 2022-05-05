// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_HTTP_PARSER_H
#define SRC_HTTP_PARSER_H

#include "ah/http.h"

bool ah_i_http_buf_has_line_end(const ah_buf_t* buf);
bool ah_i_http_buf_has_headers_end(const ah_buf_t* buf);

ah_err_t ah_i_http_parse_headers(ah_buf_t* src, ah_http_hmap_t* hmap);
bool ah_i_http_parse_req_line(ah_buf_t* src, ah_http_req_line_t* req_line);
bool ah_i_http_parse_stat_line(ah_buf_t* src, ah_http_stat_line_t* stat_line);

#endif
