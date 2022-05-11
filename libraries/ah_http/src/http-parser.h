// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_HTTP_PARSER_H
#define SRC_HTTP_PARSER_H

#include "ah/http.h"

ah_err_t ah_i_http_parse_chunk_line(ah_buf_rw_t* rw, ah_http_chunk_line_t* chunk_line);
ah_err_t ah_i_http_parse_header(ah_buf_rw_t* rw, ah_http_header_t* header);
ah_err_t ah_i_http_parse_req_line(ah_buf_rw_t* rw, ah_http_req_line_t* req_line);
ah_err_t ah_i_http_parse_stat_line(ah_buf_rw_t* rw, ah_http_stat_line_t* stat_line);

#endif
