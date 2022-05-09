// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_HTTP_PARSER_H
#define SRC_HTTP_PARSER_H

#include "ah/http.h"

typedef struct ah_i_http_parser ah_i_http_parser_t;

void ah_i_http_parser_init(ah_i_http_parser_t* parser, const uint8_t* base, unsigned long size);

static inline bool ah_i_http_parser_is_writable(ah_i_http_parser_t* parser)
{
    ah_assert_if_debug(parser != NULL);
    return parser->_limit < parser->_end;
}

static inline size_t ah_i_http_parser_not_yet_parsed_size(ah_i_http_parser_t* parser)
{
    ah_assert_if_debug(parser != NULL);
    return (size_t) (parser->_limit - parser->_off);
}

// Error codes:
// * AH_EOVERFLOW - `buf` is not large enough to contain the not yet parsed
//                  bytes in `parser` and one additional byte.
ah_err_t ah_i_http_parser_migrate_to(ah_i_http_parser_t* parser, ah_buf_t* buf);

void ah_i_http_parser_get_writable_buf(const ah_i_http_parser_t* parser, ah_buf_t* buf);

// Error codes common to the below three functions:
// * AH_EILSEQ - `buf` contains an illegal byte sequence at `parser` offset.
// * AH_EAGAIN - Parsing not complete, use ah_i_http_parser_migrate_to() to move
//               any unparsed bytes to a new buffer, add more incoming bytes to
//               that buffer and then call the below function again with it. The
//               same `parser` must, of course, be used with each call.
ah_err_t ah_i_http_parse_res_line(ah_i_http_parser_t* parser, const ah_buf_t* buf, size_t limit);
ah_err_t ah_i_http_parse_headers(ah_i_http_parser_t* parser, const ah_buf_t* buf, size_t limit);
ah_err_t ah_i_http_parse_chunk_line(ah_i_http_parser_t* parser, const ah_buf_t* buf, size_t limit);

#endif
