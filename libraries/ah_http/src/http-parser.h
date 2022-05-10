// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_HTTP_PARSER_H
#define SRC_HTTP_PARSER_H

#include "ah/http.h"

void ah_i_http_rwbuf_init(struct ah_i_http_rwbuf* rw, const uint8_t* base, unsigned long size);

static inline bool ah_i_http_rwbuf_is_writable(struct ah_i_http_rwbuf* rw)
{
    ah_assert_if_debug(rw != NULL);
    return rw->_wr < rw->_end;
}

static inline size_t ah_i_http_rwbuf_get_readable_size(struct ah_i_http_rwbuf* rw)
{
    ah_assert_if_debug(rw != NULL);
    return (size_t) (rw->_wr - rw->_rd);
}

static inline void ah_i_http_rwbuf_set_readable_size(struct ah_i_http_rwbuf* rw, size_t size)
{
    ah_assert_if_debug(rw != NULL);
    ah_assert_if_debug(size <= (size_t) (rw->_end - rw->_wr));

    rw->_wr = &rw->_wr[size];
}

// Error codes:
// * AH_EOVERFLOW - `target` is not large enough to contain the not yet parsed
//                  bytes in `rw` and one additional byte.
ah_err_t ah_i_http_rwbuf_migrate_to(struct ah_i_http_rwbuf* rw, ah_buf_t* target);

void ah_i_http_parser_get_writable_buf(const struct ah_i_http_rwbuf* rw, ah_buf_t* target);

// Error codes common to the below three functions:
// * AH_EILSEQ - `buf` contains an illegal byte sequence at `parser` offset.
// * AH_EAGAIN - Parsing not complete, use ah_i_http_rwbuf_migrate_to() to move
//               any unparsed bytes to a new buffer, add more incoming bytes to
//               that buffer and then call the below function again with it. The
//               same `parser` must, of course, be used with each call.
ah_err_t ah_i_http_parse_res_line(struct ah_i_http_rwbuf* parser, const ah_buf_t* buf, size_t limit);
ah_err_t ah_i_http_parse_headers(struct ah_i_http_rwbuf* parser, const ah_buf_t* buf, size_t limit);
ah_err_t ah_i_http_parse_chunk_line(struct ah_i_http_rwbuf* parser, const ah_buf_t* buf, size_t limit);

/*
size_t readable_buf_size = ah_buf_get_size(&readable_buf);
if (cln->_i_n_expected_bytes < readable_buf_size) {
    err = ah_buf_init(&readable_buf, ah_buf_get_base(&readable_buf), cln->_i_n_expected_bytes);
    if (err != AH_ENONE) {
        goto close_conn_and_report_err;
    }
    cln->_i_n_expected_bytes = 0u;
}
else {
    cln->_i_n_expected_bytes -= readable_buf_size;
}
*/

#endif
