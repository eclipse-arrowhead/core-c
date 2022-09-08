// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_HTTP_WRITER_H_
#define SRC_HTTP_WRITER_H_

#include "ah/http.h"

bool ah_i_http_write_crlf(ah_rw_t* rw);
bool ah_i_http_write_cstr(ah_rw_t* rw, const char* cstr);
bool ah_i_http_write_size_as_string(ah_rw_t* rw, size_t size, unsigned base);

#endif
