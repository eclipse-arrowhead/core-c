// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_HTTP_WRITER_H_
#define SRC_HTTP_WRITER_H_

#include "ah/http.h"

bool ah_i_http_write_crlf(ah_prw_t* rw);
bool ah_i_http_write_cstr(ah_prw_t* rw, const char* cstr);
bool ah_i_http_write_size_as_string(ah_prw_t* rw, size_t size, unsigned base);

#endif
