// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_HTTP_IHEADERS_H
#define SRC_HTTP_IHEADERS_H

#include "ah/http.h"

ah_err_t ah_i_http_hmap_init(struct ah_http_hmap* headers, ah_alloc_cb alloc_cb, size_t capacity);
ah_err_t ah_i_http_hmap_add(struct ah_http_hmap* headers, const char* name, const char* value);
ah_err_t ah_i_http_hmap_add_if_not_exists(struct ah_http_hmap* headers, const char* name, const char* value);
void ah_i_http_hmap_term(struct ah_http_hmap* headers, ah_alloc_cb alloc_cb);

#endif
