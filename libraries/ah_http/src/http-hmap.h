// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_HTTP_IHEADERS_H
#define SRC_HTTP_IHEADERS_H

#include "ah/http.h"

ah_err_t ah_i_http_hmap_init(struct ah_http_hmap* hmap, struct ah_i_http_hmap_header* headers, size_t len);
ah_err_t ah_i_http_hmap_add(struct ah_http_hmap* hmap, ah_str_t name, ah_str_t value);

#endif
