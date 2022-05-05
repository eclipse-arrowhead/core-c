// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_HTTP_HMAP_H
#define SRC_HTTP_HMAP_H

#include "ah/http.h"

bool ah_i_http_hmap_is_transfer_encoding_chunked(ah_http_hmap_t* hmap);
ah_err_t ah_i_http_hmap_get_content_length(ah_http_hmap_t* hmap, size_t* content_length);

#endif
