// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_HTTP_HMAP_H
#define SRC_HTTP_HMAP_H

#include "ah/http.h"

void ah_i_http_hmap_init(struct ah_http_hmap* hmap, struct ah_i_http_hmap_header* headers, size_t len);

static inline void ah_i_http_hmap_reset(struct ah_http_hmap* hmap)
{
    ah_assert_if_debug(hmap != NULL);
    (void) memset(hmap->_headers, 0, sizeof(struct ah_i_http_hmap_header) * (hmap->_mask + 1u));
    hmap->_count = 0u;
}

ah_err_t ah_i_http_hmap_is_transfer_encoding_chunked(ah_http_hmap_t* hmap, bool* is_chunked);
ah_err_t ah_i_http_hmap_get_content_length(ah_http_hmap_t* hmap, size_t* content_length);

#endif
