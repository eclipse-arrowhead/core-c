// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include <ah/assert.h>

ah_extern ah_http_body_t ah_http_body_empty()
{
    return (ah_http_body_t) { ._as_any._kind = AH_I_HTTP_BODY_KIND_EMPTY };
}

ah_extern ah_http_body_t ah_http_body_from_buf(ah_buf_t buf)
{
    return (ah_http_body_t) { ._as_out._kind = AH_I_HTTP_BODY_KIND_MSG, ._as_out._out.buf = buf };
}

ah_extern ah_http_body_t ah_http_body_override(void)
{
    return (ah_http_body_t) { ._as_any._kind = AH_I_HTTP_BODY_KIND_OVERRIDE };
}
