// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include <ah/assert.h>

ah_extern ah_http_body_t ah_http_body_from_buf(ah_buf_t buf)
{
    return (ah_http_body_t) { ._as_buf._kind = AH_I_HTTP_BODY_KIND_BUF, ._as_buf._buf = buf };
}

ah_extern ah_http_body_t ah_http_body_from_bufs(ah_bufs_t bufs)
{
    return (ah_http_body_t) { ._as_bufs._kind = AH_I_HTTP_BODY_KIND_BUFS, ._as_bufs._bufs = bufs };
}

ah_extern ah_http_body_t ah_http_body_from_cb(void (*cb)(void*, ah_bufs_t*), void* user_data)
{
    ah_assert_if_debug(cb != NULL);

    return (ah_http_body_t) {
        ._as_cb._kind = AH_I_HTTP_BODY_KIND_CB,
        ._as_cb._cb = cb,
        ._as_cb._user_data = user_data,
    };
}

ah_extern ah_http_body_t ah_http_body_from_cstr(char* cstr)
{
    ah_assert_if_debug(cstr != NULL);

    ah_buf_t buf;
    ah_err_t err = ah_buf_init(&buf, (uint8_t*) cstr, strlen(cstr));
    ah_assert(err == 0);

    return ah_http_body_from_buf(buf);
}

ah_extern ah_http_body_t ah_http_body_override(void)
{
    return (ah_http_body_t) { ._as_any._kind = AH_I_HTTP_BODY_KIND_OVERRIDE };
}
