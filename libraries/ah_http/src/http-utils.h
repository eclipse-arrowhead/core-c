// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_HTTP_UTILS_H_
#define SRC_HTTP_UTILS_H_

#include "ah/http.h"

#include <ah/assert.h>

static inline ah_http_client_t* ah_i_http_ctx_to_client(void* ctx)
{
    ah_assert_if_debug(ctx != NULL);
    return ctx;
}

static inline ah_http_server_t* ah_i_http_ctx_to_server(void* ctx)
{
    ah_assert_if_debug(ctx != NULL);
    return ctx;
}

#endif
