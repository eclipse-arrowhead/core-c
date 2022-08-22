// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_HTTP_UTILS_H_
#define SRC_HTTP_UTILS_H_

#include "ah/http.h"

#include <ah/assert.h>

static inline ah_http_client_t* ah_i_http_conn_to_client(ah_tcp_conn_t* conn)
{
    ah_assert_if_debug(conn != NULL);

    // This is only safe if `conn` is a member of an ah_http_client_t value.
    const size_t conn_member_offset = offsetof(ah_http_client_t, _conn);
    ah_assert_if_debug(conn_member_offset <= PTRDIFF_MAX);
    ah_http_client_t* cln = (ah_http_client_t*) &((uint8_t*) conn)[-((ptrdiff_t) conn_member_offset)];

    return cln;
}

static inline ah_http_server_t* ah_i_http_conn_to_server(ah_tcp_listener_t* ln)
{
    ah_assert_if_debug(ln != NULL);

    // This is only safe if `ln` is a member of an ah_http_server_t value.
    const size_t ln_member_offset = offsetof(ah_http_server_t, _ln);
    ah_assert_if_debug(ln_member_offset <= PTRDIFF_MAX);
    ah_http_server_t* srv = (ah_http_server_t*) &((uint8_t*) ln)[-((ptrdiff_t) ln_member_offset)];

    return srv;
}

#endif
