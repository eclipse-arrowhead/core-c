// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include <ah/unit.h>

static void s_should_be_safe_to_cast_tcp_conn_to_http_client(ah_unit_t* unit);

void test_http_client(ah_unit_t* unit)
{
    s_should_be_safe_to_cast_tcp_conn_to_http_client(unit);
}

static void s_should_be_safe_to_cast_tcp_conn_to_http_client(ah_unit_t* unit)
{
    size_t conn_offset = offsetof(ah_http_client_t, _conn);
    ah_unit_assert_unsigned_eq(unit, 0u, conn_offset);
}
