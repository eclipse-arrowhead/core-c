// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include <ah/unit.h>

static void s_should_be_safe_to_cast_tcp_listener_to_http_server(ah_unit_t* unit);

void test_http_server(ah_unit_t* unit)
{
    s_should_be_safe_to_cast_tcp_listener_to_http_server(unit);
}

static void s_should_be_safe_to_cast_tcp_listener_to_http_server(ah_unit_t* unit)
{
    size_t ln_offset = offsetof(ah_http_server_t, _ln);
    ah_unit_assert_unsigned_eq(unit, 0u, ln_offset);
}
