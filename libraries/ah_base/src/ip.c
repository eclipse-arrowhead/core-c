// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/ip.h"

#include "ah/assert.h"
#include "ah/defs.h"

ah_extern bool ah_ipaddr_v4_is_loopback(const ah_ipaddr_v4_t* addr)
{
    ah_assert_if_debug(addr != NULL);

    return memcmp(addr->octets, ah_ipaddr_v4_loopback.octets, 4u) == 0;
}

ah_extern bool ah_ipaddr_v4_is_wildcard(const ah_ipaddr_v4_t* addr)
{
    ah_assert_if_debug(addr != NULL);

    return memcmp(addr->octets, ah_ipaddr_v4_wildcard.octets, 4u) == 0;
}

ah_extern bool ah_ipaddr_v6_is_loopback(const ah_ipaddr_v6_t* addr)
{
    ah_assert_if_debug(addr != NULL);

    return memcmp(addr->octets, ah_ipaddr_v6_loopback.octets, 16u) == 0;
}

ah_extern bool ah_ipaddr_v6_is_wildcard(const ah_ipaddr_v6_t* addr)
{
    ah_assert_if_debug(addr != NULL);

    return memcmp(addr->octets, ah_ipaddr_v6_wildcard.octets, 16u) == 0;
}
