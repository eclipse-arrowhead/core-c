// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_IP_H_
#define AH_IP_H_

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

struct ah_ipaddr_v4 {
    uint8_t octets[4];
};

struct ah_ipaddr_v6 {
    uint8_t octets[16];
};

static const struct ah_ipaddr_v4 ah_ipaddr_v4_loopback = {
    .octets = {127u, 0u, 0u, 1u},
};
static const struct ah_ipaddr_v4 ah_ipaddr_v4_wildcard = {
    .octets = {0u, 0u, 0u, 0u},
};

static const struct ah_ipaddr_v6 ah_ipaddr_v6_loopback = {
    .octets = {0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u},
};
static const struct ah_ipaddr_v6 ah_ipaddr_v6_wildcard = {
    .octets = {0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u},
};

ah_extern_inline bool ah_ipaddr_v4_is_loopback(const struct ah_ipaddr_v4 addr)
{
    return memcmp(addr.octets, ah_ipaddr_v4_loopback.octets, 4u) == 0;
}

ah_extern_inline bool ah_ipaddr_v4_is_wildcard(const struct ah_ipaddr_v4 addr)
{
    return memcmp(addr.octets, ah_ipaddr_v4_wildcard.octets, 4u) == 0;
}

ah_extern_inline bool ah_ipaddr_v6_is_loopback(const struct ah_ipaddr_v6 addr)
{
    return memcmp(addr.octets, ah_ipaddr_v6_loopback.octets, 16u) == 0;
}

ah_extern_inline bool ah_ipaddr_v6_is_wildcard(const struct ah_ipaddr_v6 addr)
{
    return memcmp(addr.octets, ah_ipaddr_v6_wildcard.octets, 16u) == 0;
}

#endif
