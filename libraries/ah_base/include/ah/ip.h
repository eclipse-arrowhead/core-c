// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_IP_H_
#define AH_IP_H_

#include "defs.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define AH_IPADDR_V4_STRLEN_MAX  16u
#define AH_IPADDR_V6_STRLEN_MAX  46u

struct ah_ipaddr_v4 {
    uint8_t octets[4];
};

struct ah_ipaddr_v6 {
    uint8_t octets[16];
};

static const ah_ipaddr_v4_t ah_ipaddr_v4_loopback = {
    { 127u, 0u, 0u, 1u }
};
static const ah_ipaddr_v4_t ah_ipaddr_v4_wildcard = {
    { 0u, 0u, 0u, 0u },
};

static const ah_ipaddr_v6_t ah_ipaddr_v6_loopback = {
    { 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u },
};
static const ah_ipaddr_v6_t ah_ipaddr_v6_wildcard = {
    { 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u },
};

ah_extern bool ah_ipaddr_v4_is_loopback(const ah_ipaddr_v4_t* addr);
ah_extern bool ah_ipaddr_v4_is_wildcard(const ah_ipaddr_v4_t* addr);
ah_extern bool ah_ipaddr_v6_is_loopback(const ah_ipaddr_v6_t* addr);
ah_extern bool ah_ipaddr_v6_is_wildcard(const ah_ipaddr_v6_t* addr);

ah_extern ah_err_t ah_ipaddr_v4_stringify(const struct ah_ipaddr_v4* addr, char* dest, size_t* dest_size);
ah_extern ah_err_t ah_ipaddr_v6_stringify(const struct ah_ipaddr_v6* addr, char* dest, size_t* dest_size);

#endif
