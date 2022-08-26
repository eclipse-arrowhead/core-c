// SPDX-License-Identifier: EPL-2.0

#include "ah/ip.h"

#include "ah/assert.h"
#include "ah/defs.h"
#include "ah/err.h"

#include <stdio.h>

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

ah_extern ah_err_t ah_ipaddr_v4_stringify(const struct ah_ipaddr_v4* addr, char* dest, size_t* dest_size)
{
    if (addr == NULL || dest == NULL || dest_size == NULL) {
        return AH_EINVAL;
    }

    char buf[AH_IPADDR_V4_STRLEN_MAX];

    const int n = snprintf(buf, sizeof(buf), "%d.%d.%d.%d",
        addr->octets[0], addr->octets[1], addr->octets[2], addr->octets[3]);

    if (n < 0) {
        return AH_EINTERN;
    }

    if (((size_t) n) < *dest_size) {
        (void) memcpy(dest, buf, n + 1u);
        *dest_size = n;
        return AH_ENONE;
    }

    return AH_EOVERFLOW;
}

ah_extern ah_err_t ah_ipaddr_v6_stringify(const struct ah_ipaddr_v6* addr, char* dest, size_t* dest_size)
{
    if (addr == NULL || dest == NULL || dest_size == NULL) {
        return AH_EINVAL;
    }

    char buf[AH_IPADDR_V6_STRLEN_MAX];
    size_t buf_i = 0u;

    struct {
        size_t offset;
        size_t size;
    } double_colon_range = { 0u }, candidate_double_colon_range = { 0u };

    for (size_t i = 0u; i < 16u; i += 2u) {
        if (addr->octets[i] == 0 && addr->octets[i + 1u] == 0) {
            candidate_double_colon_range.size += 2u;
            continue;
        }
        if (double_colon_range.size < candidate_double_colon_range.size) {
            double_colon_range = candidate_double_colon_range;
        }
        candidate_double_colon_range.offset = i + 2u;
        candidate_double_colon_range.size = 0u;
    }

    // Does address consists of only zeroes?
    if (candidate_double_colon_range.size == 16u) {
        if (*dest_size > 2u) {
            (void) memcpy(dest, "::", 3u);
            *dest_size = 2u;
            return AH_ENONE;
        }
        return AH_EOVERFLOW;
    }

    int n;

    for (size_t i = 0u; i < 16u; i += 2u) {
        if (i == double_colon_range.offset && double_colon_range.size != 0u) {
            buf[buf_i] = ':';
            buf_i += 1u;

            if (i == 0u) {
                // Does address start with 0:0:0:0:0:FFFF? It is an IPv4-mapped IPv6 address!
                if (double_colon_range.size == 10u && addr->octets[10] == 0xFF && addr->octets[11] == 0xFF) {
                    n = snprintf(&buf[buf_i], AH_IPADDR_V6_STRLEN_MAX - buf_i, ":FFFF:%d.%d.%d.%d",
                        addr->octets[12], addr->octets[13], addr->octets[14], addr->octets[15]);
                    if (n < 0) {
                        return AH_EINTERN;
                    }
                    buf_i += (size_t) n;
                    break;
                }

                // Does address start with 0:0:0:0:0:0? It is an IPv4-compatible IPv6 address!
                if (double_colon_range.size == 12u) {
                    n = snprintf(&buf[buf_i], AH_IPADDR_V6_STRLEN_MAX - buf_i, ":%d.%d.%d.%d",
                        addr->octets[12], addr->octets[13], addr->octets[14], addr->octets[15]);
                    if (n < 0) {
                        return AH_EINTERN;
                    }
                    buf_i += (size_t) n;
                    break;
                }
            }

            i += double_colon_range.size - 2u;

            continue;
        }
        else if (i != 0u) {
            buf[buf_i] = ':';
            buf_i += 1u;
        }

        uint16_t value = ((uint16_t) addr->octets[i]) << 8 | addr->octets[i + 1u];
        n = snprintf(&buf[buf_i], AH_IPADDR_V6_STRLEN_MAX - buf_i, "%X", value);
        if (n < 0) {
            return AH_EINTERN;
        }
        buf_i += (size_t) n;
    }

    if (buf_i < *dest_size) {
        (void) memcpy(dest, buf, buf_i + 1u);
        *dest_size = buf_i;
        return AH_ENONE;
    }

    return AH_EOVERFLOW;
}
