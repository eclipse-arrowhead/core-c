// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/sock.h"

#include "ah/assert.h"
#include "ah/err.h"

#include <inttypes.h>
#include <stdio.h>

ah_extern ah_err_t ah_sockaddr_init_ipv4(ah_sockaddr_t* sockaddr, uint16_t port, const struct ah_ipaddr_v4* ipaddr)
{
    if (sockaddr == NULL || ipaddr == NULL) {
        return AH_EINVAL;
    }

    sockaddr->as_ipv4 = (struct ah_sockaddr_ipv4)
    {
#if AH_I_SOCKADDR_HAS_SIZE
        .size = sizeof(struct sockaddr_in),
#endif
        .family = AH_SOCKFAMILY_IPV4,
        .port = port,
        .ipaddr = *ipaddr,
    };

    return AH_ENONE;
}

ah_extern ah_err_t ah_sockaddr_init_ipv6(ah_sockaddr_t* sockaddr, uint16_t port, const struct ah_ipaddr_v6* ipaddr)
{
    if (sockaddr == NULL || ipaddr == NULL) {
        return AH_EINVAL;
    }

    sockaddr->as_ipv6 = (struct ah_sockaddr_ipv6)
    {
#if AH_I_SOCKADDR_HAS_SIZE
        .size = sizeof(struct sockaddr_in6),
#endif
        .family = AH_SOCKFAMILY_IPV4, .port = port, .ipaddr = *ipaddr,
    };

    return AH_ENONE;
}

ah_extern bool ah_sockaddr_is_ip(const ah_sockaddr_t* sockaddr)
{
    ah_assert_if_debug(sockaddr != NULL);
    return sockaddr->as_any.family == AH_SOCKFAMILY_IPV4 || sockaddr->as_any.family == AH_SOCKFAMILY_IPV6;
}

ah_extern bool ah_sockaddr_is_ip_wildcard(const ah_sockaddr_t* sockaddr)
{
    ah_assert_if_debug(sockaddr != NULL);

    switch (sockaddr->as_any.family) {
    case AH_SOCKFAMILY_IPV4:
        return ah_ipaddr_v4_is_wildcard(&sockaddr->as_ipv4.ipaddr);

    case AH_SOCKFAMILY_IPV6:
        return ah_ipaddr_v6_is_wildcard(&sockaddr->as_ipv6.ipaddr);

    default:
        return false;
    }
}

ah_extern bool ah_sockaddr_is_ip_with_port_zero(const ah_sockaddr_t* sockaddr)
{
    ah_assert_if_debug(sockaddr != NULL);

    switch (sockaddr->as_any.family) {
    case AH_SOCKFAMILY_IPV4:
    case AH_SOCKFAMILY_IPV6:
        return sockaddr->as_ip.port == 0u;

    default:
        return false;
    }
}

ah_extern ah_err_t ah_sockaddr_stringify(const ah_sockaddr_t* sockaddr, char* dest, size_t* dest_size)
{
    ah_assert_if_debug(sockaddr != NULL);
    ah_assert_if_debug(dest != NULL);
    ah_assert_if_debug(dest_size != NULL);

    ah_err_t err;
    size_t dest_rem = *dest_size;

    switch (sockaddr->as_any.family) {
    case AH_SOCKFAMILY_IPV4: {
        size_t ipaddr_size = dest_rem;
        err = ah_ipaddr_v4_stringify(&sockaddr->as_ipv4.ipaddr, dest, &ipaddr_size);
        if (err != AH_ENONE) {
            return err;
        }
        dest = &dest[ipaddr_size];
        dest_rem -= ipaddr_size;

        size_t port_size;
        const int n = snprintf(dest, dest_rem, ":%" PRIu16, sockaddr->as_ipv4.port);
        if (n < 0) {
            return AH_EINTERN;
        }
        port_size = (size_t) n;
        if (port_size == dest_rem) {
            return AH_ENOSPC;
        }

        *dest_size = ipaddr_size + port_size;
        return AH_ENONE;
    }

    case AH_SOCKFAMILY_IPV6: {
        if (dest_rem <= 1u) {
            return AH_ENOSPC;
        }
        dest[0u] = '[';
        dest = &dest[1u];
        dest_rem -= 1u;

        size_t ipaddr_size = dest_rem;
        err = ah_ipaddr_v6_stringify(&sockaddr->as_ipv6.ipaddr, dest, &ipaddr_size);
        if (err != AH_ENONE) {
            return err;
        }
        dest = &dest[ipaddr_size];
        dest_rem -= ipaddr_size;

        size_t zone_id_size;
        if (sockaddr->as_ipv6.zone_id != 0u) {
            const int n = snprintf(dest, dest_rem, "%%25%" PRIu32, sockaddr->as_ipv6.zone_id);
            if (n < 0) {
                return AH_EINTERN;
            }
            zone_id_size = (size_t) n;
            if (zone_id_size == dest_rem) {
                return AH_ENOSPC;
            }
            dest = &dest[zone_id_size];
            dest_rem -= ipaddr_size;
        }
        else {
            zone_id_size = 0u;
        }

        if (dest_rem <= 1u) {
            return AH_ENOSPC;
        }
        dest[0u] = ']';
        dest = &dest[1u];
        dest_rem -= 1u;

        size_t port_size;
        const int n = snprintf(dest, dest_rem, ":%" PRIu16, sockaddr->as_ipv4.port);
        if (n < 0) {
            return AH_EINTERN;
        }
        port_size = (size_t) n;
        if (port_size == dest_rem) {
            return AH_ENOSPC;
        }

        *dest_size = 1u + ipaddr_size + zone_id_size + 1u + port_size;
        return AH_ENONE;
    }

    default:
        return AH_EPROTONOSUPPORT;
    }
}
