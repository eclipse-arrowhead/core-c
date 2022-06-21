// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "udp-in.h"

#include "ah/alloc.h"
#include "ah/assert.h"

ah_udp_in_t* ah_i_udp_in_alloc()
{
    uint8_t* page = ah_palloc();
    if (page == NULL) {
        return NULL;
    }

    ah_udp_in_t* in = (void*) page;

    *in = (ah_udp_in_t) {
        .raddr = NULL,
        .buf = ah_buf_from(&page[sizeof(ah_udp_in_t)], AH_PSIZE - sizeof(ah_udp_in_t)),
        .nread = 0u,
    };

    return in;
}

void ah_i_udp_in_refresh(ah_udp_in_t** in, ah_udp_sock_in_mode_t mode)
{
    ah_assert_if_debug(in != NULL);

    switch (mode) {
    case AH_UDP_SOCK_IN_MODE_RESETTING: {
        uint8_t* page = (void*) in;
        **in = (ah_udp_in_t) {
            .buf = ah_buf_from(&page[sizeof(ah_udp_in_t)], AH_PSIZE - sizeof(ah_udp_in_t)),
            .nread = 0u,
        };
        break;
    }

    case AH_UDP_SOCK_IN_MODE_REPLACING: {
        *in = ah_i_udp_in_alloc();
        break;
    }

    default:
        ah_unreachable();
    }
}

void ah_i_udp_in_free(ah_udp_in_t* in)
{
    ah_assert_if_debug(in != NULL);

    ah_pfree(in);
}
