// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_UDP_IN_H_
#define SRC_UDP_IN_H_

#include "ah/alloc.h"
#include "ah/assert.h"
#include "ah/udp.h"

static inline ah_udp_in_t* ah_i_udp_in_alloc()
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

static inline void ah_i_udp_in_free(ah_udp_in_t* in)
{
    ah_assert_if_debug(in != NULL);

    ah_pfree(in);
}

#endif
