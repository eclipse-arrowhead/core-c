// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "udp-in.h"

#include "ah/alloc.h"
#include "ah/assert.h"
#include "ah/err.h"

ah_err_t ah_i_udp_in_alloc_for(ah_udp_in_t** owner_ptr)
{
    ah_assert_if_debug(owner_ptr != NULL);

    uint8_t* page = ah_palloc();
    if (page == NULL) {
        return AH_ENOMEM;
    }

    ah_udp_in_t* in = (void*) page;

    *in = (ah_udp_in_t) {
        .raddr = NULL,
        .buf = ah_buf_from(&page[sizeof(ah_udp_in_t)], AH_PSIZE - sizeof(ah_udp_in_t)),
        .nrecv = 0u,
        ._owner_ptr = owner_ptr,
    };

    if (ah_buf_get_size(&in->buf) > AH_PSIZE) {
        ah_pfree(page);
        return AH_EOVERFLOW;
    }

    *owner_ptr = in;

    return AH_ENONE;
}

ah_err_t ah_i_udp_in_detach(ah_udp_in_t* in)
{
    ah_assert_if_debug(in != NULL);

    ah_err_t err = ah_i_udp_in_alloc_for(in->_owner_ptr);
    if (err != AH_ENONE) {
        return err;
    }

    in->_owner_ptr = NULL;

    return AH_ENONE;
}

void ah_i_udp_in_free(ah_udp_in_t* in)
{
    ah_assert_if_debug(in != NULL);

    ah_pfree(in);
}

void ah_i_udp_in_reset(ah_udp_in_t* in)
{
    ah_assert_if_debug(in != NULL);

    uint8_t* page = (uint8_t*) in;

    in->raddr = NULL;
    in->buf = ah_buf_from(&page[sizeof(ah_udp_in_t)], AH_PSIZE - sizeof(ah_udp_in_t));
    in->nrecv = 0u;
}
