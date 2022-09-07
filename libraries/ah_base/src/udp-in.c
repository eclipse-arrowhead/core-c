// SPDX-License-Identifier: EPL-2.0

#include "ah/udp.h"

#include "ah/err.h"

ah_extern ah_err_t ah_udp_in_alloc_for(ah_udp_in_t** owner_ptr)
{
    if (owner_ptr == NULL) {
        return AH_EINVAL;
    }

    uint8_t* page = ah_palloc();
    if (page == NULL) {
        return AH_ENOMEM;
    }

    ah_udp_in_t* in = (void*) page;

    *in = (ah_udp_in_t) {
        .raddr = NULL,
        .buf = ah_buf_from(&page[sizeof(ah_udp_in_t)], AH_UDP_IN_BUF_SIZE),
        .nrecv = 0u,
        ._owner_ptr = owner_ptr,
    };

    if (in->buf.size > AH_PSIZE) {
        ah_pfree(page);
        return AH_EOVERFLOW;
    }

    *owner_ptr = in;

    return AH_ENONE;
}

ah_extern ah_err_t ah_udp_in_detach(ah_udp_in_t* in)
{
    if (in == NULL) {
        return AH_EINVAL;
    }
    if (in->_owner_ptr == NULL) {
        return AH_ESTATE;
    }

    ah_err_t err = ah_udp_in_alloc_for(in->_owner_ptr);
    if (err != AH_ENONE) {
        return err;
    }

    in->_owner_ptr = NULL;

    return AH_ENONE;
}

ah_extern void ah_udp_in_free(ah_udp_in_t* in)
{
    if (in != NULL) {
#ifndef NDEBUG
        memset(in, 0, AH_PSIZE);
#endif
        ah_pfree(in);
    }
}

ah_extern void ah_udp_in_reset(ah_udp_in_t* in)
{
    if (in == NULL) {
        return;
    }

    uint8_t* page = (uint8_t*) in;

    in->raddr = NULL;
    in->buf = ah_buf_from(&page[sizeof(ah_udp_in_t)], AH_UDP_IN_BUF_SIZE);
    in->nrecv = 0u;
}
