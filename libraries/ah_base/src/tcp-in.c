// SPDX-License-Identifier: EPL-2.0

#include "ah/tcp.h"

#include "ah/err.h"
#include "ah/intrin.h"

#include <string.h>

ah_extern ah_err_t ah_tcp_in_alloc_for(ah_tcp_in_t** owner_ptr)
{
    if (owner_ptr == NULL) {
        return AH_EINVAL;
    }

    uint8_t* page = ah_palloc();
    if (page == NULL) {
        return AH_ENOMEM;
    }

    ah_tcp_in_t* in = (void*) page;

    uint8_t* base = &page[sizeof(ah_tcp_in_t)];
    uint8_t* end = &page[AH_PSIZE];

    if (base >= end) {
        return AH_EOVERFLOW;
    }

    *in = (ah_tcp_in_t) {
        .rw.r = base,
        .rw.w = base,
        .rw.e = end,
        ._owner_ptr = owner_ptr,
    };

    *owner_ptr = in;

    return AH_ENONE;
}

ah_extern ah_err_t ah_tcp_in_detach(ah_tcp_in_t* in)
{
    if (in == NULL) {
        return AH_EINVAL;
    }
    if (in->_owner_ptr == NULL) {
        return AH_ESTATE;
    }

    ah_err_t err = ah_tcp_in_alloc_for(in->_owner_ptr);
    if (err != AH_ENONE) {
        return err;
    }

    in->_owner_ptr = NULL;

    return AH_ENONE;
}

ah_extern void ah_tcp_in_free(ah_tcp_in_t* in)
{
    if (in != NULL) {
#ifndef NDEBUG
        memset(in, 0, AH_PSIZE);
#endif
        ah_pfree(in);
    }
}

ah_extern ah_err_t ah_tcp_in_repackage(ah_tcp_in_t* in)
{
    if (in == NULL) {
        return AH_EINVAL;
    }

    uint8_t* r_off = in->rw.r;
    size_t r_size = ah_rw_get_readable_size(&in->rw);

    ah_tcp_in_reset(in);

    if (in->rw.r == r_off) {
        if (ah_unlikely(in->rw.w == in->rw.e)) {
            return AH_EOVERFLOW;
        }
        return AH_ENONE;
    }

    memmove(in->rw.r, r_off, r_size);

    in->rw.w = &in->rw.r[r_size];

    return AH_ENONE;
}

ah_extern void ah_tcp_in_reset(ah_tcp_in_t* in)
{
    if (in == NULL) {
        return;
    }

    uint8_t* page = (uint8_t*) in;

    uint8_t* base = &page[sizeof(ah_tcp_in_t)];
    in->rw.r = base;
    in->rw.w = base;
}
