// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "tcp-in.h"

#include "ah/assert.h"
#include "ah/err.h"

#include <string.h>

ah_err_t ah_i_tcp_in_alloc_for(ah_tcp_in_t** owner_ptr)
{
    ah_assert_if_debug(owner_ptr != NULL);

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

ah_err_t ah_i_tcp_in_detach(ah_tcp_in_t* in)
{
    ah_assert_if_debug(in != NULL);

    ah_err_t err = ah_i_tcp_in_alloc_for(in->_owner_ptr);
    if (err != AH_ENONE) {
        return err;
    }

    in->_owner_ptr = NULL;

    return AH_ENONE;
}

void ah_i_tcp_in_free(ah_tcp_in_t* in)
{
    ah_assert_if_debug(in != NULL);

    ah_pfree(in);
}

void ah_i_tcp_in_repackage(ah_tcp_in_t* in)
{
    ah_assert_if_debug(in != NULL);

    uint8_t* r_off = in->rw.r;
    size_t r_size = ah_rw_get_readable_size(&in->rw);

    ah_i_tcp_in_reset(in);

    memmove(in->rw.r, r_off, r_size);

    in->rw.w = &in->rw.r[r_size];
}

void ah_i_tcp_in_reset(ah_tcp_in_t* in)
{
    ah_assert_if_debug(in != NULL);

    uint8_t* page = (uint8_t*) in;

    uint8_t* base = &page[sizeof(ah_tcp_in_t)];
    in->rw.r = base;
    in->rw.w = base;

    ah_assert_if_debug(in->rw.e == &page[AH_PSIZE]);
}
