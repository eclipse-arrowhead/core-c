// SPDX-License-Identifier: EPL-2.0

#include "ah/tcp.h"

ah_extern ah_tcp_out_t* ah_tcp_out_alloc(void)
{
    uint8_t* page = ah_palloc();
    if (page == NULL) {
        return NULL;
    }

    ah_tcp_out_t* out = (void*) page;

    *out = (ah_tcp_out_t) {
        .buf = ah_buf_from(&page[sizeof(ah_tcp_out_t)], AH_TCP_OUT_BUF_SIZE),
    };

    if (out->buf.size > AH_PSIZE) {
        ah_pfree(page);
        return NULL;
    }

    return out;
}

ah_extern void ah_tcp_out_free(ah_tcp_out_t* out)
{
    if (out != NULL) {
        ah_pfree(out);
    }
}
