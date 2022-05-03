// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/udp.h"

#include "ah/err.h"
#include "ah/loop.h"

ah_extern ah_err_t ah_udp_sock_init(ah_udp_sock_t* sock, ah_loop_t* loop, const ah_udp_sock_vtab_t* vtab)
{
    if (sock == NULL || loop == NULL || vtab == NULL) {
        return AH_EINVAL;
    }
    if (vtab->on_open == NULL || vtab->on_close == NULL) {
        return AH_EINVAL;
    }
    if ((vtab->on_recv_alloc == NULL) != (vtab->on_recv_done == NULL)) {
        return AH_EINVAL;
    }
    if (ah_loop_is_term(loop)) {
        return AH_ESTATE;
    }

    *sock = (ah_udp_sock_t) {
        ._loop = loop,
        ._vtab = vtab,
    };

    return AH_ENONE;
}

ah_extern void ah_udp_trans_init(ah_udp_trans_t* trans, ah_loop_t* loop)
{
    ah_assert_if_debug(loop != NULL);

    static const ah_udp_trans_vtab_t s_vtab = {
        .sock_init = ah_udp_sock_init,
        .sock_open = ah_udp_sock_open,
        .sock_recv_start = ah_udp_sock_recv_start,
        .sock_recv_stop = ah_udp_sock_recv_stop,
        .sock_send = ah_udp_sock_send,
        .sock_close = ah_udp_sock_close,
    };

    *trans = (ah_udp_trans_t) {
        ._vtab = &s_vtab,
        ._loop = loop,
        ._trans_data = NULL,
    };
}
