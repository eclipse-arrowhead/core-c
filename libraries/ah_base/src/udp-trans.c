// SPDX-License-Identifier: EPL-2.0

#include "ah/udp.h"

#include "udp-trans-default.h"

ah_extern ah_udp_trans_t ah_udp_trans_get_default(void)
{
    static const ah_udp_trans_vtab_t s_vtab = {
        .sock_init = ah_i_udp_trans_default_sock_init,
        .sock_open = ah_i_udp_trans_default_sock_open,
        .sock_recv_start = ah_i_udp_trans_default_sock_recv_start,
        .sock_recv_stop = ah_i_udp_trans_default_sock_recv_stop,
        .sock_send = ah_i_udp_trans_default_sock_send,
        .sock_close = ah_i_udp_trans_default_sock_close,
        .sock_term = ah_i_udp_trans_default_sock_term,
        .sock_get_family = ah_i_udp_trans_default_sock_get_family,
        .sock_get_laddr = ah_i_udp_trans_default_sock_get_laddr,
        .sock_get_loop = ah_i_udp_trans_default_sock_get_loop,
        .sock_is_closed = ah_i_udp_trans_default_sock_is_closed,
        .sock_is_receiving = ah_i_udp_trans_default_sock_is_receiving,
        .sock_set_multicast_hop_limit = ah_i_udp_trans_default_sock_set_multicast_hop_limit,
        .sock_set_multicast_loopback = ah_i_udp_trans_default_sock_set_multicast_loopback,
        .sock_set_reuseaddr = ah_i_udp_trans_default_sock_set_reuseaddr,
        .sock_set_unicast_hop_limit = ah_i_udp_trans_default_sock_set_unicast_hop_limit,
        .sock_join = ah_i_udp_trans_default_sock_join,
        .sock_leave = ah_i_udp_trans_default_sock_leave,
    };

    return (ah_udp_trans_t) {
        .vtab = &s_vtab,
        .ctx = NULL,
    };
}

ah_extern bool ah_udp_trans_vtab_is_valid(const ah_udp_trans_vtab_t* vtab)
{
    return vtab != NULL
        && vtab->sock_init != NULL
        && vtab->sock_open != NULL
        && vtab->sock_recv_start != NULL
        && vtab->sock_recv_stop != NULL
        && vtab->sock_send != NULL
        && vtab->sock_close != NULL
        && vtab->sock_term != NULL
        && vtab->sock_get_family != NULL
        && vtab->sock_get_laddr != NULL
        && vtab->sock_get_loop != NULL
        && vtab->sock_is_closed != NULL
        && vtab->sock_is_receiving != NULL
        && vtab->sock_set_multicast_hop_limit != NULL
        && vtab->sock_set_multicast_loopback != NULL
        && vtab->sock_set_reuseaddr != NULL
        && vtab->sock_set_unicast_hop_limit != NULL
        && vtab->sock_join != NULL
        && vtab->sock_leave != NULL;
}
