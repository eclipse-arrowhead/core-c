// SPDX-License-Identifier: EPL-2.0

#include "ah/udp.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"

ah_extern ah_err_t ah_udp_sock_init(ah_udp_sock_t* sock, ah_loop_t* loop, ah_udp_trans_t trans, ah_udp_sock_obs_t obs)
{
    if (ah_unlikely(sock == NULL || trans.vtab == NULL || trans.vtab->sock_init == NULL)) {
        return AH_EINVAL;
    }

    (void) memset(sock, 0, sizeof(*sock));

    return trans.vtab->sock_init(trans.ctx, sock, loop, trans, obs);
}

ah_extern ah_err_t ah_udp_sock_open(ah_udp_sock_t* sock, const ah_sockaddr_t* laddr)
{
    if (ah_unlikely(sock == NULL || sock->_trans.vtab == NULL || sock->_trans.vtab->sock_open == NULL)) {
        return AH_EINVAL;
    }
    return sock->_trans.vtab->sock_open(sock->_trans.ctx, sock, laddr);
}

ah_extern ah_err_t ah_udp_sock_recv_start(ah_udp_sock_t* sock)
{
    if (ah_unlikely(sock == NULL || sock->_trans.vtab == NULL || sock->_trans.vtab->sock_recv_start == NULL)) {
        return AH_EINVAL;
    }
    return sock->_trans.vtab->sock_recv_start(sock->_trans.ctx, sock);
}

ah_extern ah_err_t ah_udp_sock_recv_stop(ah_udp_sock_t* sock)
{
    if (ah_unlikely(sock == NULL || sock->_trans.vtab == NULL || sock->_trans.vtab->sock_recv_stop == NULL)) {
        return AH_EINVAL;
    }
    return sock->_trans.vtab->sock_recv_stop(sock->_trans.ctx, sock);
}

ah_extern ah_err_t ah_udp_sock_send(ah_udp_sock_t* sock, ah_udp_out_t* out)
{
    if (ah_unlikely(sock == NULL || sock->_trans.vtab == NULL || sock->_trans.vtab->sock_send == NULL)) {
        return AH_EINVAL;
    }
    return sock->_trans.vtab->sock_send(sock->_trans.ctx, sock, out);
}

ah_extern ah_err_t ah_udp_sock_close(ah_udp_sock_t* sock)
{
    if (ah_unlikely(sock == NULL || sock->_trans.vtab == NULL || sock->_trans.vtab->sock_close == NULL)) {
        return AH_EINVAL;
    }
    return sock->_trans.vtab->sock_close(sock->_trans.ctx, sock);
}

ah_extern ah_err_t ah_udp_sock_term(ah_udp_sock_t* sock)
{
    if (ah_unlikely(sock == NULL || sock->_trans.vtab == NULL || sock->_trans.vtab->sock_term == NULL)) {
        return AH_EINVAL;
    }
    return sock->_trans.vtab->sock_term(sock->_trans.ctx, sock);
}

ah_extern int ah_udp_sock_get_family(const ah_udp_sock_t* sock)
{
    if (ah_unlikely(sock == NULL || sock->_trans.vtab == NULL || sock->_trans.vtab->sock_get_family == NULL)) {
        return -1;
    }
    return sock->_trans.vtab->sock_get_family(sock->_trans.ctx, sock);
}

ah_extern ah_err_t ah_udp_sock_get_laddr(const ah_udp_sock_t* sock, ah_sockaddr_t* laddr)
{
    if (ah_unlikely(sock == NULL || sock->_trans.vtab == NULL || sock->_trans.vtab->sock_get_laddr == NULL)) {
        return AH_EINVAL;
    }
    return sock->_trans.vtab->sock_get_laddr(sock->_trans.ctx, sock, laddr);
}

ah_extern ah_loop_t* ah_udp_sock_get_loop(const ah_udp_sock_t* sock)
{
    if (ah_unlikely(sock == NULL || sock->_trans.vtab == NULL || sock->_trans.vtab->sock_get_loop == NULL)) {
        return NULL;
    }
    return sock->_trans.vtab->sock_get_loop(sock->_trans.ctx, sock);
}

ah_extern bool ah_udp_sock_is_closed(const ah_udp_sock_t* sock)
{
    if (ah_unlikely(sock == NULL || sock->_trans.vtab == NULL || sock->_trans.vtab->sock_is_closed == NULL)) {
        return true;
    }
    return sock->_trans.vtab->sock_is_closed(sock->_trans.ctx, sock);
}

ah_extern bool ah_udp_sock_is_receiving(const ah_udp_sock_t* sock)
{
    if (ah_unlikely(sock == NULL || sock->_trans.vtab == NULL || sock->_trans.vtab->sock_is_receiving == NULL)) {
        return false;
    }
    return sock->_trans.vtab->sock_is_receiving(sock->_trans.ctx, sock);
}

ah_extern ah_err_t ah_udp_sock_set_multicast_hop_limit(ah_udp_sock_t* sock, uint8_t hop_limit)
{
    if (ah_unlikely(sock == NULL || sock->_trans.vtab == NULL || sock->_trans.vtab->sock_set_multicast_hop_limit == NULL)) {
        return AH_EINVAL;
    }
    return sock->_trans.vtab->sock_set_multicast_hop_limit(sock->_trans.ctx, sock, hop_limit);
}

ah_extern ah_err_t ah_udp_sock_set_multicast_loopback(ah_udp_sock_t* sock, bool is_enabled)
{
    if (ah_unlikely(sock == NULL || sock->_trans.vtab == NULL || sock->_trans.vtab->sock_set_multicast_loopback == NULL)) {
        return AH_EINVAL;
    }
    return sock->_trans.vtab->sock_set_multicast_loopback(sock->_trans.ctx, sock, is_enabled);
}

ah_extern ah_err_t ah_udp_sock_set_reuseaddr(ah_udp_sock_t* sock, bool is_enabled)
{
    if (ah_unlikely(sock == NULL || sock->_trans.vtab == NULL || sock->_trans.vtab->sock_set_reuseaddr == NULL)) {
        return AH_EINVAL;
    }
    return sock->_trans.vtab->sock_set_reuseaddr(sock->_trans.ctx, sock, is_enabled);
}

ah_extern ah_err_t ah_udp_sock_set_unicast_hop_limit(ah_udp_sock_t* sock, uint8_t hop_limit)
{
    if (ah_unlikely(sock == NULL || sock->_trans.vtab == NULL || sock->_trans.vtab->sock_set_unicast_hop_limit == NULL)) {
        return AH_EINVAL;
    }
    return sock->_trans.vtab->sock_set_unicast_hop_limit(sock->_trans.ctx, sock, hop_limit);
}

ah_extern ah_err_t ah_udp_sock_join(ah_udp_sock_t* sock, const ah_udp_group_t* group)
{
    if (ah_unlikely(sock == NULL || sock->_trans.vtab == NULL || sock->_trans.vtab->sock_join == NULL)) {
        return AH_EINVAL;
    }
    return sock->_trans.vtab->sock_join(sock->_trans.ctx, sock, group);
}

ah_extern ah_err_t ah_udp_sock_leave(ah_udp_sock_t* sock, const ah_udp_group_t* group)
{
    if (ah_unlikely(sock == NULL || sock->_trans.vtab == NULL || sock->_trans.vtab->sock_leave == NULL)) {
        return AH_EINVAL;
    }
    return sock->_trans.vtab->sock_leave(sock->_trans.ctx, sock, group);
}

ah_extern bool ah_udp_sock_cbs_is_valid(const ah_udp_sock_cbs_t* cbs)
{
    return cbs != NULL
        && cbs->on_open != NULL
        && cbs->on_recv != NULL
        && cbs->on_send != NULL
        && cbs->on_close != NULL;
}
