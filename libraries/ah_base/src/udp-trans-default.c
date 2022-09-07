// SPDX-License-Identifier: EPL-2.0

#include "udp-trans-default.h"

#include "ah/err.h"
#include "ah/intrin.h"
#include "ah/udp.h"

ah_err_t ah_i_udp_trans_default_sock_init(void* ctx, ah_udp_sock_t* sock, ah_loop_t* loop, ah_udp_trans_t trans, ah_udp_sock_obs_t obs)
{
    (void) ctx;

    if (ah_unlikely(sock == NULL || loop == NULL || !ah_udp_trans_vtab_is_valid(trans.vtab) || !ah_udp_sock_cbs_is_valid(obs.cbs))) {
        return AH_EINVAL;
    }

    sock->_loop = loop;
    sock->_trans = trans;
    sock->_obs = obs;
    sock->_state = AH_I_UDP_SOCK_STATE_INITIALIZED;

    return AH_ENONE;
}

ah_err_t ah_i_udp_trans_default_sock_term(void* ctx, ah_udp_sock_t* sock)
{
    (void) ctx;

    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state != AH_I_UDP_SOCK_STATE_CLOSED) {
        return AH_ESTATE;
    }
    sock->_state = AH_I_UDP_SOCK_STATE_TERMINATED;

    return AH_ENONE;
}

int ah_i_udp_trans_default_sock_get_family(void* ctx, const ah_udp_sock_t* sock)
{
    (void) ctx;

    if (sock == NULL) {
        return -1;
    }
    return sock->_sock_family;
}

ah_loop_t* ah_i_udp_trans_default_sock_get_loop(void* ctx, const ah_udp_sock_t* sock)
{
    (void) ctx;

    if (sock == NULL) {
        return NULL;
    }
    return sock->_loop;
}

bool ah_i_udp_trans_default_sock_is_closed(void* ctx, const ah_udp_sock_t* sock)
{
    (void) ctx;

    return sock == NULL || sock->_state == AH_I_UDP_SOCK_STATE_CLOSED;
}

bool ah_i_udp_trans_default_sock_is_receiving(void* ctx, const ah_udp_sock_t* sock)
{
    (void) ctx;

    return sock != NULL && sock->_state == AH_I_UDP_SOCK_STATE_RECEIVING;
}
