// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/udp.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"

ah_err_t ah_i_udp_sock_open(void* ctx, ah_udp_sock_t* sock, const ah_sockaddr_t* laddr);
ah_err_t ah_i_udp_sock_recv_start(void* ctx, ah_udp_sock_t* sock);
ah_err_t ah_i_udp_sock_recv_stop(void* ctx, ah_udp_sock_t* sock);
ah_err_t ah_i_udp_sock_send(void* ctx, ah_udp_sock_t* sock, ah_udp_msg_t* msg);
ah_err_t ah_i_udp_sock_close(void* ctx, ah_udp_sock_t* sock);

ah_extern ah_udp_trans_t ah_udp_trans_get_default(void)
{
    static const ah_udp_vtab_t s_vtab = {
        .sock_open = ah_i_udp_sock_open,
        .sock_recv_start = ah_i_udp_sock_recv_start,
        .sock_recv_stop = ah_i_udp_sock_recv_stop,
        .sock_send = ah_i_udp_sock_send,
        .sock_close = ah_i_udp_sock_close,
    };

    return (ah_udp_trans_t) {
        .vtab = &s_vtab,
        .ctx = NULL,
    };
}

ah_extern bool ah_udp_vtab_is_valid(const ah_udp_vtab_t* vtab)
{
    if (vtab == NULL) {
        return false;
    }
    if (vtab->sock_open == NULL) {
        return false;
    }
    if (vtab->sock_recv_start == NULL || vtab->sock_recv_stop == NULL || vtab->sock_send == NULL) {
        return false;
    }
    if (vtab->sock_close == NULL) {
        return false;
    }
    return true;
}

ah_extern ah_err_t ah_udp_sock_init(ah_udp_sock_t* sock, ah_loop_t* loop, ah_udp_trans_t trans, const ah_udp_sock_cbs_t* cbs)
{
    if (sock == NULL || loop == NULL || cbs == NULL) {
        return AH_EINVAL;
    }
    if (cbs->on_open == NULL || cbs->on_close == NULL) {
        return AH_EINVAL;
    }

    *sock = (ah_udp_sock_t) {
        ._loop = loop,
        ._trans = trans,
        ._cbs = cbs,
    };

    return AH_ENONE;
}

ah_extern ah_err_t ah_udp_sock_open(ah_udp_sock_t* sock, const ah_sockaddr_t* laddr)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (sock->_trans.vtab == NULL || sock->_trans.vtab->sock_open == NULL) {
        return AH_ESTATE;
    }
    return sock->_trans.vtab->sock_open(sock->_trans.ctx, sock, laddr);
}

ah_extern ah_err_t ah_udp_sock_recv_start(ah_udp_sock_t* sock)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (sock->_trans.vtab == NULL || sock->_trans.vtab->sock_recv_start == NULL) {
        return AH_ESTATE;
    }
    return sock->_trans.vtab->sock_recv_start(sock->_trans.ctx, sock);
}

ah_extern ah_err_t ah_udp_sock_recv_stop(ah_udp_sock_t* sock)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (sock->_trans.vtab == NULL || sock->_trans.vtab->sock_recv_stop == NULL) {
        return AH_ESTATE;
    }
    return sock->_trans.vtab->sock_recv_stop(sock->_trans.ctx, sock);
}

ah_extern ah_err_t ah_udp_sock_send(ah_udp_sock_t* sock, ah_udp_msg_t* msg)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (sock->_trans.vtab == NULL || sock->_trans.vtab->sock_send == NULL) {
        return AH_ESTATE;
    }
    return sock->_trans.vtab->sock_send(sock->_trans.ctx, sock, msg);
}

ah_extern ah_err_t ah_udp_sock_close(ah_udp_sock_t* sock)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (sock->_trans.vtab == NULL || sock->_trans.vtab->sock_close == NULL) {
        return AH_ESTATE;
    }
    return sock->_trans.vtab->sock_close(sock->_trans.ctx, sock);
}

ah_extern ah_loop_t* ah_udp_sock_get_loop(const ah_udp_sock_t* sock)
{
    ah_assert(sock != NULL);

    return sock->_loop;
}

ah_extern void* ah_udp_sock_get_user_data(const ah_udp_sock_t* sock)
{
    ah_assert(sock != NULL);

    return sock->_user_data;
}

ah_extern bool ah_udp_sock_is_closed(const ah_udp_sock_t* sock)
{
    ah_assert(sock != NULL);

    return sock->_state == AH_I_UDP_SOCK_STATE_CLOSED;
}

ah_extern bool ah_udp_sock_is_receiving(const ah_udp_sock_t* sock)
{
    ah_assert(sock != NULL);

    return sock->_state == AH_I_UDP_SOCK_STATE_RECEIVING;
}

ah_extern void ah_udp_sock_set_user_data(ah_udp_sock_t* sock, void* user_data)
{
    ah_assert(sock != NULL);

    sock->_user_data = user_data;
}
