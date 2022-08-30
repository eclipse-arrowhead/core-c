// SPDX-License-Identifier: EPL-2.0

#include "ah/udp.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"

ah_err_t ah_i_udp_sock_open(void* ctx, ah_udp_sock_t* sock, const ah_sockaddr_t* laddr);
ah_err_t ah_i_udp_sock_recv_start(void* ctx, ah_udp_sock_t* sock);
ah_err_t ah_i_udp_sock_recv_stop(void* ctx, ah_udp_sock_t* sock);
ah_err_t ah_i_udp_sock_send(void* ctx, ah_udp_sock_t* sock, ah_udp_out_t* out);
ah_err_t ah_i_udp_sock_close(void* ctx, ah_udp_sock_t* sock);

ah_extern ah_udp_trans_t ah_udp_trans_get_default(void)
{
    static const ah_udp_trans_vtab_t s_vtab = {
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

ah_extern bool ah_udp_trans_vtab_is_valid(const ah_udp_trans_vtab_t* vtab)
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
    if (sock == NULL || loop == NULL || !ah_udp_trans_vtab_is_valid(trans.vtab) || cbs == NULL) {
        return AH_EINVAL;
    }
    if (cbs->on_open == NULL || cbs->on_recv == NULL || cbs->on_send == NULL || cbs->on_close == NULL) {
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

    ah_assert_if_debug(sock->_trans.vtab != NULL && sock->_trans.vtab->sock_open != NULL);

    return sock->_trans.vtab->sock_open(sock->_trans.ctx, sock, laddr);
}

ah_extern ah_err_t ah_udp_sock_recv_start(ah_udp_sock_t* sock)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }

    ah_assert_if_debug(sock->_trans.vtab != NULL && sock->_trans.vtab->sock_recv_start != NULL);

    return sock->_trans.vtab->sock_recv_start(sock->_trans.ctx, sock);
}

ah_extern ah_err_t ah_udp_sock_recv_stop(ah_udp_sock_t* sock)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }

    ah_assert_if_debug(sock->_trans.vtab != NULL && sock->_trans.vtab->sock_recv_stop != NULL);

    return sock->_trans.vtab->sock_recv_stop(sock->_trans.ctx, sock);
}

ah_extern ah_err_t ah_udp_sock_send(ah_udp_sock_t* sock, ah_udp_out_t* out)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }

    ah_assert_if_debug(sock->_trans.vtab != NULL && sock->_trans.vtab->sock_send != NULL);

    return sock->_trans.vtab->sock_send(sock->_trans.ctx, sock, out);
}

ah_extern ah_err_t ah_udp_sock_close(ah_udp_sock_t* sock)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }

    ah_assert_if_debug(sock->_trans.vtab != NULL && sock->_trans.vtab->sock_close != NULL);

    return sock->_trans.vtab->sock_close(sock->_trans.ctx, sock);
}

ah_extern int ah_udp_sock_get_family(const ah_udp_sock_t* sock)
{
    if (sock == NULL) {
        return -1;
    }

    return sock->_is_ipv6 ? AH_SOCKFAMILY_IPV6 : AH_SOCKFAMILY_IPV4;
}

ah_extern ah_loop_t* ah_udp_sock_get_loop(const ah_udp_sock_t* sock)
{
    if (sock == NULL) {
        return NULL;
    }
    return sock->_loop;
}

ah_extern void* ah_udp_sock_get_user_data(const ah_udp_sock_t* sock)
{
    if (sock == NULL) {
        return NULL;
    }
    return sock->_user_data;
}

ah_extern bool ah_udp_sock_is_closed(const ah_udp_sock_t* sock)
{
    return sock == NULL || sock->_state == AH_I_UDP_SOCK_STATE_CLOSED;
}

ah_extern bool ah_udp_sock_is_receiving(const ah_udp_sock_t* sock)
{
    return sock != NULL && sock->_state == AH_I_UDP_SOCK_STATE_RECEIVING;
}

ah_extern void ah_udp_sock_set_user_data(ah_udp_sock_t* sock, void* user_data)
{
    if (sock != NULL) {
        sock->_user_data = user_data;
    }
}

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

ah_extern ah_udp_out_t* ah_udp_out_alloc(void)
{
    uint8_t* page = ah_palloc();
    if (page == NULL) {
        return NULL;
    }

    ah_udp_out_t* out = (void*) page;

    *out = (ah_udp_out_t) {
        .buf = ah_buf_from(&page[sizeof(ah_udp_out_t)], AH_UDP_OUT_BUF_SIZE),
    };

    if (out->buf.size > AH_PSIZE) {
        ah_pfree(page);
        return NULL;
    }

    return out;
}

ah_extern void ah_udp_out_free(ah_udp_out_t* out)
{
    if (out != NULL) {
        ah_pfree(out);
    }
}

