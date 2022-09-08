// SPDX-License-Identifier: EPL-2.0

#include "ah/mbedtls.h"

#include "ah/internal/collections/slab.h"
#include "mbedtls-client.h"
#include "mbedtls-utils.h"

#include <ah/assert.h>
#include <ah/err.h>
#include <mbedtls/error.h>
#include <mbedtls/ssl.h>

static void s_listener_on_open(void* srv_, ah_tcp_listener_t* ln, ah_err_t err);
static void s_listener_on_listen(void* srv_, ah_tcp_listener_t* ln, ah_err_t err);
static void s_listener_on_accept(void* srv_, ah_tcp_listener_t* ln, ah_tcp_accept_t* accept, ah_err_t err);
static void s_listener_on_close(void* srv_, ah_tcp_listener_t* ln, ah_err_t err);

static const ah_tcp_listener_cbs_t s_listener_cbs = {
    .on_open = s_listener_on_open,
    .on_listen = s_listener_on_listen,
    .on_accept = s_listener_on_accept,
    .on_close = s_listener_on_close,
};

ah_extern ah_err_t ah_mbedtls_server_init(ah_mbedtls_server_t* srv, ah_tcp_trans_t trans, mbedtls_ssl_config* ssl_conf, ah_mbedtls_on_handshake_done_cb on_handshake_done_cb)
{
    if (srv == NULL || !ah_tcp_trans_vtab_is_valid(trans.vtab) || ssl_conf == NULL || on_handshake_done_cb == NULL) {
        return AH_EINVAL;
    }

    *srv = (ah_mbedtls_server_t) {
        ._trans = trans,
        ._on_handshake_done_cb = on_handshake_done_cb,
        ._ssl_conf = ssl_conf,
    };

    return ah_i_slab_init(&srv->_client_slab, 1u, sizeof(ah_mbedtls_client_t));
}

ah_extern ah_tcp_trans_t ah_mbedtls_server_as_tcp_trans(ah_mbedtls_server_t* srv)
{
    return (ah_tcp_trans_t) {
        .vtab = &ah_i_mbedtls_tcp_vtab,
        .ctx = srv,
    };
}

ah_extern void ah_mbedtls_server_term(ah_mbedtls_server_t* srv)
{
    if (srv == NULL) {
        return;
    }
    ah_i_slab_term(&srv->_client_slab, NULL);
}

void ah_i_tls_server_free_accepted_client(ah_mbedtls_server_t* srv, ah_mbedtls_client_t* client)
{
    ah_assert_if_debug(srv != NULL);
    ah_assert_if_debug(client != NULL);

    ah_i_slab_free(&srv->_client_slab, client);
}

ah_err_t ah_i_mbedtls_listener_init(void* srv_, ah_tcp_listener_t* ln, ah_loop_t* loop, ah_tcp_trans_t trans, ah_tcp_listener_obs_t obs)
{
    ah_mbedtls_server_t* srv = srv_;
    if (srv == NULL || srv->_trans.vtab == NULL || srv->_trans.vtab->listener_init == NULL || !ah_tcp_listener_cbs_is_valid(obs.cbs)) {
        return AH_EINVAL;
    }

    srv->_ln_obs = obs;

    return srv->_trans.vtab->listener_init(srv->_trans.ctx, ln, loop, trans, (ah_tcp_listener_obs_t) { &s_listener_cbs, srv });
}

ah_err_t ah_i_mbedtls_listener_open(void* srv_, ah_tcp_listener_t* ln, const ah_sockaddr_t* laddr)
{
    ah_mbedtls_server_t* srv = srv_;
    if (srv == NULL || ln == NULL || srv->_trans.vtab == NULL || srv->_trans.vtab->listener_open == NULL) {
        return AH_EINVAL;
    }
    return srv->_trans.vtab->listener_open(srv->_trans.ctx, ln, laddr);
}

static void s_listener_on_open(void* srv_, ah_tcp_listener_t* ln, ah_err_t err)
{
    ah_mbedtls_server_t* srv = srv_;
    ah_assert_if_debug(srv != NULL && srv->_ln_obs.cbs != NULL && srv->_ln_obs.cbs->on_open != NULL);
    srv->_ln_obs.cbs->on_open(srv->_ln_obs.ctx, ln, err);
}

ah_err_t ah_i_mbedtls_listener_listen(void* srv_, ah_tcp_listener_t* ln, unsigned backlog)
{
    ah_mbedtls_server_t* srv = srv_;
    if (srv == NULL || srv->_trans.vtab == NULL || srv->_trans.vtab->listener_listen == NULL) {
        return AH_EINVAL;
    }
    return srv->_trans.vtab->listener_listen(srv->_trans.ctx, ln, backlog);
}

static void s_listener_on_listen(void* srv_, ah_tcp_listener_t* ln, ah_err_t err)
{
    ah_mbedtls_server_t* srv = srv_;
    ah_assert_if_debug(srv != NULL && srv->_ln_obs.cbs != NULL && srv->_ln_obs.cbs->on_listen != NULL);
    srv->_ln_obs.cbs->on_listen(srv->_ln_obs.ctx, ln, err);
}

static void s_listener_on_accept(void* srv_, ah_tcp_listener_t* ln, ah_tcp_accept_t* accept, ah_err_t err)
{
    ah_mbedtls_server_t* srv = srv_;
    ah_assert_if_debug(srv != NULL && srv->_ln_obs.cbs != NULL && srv->_ln_obs.cbs->on_accept != NULL);

    ah_tcp_accept_t accept0;

    if (accept != NULL) {
        ah_mbedtls_client_t* cln = accept->ctx;
        cln->_conn = accept->conn;

        ah_tcp_conn_obs_t* obs = accept->obs;
        obs->cbs = &ah_i_mbedtls_tcp_conn_cbs;
        obs->ctx = cln;

        accept0 = (ah_tcp_accept_t) {
            .ctx = cln->_trans.ctx,
            .conn = accept->conn,
            .obs = &cln->_conn_obs,
            .raddr = accept->raddr,
        };
        accept = &accept0;
    }

    srv->_ln_obs.cbs->on_accept(srv->_ln_obs.ctx, ln, accept, err);
}

ah_err_t ah_i_mbedtls_listener_close(void* srv_, ah_tcp_listener_t* ln)
{
    ah_mbedtls_server_t* srv = srv_;
    if (srv == NULL || srv->_trans.vtab == NULL || srv->_trans.vtab->listener_close == NULL) {
        return AH_EINVAL;
    }
    return srv->_trans.vtab->listener_close(srv->_trans.ctx, ln);
}

static void s_listener_on_close(void* srv_, ah_tcp_listener_t* ln, ah_err_t err)
{
    ah_mbedtls_server_t* srv = srv_;
    ah_assert_if_debug(srv != NULL && srv->_ln_obs.cbs != NULL && srv->_ln_obs.cbs->on_close != NULL);
    srv->_ln_obs.cbs->on_close(srv->_ln_obs.ctx, ln, err);
}

ah_err_t ah_i_mbedtls_listener_term(void* srv_, ah_tcp_listener_t* ln)
{
    ah_mbedtls_server_t* srv = srv_;
    if (srv == NULL || srv->_trans.vtab == NULL || srv->_trans.vtab->listener_close == NULL) {
        return AH_EINVAL;
    }
    return srv->_trans.vtab->listener_term(srv->_trans.ctx, ln);
}

int ah_i_mbedtls_listener_get_family(void* srv_, const ah_tcp_listener_t* ln)
{
    ah_mbedtls_server_t* srv = srv_;
    if (srv == NULL || srv->_trans.vtab == NULL || srv->_trans.vtab->listener_get_family == NULL) {
        return -1;
    }
    return srv->_trans.vtab->listener_get_family(srv->_trans.ctx, ln);
}

ah_err_t ah_i_mbedtls_listener_get_laddr(void* srv_, const ah_tcp_listener_t* ln, ah_sockaddr_t* laddr)
{
    ah_mbedtls_server_t* srv = srv_;
    if (srv == NULL || srv->_trans.vtab == NULL || srv->_trans.vtab->listener_get_laddr == NULL) {
        return AH_EINVAL;
    }
    return srv->_trans.vtab->listener_get_laddr(srv->_trans.ctx, ln, laddr);
}

ah_loop_t* ah_i_mbedtls_listener_get_loop(void* srv_, const ah_tcp_listener_t* ln)
{
    ah_mbedtls_server_t* srv = srv_;
    if (srv == NULL || srv->_trans.vtab == NULL || srv->_trans.vtab->listener_get_loop == NULL) {
        return NULL;
    }
    return srv->_trans.vtab->listener_get_loop(srv->_trans.ctx, ln);
}

void* ah_i_mbedtls_listener_get_obs_ctx(void* srv_, const ah_tcp_listener_t* ln)
{
    ah_mbedtls_server_t* srv = srv_;
    if (srv == NULL || srv->_trans.vtab == NULL || srv->_trans.vtab->listener_get_obs_ctx == NULL) {
        return NULL;
    }
    return srv->_trans.vtab->listener_get_obs_ctx(srv->_trans.ctx, ln);
}

bool ah_i_mbedtls_listener_is_closed(void* srv_, ah_tcp_listener_t* ln)
{
    ah_mbedtls_server_t* srv = srv_;
    if (srv == NULL || srv->_trans.vtab == NULL || srv->_trans.vtab->listener_is_closed == NULL) {
        return true;
    }
    return srv->_trans.vtab->listener_is_closed(srv->_trans.ctx, ln);
}

ah_err_t ah_i_mbedtls_listener_set_keepalive(void* srv_, ah_tcp_listener_t* ln, bool is_enabled)
{
    ah_mbedtls_server_t* srv = srv_;
    if (srv == NULL || srv->_trans.vtab == NULL || srv->_trans.vtab->listener_set_keepalive == NULL) {
        return AH_EINVAL;
    }
    return srv->_trans.vtab->listener_set_keepalive(srv->_trans.ctx, ln, is_enabled);
}

ah_err_t ah_i_mbedtls_listener_set_nodelay(void* srv_, ah_tcp_listener_t* ln, bool is_enabled)
{
    ah_mbedtls_server_t* srv = srv_;
    if (srv == NULL || srv->_trans.vtab == NULL || srv->_trans.vtab->listener_set_nodelay == NULL) {
        return AH_EINVAL;
    }
    return srv->_trans.vtab->listener_set_nodelay(srv->_trans.ctx, ln, is_enabled);
}

ah_err_t ah_i_mbedtls_listener_set_reuseaddr(void* srv_, ah_tcp_listener_t* ln, bool is_enabled)
{
    ah_mbedtls_server_t* srv = srv_;
    if (srv == NULL || srv->_trans.vtab == NULL || srv->_trans.vtab->listener_set_reuseaddr == NULL) {
        return AH_EINVAL;
    }
    return srv->_trans.vtab->listener_set_reuseaddr(srv->_trans.ctx, ln, is_enabled);
}

ah_err_t ah_i_mbedtls_listener_prepare(void* srv_, ah_tcp_listener_t* ln, ah_tcp_trans_t* trans)
{
    ah_mbedtls_server_t* srv = srv_;
    if (srv == NULL || srv->_trans.vtab == NULL || srv->_trans.vtab->listener_prepare == NULL
        || ln == NULL || trans == NULL) {
        return AH_EINVAL;
    }

    ah_err_t err;

    ah_mbedtls_client_t* cln = ah_i_slab_alloc(&srv->_client_slab);
    if (cln == NULL) {
        return AH_ENOMEM;
    }

    err = ah_i_mbedtls_client_prepare(cln, srv->_ssl_conf, srv->_on_handshake_done_cb);
    if (err != AH_ENONE) {
        goto free_cln_and_return_err;
    }

    err = srv->_trans.vtab->listener_prepare(srv->_trans.ctx, ln, &cln->_trans);
    if (err != AH_ENONE) {
        goto retract_cln_free_cln_and_return_err;
    }

    cln->_server = srv;

    trans->vtab = &ah_i_mbedtls_tcp_vtab;
    trans->ctx = cln;

    return AH_ENONE;

retract_cln_free_cln_and_return_err:
    ah_i_mbedtls_client_retract(cln);

free_cln_and_return_err:
    ah_i_slab_free(&srv->_client_slab, cln);

    return err;
}
