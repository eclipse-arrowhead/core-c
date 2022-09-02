// SPDX-License-Identifier: EPL-2.0

#include "ah/mbedtls.h"

#include "ah/internal/collections/slab.h"
#include "mbedtls-client.h"
#include "mbedtls-utils.h"

#include <ah/assert.h>
#include <ah/err.h>
#include <mbedtls/error.h>
#include <mbedtls/ssl.h>

static void ah_s_tcp_listener_on_open(void* srv_, ah_tcp_listener_t* ln, ah_err_t err);
static void ah_s_tcp_listener_on_listen(void* srv_, ah_tcp_listener_t* ln, ah_err_t err);
static void ah_s_tcp_listener_on_accept(void* srv_, ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, ah_tcp_conn_obs_t* obs, const ah_sockaddr_t* raddr, ah_err_t err);
static void ah_s_tcp_listener_on_close(void* srv_, ah_tcp_listener_t* ln, ah_err_t err);

static const ah_tcp_listener_cbs_t s_listener_cbs = {
    .on_open = ah_s_tcp_listener_on_open,
    .on_listen = ah_s_tcp_listener_on_listen,
    .on_accept = ah_s_tcp_listener_on_accept,
    .on_close = ah_s_tcp_listener_on_close,
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

ah_extern int ah_mbedtls_server_get_last_err(ah_mbedtls_server_t* srv)
{
    if (srv == NULL) {
        return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
    }
    return srv->_errs._last_mbedtls_err;
}

ah_extern mbedtls_ssl_config* ah_mbedtls_server_get_ssl_config(ah_mbedtls_server_t* srv)
{
    if (srv == NULL) {
        return NULL;
    }
    return srv->_ssl_conf;
}

ah_extern ah_tcp_trans_t ah_mbedtls_server_as_trans(ah_mbedtls_server_t* srv)
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

    if (srv == NULL || ln == NULL || !ah_tcp_listener_cbs_is_valid(obs.cbs) || srv->_trans.vtab == NULL || srv->_trans.vtab->listener_init == NULL) {
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

static void ah_s_tcp_listener_on_open(void* srv_, ah_tcp_listener_t* ln, ah_err_t err)
{
    ah_mbedtls_server_t* srv = srv_;

    ah_assert_if_debug(srv != NULL && srv->_ln_obs.cbs != NULL && srv->_ln_obs.cbs->on_open != NULL);

    srv->_ln_obs.cbs->on_open(srv->_ln_obs.ctx, ln, err);
}

ah_err_t ah_i_mbedtls_listener_listen(void* srv_, ah_tcp_listener_t* ln, unsigned backlog)
{
    ah_mbedtls_server_t* srv = srv_;

    if (srv == NULL || ln == NULL || srv->_trans.vtab == NULL || srv->_trans.vtab->listener_listen == NULL) {
        return AH_EINVAL;
    }

    return srv->_trans.vtab->listener_listen(srv->_trans.ctx, ln, backlog);
}

static void ah_s_tcp_listener_on_listen(void* srv_, ah_tcp_listener_t* ln, ah_err_t err)
{
    ah_mbedtls_server_t* srv = srv_;

    ah_assert_if_debug(srv != NULL && srv->_ln_obs.cbs != NULL && srv->_ln_obs.cbs->on_listen != NULL);

    srv->_ln_obs.cbs->on_listen(srv->_ln_obs.ctx, ln, err);
}

ah_err_t ah_i_mbedtls_listener_close(void* srv_, ah_tcp_listener_t* ln)
{
    ah_mbedtls_server_t* srv = srv_;

    if (srv == NULL || srv->_trans.vtab == NULL || srv->_trans.vtab->listener_close == NULL) {
        return AH_EINVAL;
    }

    return srv->_trans.vtab->listener_close(srv->_trans.ctx, ln);
}

static void ah_s_tcp_listener_on_accept(void* srv_, ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, ah_tcp_conn_obs_t* obs, const ah_sockaddr_t* raddr, ah_err_t err)
{
    ah_mbedtls_server_t* srv = srv_;

    ah_assert_if_debug(srv != NULL && srv->_ln_obs.cbs != NULL && srv->_ln_obs.cbs->on_accept != NULL);

    if (err != AH_ENONE) {
        goto handle_err;
    }

    obs->cbs = &ah_i_mbedtls_tcp_conn_cbs;
    obs->ctx = cln;

    srv->_ln_obs.cbs->on_accept(srv->_ln_obs.ctx, ln, conn, &cln->_conn_obs, raddr, AH_ENONE);

    return;

handle_err:
    srv->_ln_obs.cbs->on_accept(srv->_ln_obs.ctx, ln, NULL, NULL, NULL, err);
}

static void ah_s_tcp_listener_on_close(void* srv_, ah_tcp_listener_t* ln, ah_err_t err)
{
    ah_mbedtls_server_t* srv = srv_;

    ah_assert_if_debug(srv != NULL && srv->_ln_obs.cbs != NULL && srv->_ln_obs.cbs->on_close != NULL);

    srv->_ln_obs.cbs->on_close(srv->_ln_obs.ctx, ln, err);
}

int ah_i_mbedtls_listener_get_family(void* srv_, const ah_tcp_listener_t* ln)
{
    ah_mbedtls_server_t* srv = srv_;

    if (srv == NULL || srv->_trans.vtab == NULL || srv->_trans.vtab->listener_get_family == NULL) {
        return -1;
    }
    srv->_trans.vtab->listener_get_family(srv->_trans.ctx, ln);
}

ah_err_t ah_i_mbedtls_listener_get_laddr(void* srv_, const ah_tcp_listener_t* ln, ah_sockaddr_t* laddr)
{
    ah_mbedtls_server_t* srv = srv_;
    ah_assert_if_debug(srv != NULL);

    srv->_trans.vtab->listener_get_laddr(srv->_trans.ctx, ln, laddr);
}

ah_loop_t* ah_i_mbedtls_listener_get_loop(void* srv_, const ah_tcp_listener_t* ln)
{
    ah_mbedtls_server_t* srv = srv_;
    ah_assert_if_debug(srv != NULL);

    srv->_trans.vtab->listener_get_loop(srv->_trans.ctx, ln);
}

void* ah_i_mbedtls_listener_get_obs_ctx(void* srv_, const ah_tcp_listener_t* ln)
{
    ah_mbedtls_server_t* srv = srv_;
    ah_assert_if_debug(srv != NULL);

    srv->_trans.vtab->listener_get_obs_ctx(srv->_trans.ctx, ln);
}

bool ah_i_mbedtls_listener_is_closed(void* srv_, ah_tcp_listener_t* ln)
{
    ah_mbedtls_server_t* srv = srv_;
    ah_assert_if_debug(srv != NULL);

    srv->_trans.vtab->listener_is_closed(srv->_trans.ctx, ln);
}

ah_err_t ah_i_mbedtls_listener_set_keepalive(void* srv_, ah_tcp_listener_t* ln, bool is_enabled)
{
    ah_mbedtls_server_t* srv = srv_;
    ah_assert_if_debug(srv != NULL);

    srv->_trans.vtab->listener_set_keepalive(srv->_trans.ctx, ln, is_enabled);
}

ah_err_t ah_i_mbedtls_listener_set_nodelay(void* srv_, ah_tcp_listener_t* ln, bool is_enabled)
{
    ah_mbedtls_server_t* srv = srv_;
    ah_assert_if_debug(srv != NULL);

    srv->_trans.vtab->listener_set_nodelay(srv->_trans.ctx, ln, is_enabled);
}

ah_err_t ah_i_mbedtls_listener_set_reuseaddr(void* srv_, ah_tcp_listener_t* ln, bool is_enabled)
{
    ah_mbedtls_server_t* srv = srv_;
    ah_assert_if_debug(srv != NULL);

    srv->_trans.vtab->listener_set_reuseaddr(srv->_trans.ctx, ln, is_enabled);
}

ah_err_t ah_s_tcp_trans_prepare(void* srv_, ah_tcp_trans_t* trans)
{
    ah_mbedtls_server_t* srv = srv_;

    if (srv == NULL || trans == NULL) {
        return AH_EINVAL;
    }

    ah_err_t err;

    ah_mbedtls_client_t* cln = ah_i_slab_alloc(&srv->_client_slab);
    if (cln == NULL) {
        return AH_ENOMEM;
    }

    ah_tcp_trans_t subtrans;
    err = srv->_trans.vtab->trans_prepare(srv->_trans.ctx, &subtrans);
    if (err != AH_ENONE) {
        ah_i_slab_free(&srv->_client_slab, cln);
        return err;
    }

    err = ah_i_mbedtls_client_init(cln, subtrans, srv->_ssl_conf, srv->_on_handshake_done_cb);
    if (err != AH_ENONE) {
        srv->_trans.vtab->trans_retract(srv->_trans.ctx, subtrans);
        ah_i_slab_free(&srv->_client_slab, cln);
        return err;
    }

    mbedtls_ssl_set_bio(&cln->_ssl, cln, ah_i_mbedtls_client_write_ciphertext, ah_i_mbedtls_client_read_ciphertext, NULL);

    cln->_server = srv;

    trans->vtab = &ah_i_mbedtls_tcp_vtab;
    trans->ctx = cln;

    return AH_ENONE;
}

void ah_i_tcp_trans_retract(void* srv_, ah_tcp_trans_t trans)
{
    ah_mbedtls_server_t* srv = srv_;

    ah_assert_if_debug(srv != NULL);

    if (trans.ctx == NULL) {
        return;
    }

    ah_mbedtls_client_t* cln = trans.ctx;
    ah_mbedtls_client_term(cln);
    ah_i_slab_free(&srv->_client_slab, cln);
}
