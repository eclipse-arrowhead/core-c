// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include "http-client.h"
#include "http-utils.h"

#include <ah/assert.h>
#include <ah/err.h>

static void s_listener_on_open(void* srv_, ah_tcp_listener_t* ln, ah_err_t err);
static void s_listener_on_listen(void* srv_, ah_tcp_listener_t* ln, ah_err_t err);
static void s_listener_on_accept(void* srv_, ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, ah_tcp_conn_obs_t* obs, const ah_sockaddr_t* raddr, ah_err_t err);
static void s_listener_on_close(void* srv_, ah_tcp_listener_t* ln, ah_err_t err);

ah_extern ah_err_t ah_http_server_init(ah_http_server_t* srv, ah_loop_t* loop, ah_tcp_trans_t trans, ah_http_server_obs_t obs)
{
    if (srv == NULL || !ah_http_server_cbs_is_valid(obs.cbs)) {
        return AH_EINVAL;
    }

    static const ah_tcp_listener_cbs_t s_cbs = {
        .on_open = s_listener_on_open,
        .on_listen = s_listener_on_listen,
        .on_accept = s_listener_on_accept,
        .on_close = s_listener_on_close,
    };

    *srv = (ah_http_server_t) {
        ._obs = obs,
    };
    
    ah_err_t err;

    err = ah_i_slab_init(&srv->_client_slab, 1u, sizeof(ah_http_client_t));
    if (err != AH_ENONE) {
        return err;
    }

    err = ah_tcp_listener_init(&srv->_ln, loop, trans, (ah_tcp_listener_obs_t) { &s_cbs, srv });
    if (err != AH_ENONE) {
        ah_i_slab_term(&srv->_client_slab, NULL);
        return err;
    }
    
    return AH_ENONE;
}

ah_extern ah_err_t ah_http_server_open(ah_http_server_t* srv, const ah_sockaddr_t* laddr)
{
    if (srv == NULL) {
        return AH_EINVAL;
    }
    return ah_tcp_listener_open(&srv->_ln, laddr);
}

static void s_listener_on_open(void* srv_, ah_tcp_listener_t* ln, ah_err_t err)
{
    ah_http_server_t* srv = ah_i_http_ctx_to_server(srv_);
    (void) ln;
    srv->_obs.cbs->on_open(srv->_obs.ctx, srv, err);
}

ah_extern ah_err_t ah_http_server_listen(ah_http_server_t* srv, unsigned backlog)
{
    if (srv == NULL) {
        return AH_EINVAL;
    }
    return ah_tcp_listener_listen(&srv->_ln, backlog);
}

static void s_listener_on_listen(void* srv_, ah_tcp_listener_t* ln, ah_err_t err)
{
    ah_http_server_t* srv = ah_i_http_ctx_to_server(srv_);
    (void) ln;
    srv->_obs.cbs->on_listen(srv->_obs.ctx, srv, err);
}

static void s_listener_on_accept(void* srv_, ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, ah_tcp_conn_obs_t* obs, const ah_sockaddr_t* raddr, ah_err_t err)
{
    ah_http_server_t* srv = ah_i_http_ctx_to_server(srv_);
    (void) ln;

    if (err != AH_ENONE) {
        goto handle_err;
    }

    ah_http_client_t* cln = ah_i_slab_alloc(&srv->_client_slab);
    if (cln == NULL) {
        err = AH_ENOMEM;
        goto handle_err;
    }

    *cln = (ah_http_client_t) {
        ._conn = conn,
        ._raddr = raddr,
        ._owning_slab = &srv->_client_slab,
        ._in_state = AH_I_HTTP_CLIENT_IN_STATE_INIT,
    };

    srv->_obs.cbs->on_accept(srv->_obs.ctx, srv, cln, &cln->_obs, err);

    obs->cbs = &ah_i_http_conn_cbs;
    obs->ctx = cln;

    if (ah_tcp_conn_is_closed(conn)) {
        return;
    }

    err = ah_tcp_conn_read_start(conn);
    if (err != AH_ENONE) {
        cln->_obs.cbs->on_recv_end(cln->_obs.ctx, cln, err);
    }

    return;

handle_err:
    srv->_obs.cbs->on_accept(srv->_obs.ctx, srv, NULL, NULL, err);
}

ah_extern ah_err_t ah_http_server_close(ah_http_server_t* srv)
{
    if (srv == NULL) {
        return AH_EINVAL;
    }
    return ah_tcp_listener_close(&srv->_ln);
}

static void s_listener_on_close(void* srv_, ah_tcp_listener_t* ln, ah_err_t err)
{
    ah_http_server_t* srv = ah_i_http_ctx_to_server(srv_);
    (void) ln;
    srv->_obs.cbs->on_close(srv->_obs.ctx, srv, err);
}

ah_extern ah_err_t ah_http_server_term(ah_http_server_t* srv)
{
    if (srv == NULL) {
        return AH_EINVAL;
    }

    ah_i_slab_term(&srv->_client_slab, NULL);

    return ah_tcp_listener_term(&srv->_ln);
}

ah_extern ah_tcp_listener_t* ah_http_server_get_listener(ah_http_server_t* srv)
{
    if (srv == NULL) {
        return NULL;
    }
    return &srv->_ln;
}

ah_extern ah_err_t ah_http_server_get_laddr(const ah_http_server_t* srv, ah_sockaddr_t* laddr)
{
    if (srv == NULL) {
        return AH_EINVAL;
    }
    return ah_tcp_listener_get_laddr(&srv->_ln, laddr);
}

ah_extern ah_loop_t* ah_http_server_get_loop(const ah_http_server_t* srv)
{
    if (srv == NULL) {
        return NULL;
    }
    return ah_tcp_listener_get_loop(&srv->_ln);
}

ah_extern void* ah_http_server_get_obs_ctx(const ah_http_server_t* srv)
{
    if (srv == NULL) {
        return NULL;
    }
    return srv->_obs.ctx;
}

ah_extern bool ah_http_server_cbs_is_valid(const ah_http_server_cbs_t* cbs)
{
    return cbs != NULL
        && cbs->on_open != NULL
        && cbs->on_listen != NULL
        && cbs->on_accept != NULL
        && cbs->on_close != NULL;
}
