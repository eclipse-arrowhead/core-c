// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include "http-client.h"
#include "http-utils.h"

#include <ah/assert.h>
#include <ah/err.h>

static void ah_s_http_server_listener_on_open(void* srv_, ah_tcp_listener_t* ln, ah_err_t err);
static void ah_s_http_server_listener_on_listen(void* srv_, ah_tcp_listener_t* ln, ah_err_t err);
static void ah_s_http_server_listener_on_accept(void* srv_, ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr, ah_err_t err);
static void ah_s_http_server_listener_on_close(void* srv_, ah_tcp_listener_t* ln, ah_err_t err);

ah_extern ah_err_t ah_http_server_init(ah_http_server_t* srv, ah_loop_t* loop, ah_tcp_trans_t trans, const ah_http_server_cbs_t* cbs)
{
    if (srv == NULL || !ah_http_server_cbs_is_valid(cbs)) {
        return AH_EINVAL;
    }

    static const ah_tcp_listener_cbs_t s_cbs = {
        .on_open = ah_s_http_server_listener_on_open,
        .on_listen = ah_s_http_server_listener_on_listen,
        .on_close = ah_s_http_server_listener_on_close,
        .on_accept = ah_s_http_server_listener_on_accept,
    };

    *srv = (ah_http_server_t) {
        ._cbs = cbs,
    };

    ah_err_t err = ah_i_slab_init(&srv->_client_slab, 1u, sizeof(ah_http_client_t));
    if (err != AH_ENONE) {
        return err;
    }

    return ah_tcp_listener_init(&srv->_ln, loop, trans, (ah_tcp_listener_obs_t) { &s_cbs, srv });
}

ah_extern ah_err_t ah_http_server_open(ah_http_server_t* srv, const ah_sockaddr_t* laddr)
{
    if (srv == NULL) {
        return AH_EINVAL;
    }
    return ah_tcp_listener_open(&srv->_ln, laddr);
}

static void ah_s_http_server_listener_on_open(void* srv_, ah_tcp_listener_t* ln, ah_err_t err)
{
    ah_http_server_t* srv = ah_i_http_ctx_to_server(srv_);
    (void) ln;
    srv->_cbs->on_open(srv, err);
}

ah_extern ah_err_t ah_http_server_listen(ah_http_server_t* srv, unsigned backlog, const ah_http_client_cbs_t* cbs)
{
    if (srv == NULL || cbs == NULL) {
        return AH_EINVAL;
    }
    if (cbs->on_send == NULL) {
        return AH_EINVAL;
    }
    if (cbs->on_recv_line == NULL || cbs->on_recv_header == NULL || cbs->on_recv_data == NULL || cbs->on_recv_end == NULL) {
        return AH_EINVAL;
    }
    if (cbs->on_close == NULL) {
        return AH_EINVAL;
    }

    srv->_client_cbs = cbs;

    return ah_tcp_listener_listen(&srv->_ln, backlog, (ah_tcp_conn_obs_t) { ah_i_http_client_get_conn_cbs(), srv });
}

static void ah_s_http_server_listener_on_listen(void* srv_, ah_tcp_listener_t* ln, ah_err_t err)
{
    ah_http_server_t* srv = ah_i_http_ctx_to_server(srv_);
    (void) ln;
    srv->_cbs->on_listen(srv, err);
}

static void ah_s_http_server_listener_on_accept(void* srv_, ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr, ah_err_t err)
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

    ah_i_http_client_init_accepted(cln, conn, srv, raddr);

    srv->_cbs->on_accept(srv, cln, err);
    if (ah_tcp_conn_is_closed(conn)) {
        return;
    }

    err = ah_tcp_conn_read_start(conn);
    if (err != AH_ENONE) {
        cln->_cbs->on_recv_end(cln, err);
    }

    return;

handle_err:
    srv->_cbs->on_accept(srv, NULL, err);
}

ah_extern ah_err_t ah_http_server_close(ah_http_server_t* srv)
{
    if (srv == NULL) {
        return AH_EINVAL;
    }
    return ah_tcp_listener_close(&srv->_ln);
}

static void ah_s_http_server_listener_on_close(void* srv_, ah_tcp_listener_t* ln, ah_err_t err)
{
    ah_http_server_t* srv = ah_i_http_ctx_to_server(srv_);
    (void) ln;
    srv->_cbs->on_close(srv, err);
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

ah_extern void* ah_http_server_get_user_data(const ah_http_server_t* srv)
{
    if (srv == NULL) {
        return NULL;
    }
    return ah_tcp_listener_get_user_data(&srv->_ln);
}

ah_extern void ah_http_server_set_user_data(ah_http_server_t* srv, void* user_data)
{
    if (srv != NULL) {
        ah_tcp_listener_set_user_data(&srv->_ln, user_data);
    }
}

ah_extern bool ah_http_server_cbs_is_valid(const ah_http_server_cbs_t* cbs)
{
    return cbs != NULL
        && cbs->on_open != NULL
        && cbs->on_listen != NULL
        && cbs->on_accept != NULL
        && cbs->on_close != NULL;
}
