// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/tls.h"

#include "tls-client.h"
#include "tls-utils-mbedtls.h"
#include "tls-utils.h"

#include <ah/assert.h>
#include <ah/err.h>
#include <mbedtls/error.h>
#include <mbedtls/ssl.h>

static void s_listener_on_open(ah_tcp_listener_t* ln, ah_err_t err);
static void s_listener_on_listen(ah_tcp_listener_t* ln, ah_err_t err);
static void s_listener_on_close(ah_tcp_listener_t* ln, ah_err_t err);
static void s_listener_on_conn_alloc(ah_tcp_listener_t* ln, ah_tcp_conn_t** conn);
static void s_listener_on_conn_accept(ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr, ah_err_t err);

static const ah_tcp_listener_cbs_t s_listener_cbs = {
    .on_open = s_listener_on_open,
    .on_listen = s_listener_on_listen,
    .on_close = s_listener_on_close,
    .on_conn_alloc = s_listener_on_conn_alloc,
    .on_conn_accept = s_listener_on_conn_accept,
};

ah_extern ah_err_t ah_tls_server_init(ah_tls_server_t* server, ah_tcp_trans_t trans, ah_tls_cert_store_t* certs, ah_tls_on_handshake_done_cb on_handshake_done_cb)
{
    if (server == NULL || !ah_tcp_vtab_is_valid(trans.vtab) || certs == NULL || on_handshake_done_cb == NULL) {
        return AH_EINVAL;
    }
    if (certs->_own_chain == NULL || certs->_own_key == NULL) {
        return AH_EINVAL;
    }

    *server = (ah_tls_server_t) {
        ._trans = trans,
    };

    int res = ah_i_tls_ctx_init(&server->_ctx, certs, on_handshake_done_cb, MBEDTLS_SSL_IS_SERVER);
    if (res != 0) {
        return ah_i_tls_mbedtls_res_to_err(&server->_errs, res);
    }

    mbedtls_ssl_cache_init(&server->_ssl_cache);
    mbedtls_ssl_conf_session_cache(&server->_ctx._ssl_conf, &server->_ssl_cache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);

    return AH_ENONE;
}

ah_extern ah_tls_server_t* ah_tls_server_get_from_listener(ah_tcp_listener_t* ln)
{
    if (ln == NULL || ln->_trans.vtab != &ah_i_tls_tcp_vtab) {
        return NULL;
    }
    return ln->_trans.ctx;
}

ah_extern ah_tls_err_t ah_tls_server_get_last_error(ah_tls_server_t* server)
{
    if (server == NULL) {
        return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
    }
    return server->_errs._last_mbedtls_err;
}

ah_extern ah_tcp_trans_t ah_tls_server_as_trans(ah_tls_server_t* server)
{
    return (ah_tcp_trans_t) {
        .vtab = &ah_i_tls_tcp_vtab,
        .ctx = server,
    };
}

ah_extern void ah_tls_server_term(ah_tls_server_t* server)
{
    ah_assert_if_debug(server != NULL);

    ah_i_tls_ctx_term(&server->_ctx);
}

ah_err_t ah_i_tls_server_open(void* server_, ah_tcp_listener_t* ln, const ah_sockaddr_t* laddr)
{
    ah_tls_server_t* server = server_;
    if (server == NULL || server->_trans.vtab == NULL || server->_trans.vtab->listener_open == NULL) {
        return AH_ESTATE;
    }
    if (ln == NULL) {
        return AH_EINVAL;
    }

    server->_ln_cbs = ln->_cbs;
    ln->_cbs = &s_listener_cbs;

    return server->_trans.vtab->listener_open(server->_trans.ctx, ln, laddr);
}

ah_err_t ah_i_tls_server_listen(void* server_, ah_tcp_listener_t* ln, unsigned backlog, const ah_tcp_conn_cbs_t* conn_cbs)
{
    ah_tls_server_t* server = server_;
    if (server == NULL || server->_trans.vtab == NULL || server->_trans.vtab->listener_listen == NULL) {
        return AH_ESTATE;
    }
    if (ln == NULL) {
        return AH_EINVAL;
    }

    server->_conn_cbs = conn_cbs;

    return server->_trans.vtab->listener_listen(server->_trans.ctx, ln, backlog, &ah_i_tls_tcp_conn_cbs);
}

ah_err_t ah_i_tls_server_close(void* server_, ah_tcp_listener_t* ln)
{
    ah_tls_server_t* server = server_;
    if (server == NULL || server->_trans.vtab == NULL || server->_trans.vtab->listener_close == NULL) {
        return AH_ESTATE;
    }
    if (ln == NULL) {
        return AH_EINVAL;
    }

    return server->_trans.vtab->listener_close(server->_trans.ctx, ln);
}

static void s_listener_on_open(ah_tcp_listener_t* ln, ah_err_t err)
{
    ah_tls_server_t* server = ah_tls_server_get_from_listener(ln);

    if (server == NULL) {
        ln->_cbs->on_open(ln, AH_ESTATE);
        return;
    }

    server->_ln_cbs->on_open(ln, err);
}

static void s_listener_on_listen(ah_tcp_listener_t* ln, ah_err_t err)
{
    ah_tls_server_t* server = ah_tls_server_get_from_listener(ln);

    if (server == NULL) {
        ln->_cbs->on_listen(ln, AH_ESTATE);
        return;
    }

    server->_ln_cbs->on_listen(ln, err);
}

static void s_listener_on_close(ah_tcp_listener_t* ln, ah_err_t err)
{
    ah_tls_server_t* server = ah_tls_server_get_from_listener(ln);

    if (server == NULL) {
        ln->_cbs->on_close(ln, AH_ESTATE);
        return;
    }

    server->_ln_cbs->on_close(ln, err);
}

static void s_listener_on_conn_alloc(ah_tcp_listener_t* ln, ah_tcp_conn_t** conn)
{
    ah_tls_server_t* server = ah_tls_server_get_from_listener(ln);

    if (server == NULL) {
        ln->_cbs->on_conn_accept(ln, NULL, NULL, AH_ESTATE);
        return;
    }

    server->_ln_cbs->on_conn_alloc(ln, conn);
}

static void s_listener_on_conn_accept(ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr, ah_err_t err)
{
    // TODO: Allocate and setup ah_tls_client_t, associate it with conn.

    ah_tls_server_t* server = ah_tls_server_get_from_listener(ln);

    if (server == NULL) {
        ln->_cbs->on_conn_accept(ln, NULL, NULL, AH_ESTATE);
        return;
    }

    server->_ln_cbs->on_conn_accept(ln, conn, raddr, err);
}
