// SPDX-License-Identifier: EPL-2.0

#include "ah/mbedtls.h"

#include "ah/internal/collections/slab.h"
#include "mbedtls-client.h"
#include "mbedtls-utils.h"

#include <ah/assert.h>
#include <ah/err.h>
#include <mbedtls/error.h>
#include <mbedtls/ssl.h>

static void ah_s_tcp_listener_on_open(void* server_, ah_tcp_listener_t* ln, ah_err_t err);
static void ah_s_tcp_listener_on_listen(void* server_, ah_tcp_listener_t* ln, ah_err_t err);
static void ah_s_tcp_listener_on_accept(void* server_, ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr, ah_err_t err);
static void ah_s_tcp_listener_on_close(void* server_, ah_tcp_listener_t* ln, ah_err_t err);

static const ah_tcp_listener_cbs_t s_listener_cbs = {
    .on_open = ah_s_tcp_listener_on_open,
    .on_listen = ah_s_tcp_listener_on_listen,
    .on_accept = ah_s_tcp_listener_on_accept,
    .on_close = ah_s_tcp_listener_on_close,
};

ah_extern ah_err_t ah_mbedtls_server_init(ah_mbedtls_server_t* server, ah_tcp_trans_t trans, mbedtls_ssl_config* ssl_conf, ah_mbedtls_on_handshake_done_cb on_handshake_done_cb)
{
    if (server == NULL || !ah_tcp_trans_vtab_is_valid(&trans) || ssl_conf == NULL || on_handshake_done_cb == NULL) {
        return AH_EINVAL;
    }

    *server = (ah_mbedtls_server_t) {
        ._trans = trans,
        ._on_handshake_done_cb = on_handshake_done_cb,
        ._ssl_conf = ssl_conf,
    };

    return ah_i_slab_init(&server->_client_slab, 1u, sizeof(ah_mbedtls_client_t));
}

ah_extern int ah_mbedtls_server_get_last_err(ah_mbedtls_server_t* server)
{
    if (server == NULL) {
        return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
    }
    return server->_errs._last_mbedtls_err;
}

ah_extern mbedtls_ssl_config* ah_mbedtls_server_get_ssl_config(ah_mbedtls_server_t* server)
{
    if (server == NULL) {
        return NULL;
    }
    return server->_ssl_conf;
}

ah_extern ah_tcp_trans_t ah_mbedtls_server_as_trans(ah_mbedtls_server_t* server)
{
    return (ah_tcp_trans_t) {
        .vtab = &ah_i_mbedtls_tcp_vtab,
        .ctx = server,
    };
}

ah_extern void ah_mbedtls_server_term(ah_mbedtls_server_t* server)
{
    if (server == NULL) {
        return;
    }

    ah_i_slab_term(&server->_client_slab, NULL);
}

void ah_i_tls_server_free_accepted_client(ah_mbedtls_server_t* server, ah_mbedtls_client_t* client)
{
    ah_assert_if_debug(server != NULL);
    ah_assert_if_debug(client != NULL);

    ah_i_slab_free(&server->_client_slab, client);
}

ah_err_t ah_i_mbedtls_listener_init(void* server_, ah_tcp_listener_t* ln, ah_loop_t* loop, ah_tcp_trans_t trans, ah_tcp_listener_obs_t obs)
{
    ah_mbedtls_server_t* server = server_;

    if (server == NULL || ln == NULL || !ah_tcp_listener_cbs_is_valid(obs.cbs)) {
        return AH_EINVAL;
    }

    server->_ln_obs = obs;

    ah_assert_if_debug(server->_trans.vtab != NULL && server->_trans.vtab->listener_init != NULL);

    return server->_trans.vtab->listener_init(server->_trans.ctx, ln, loop, trans, (ah_tcp_listener_obs_t) { &s_listener_cbs, server });
}

/*
ah_err_t ah_i_mbedtls_listener_set_conn_obs(void* server_, ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, ah_tcp_conn_obs_t obs)
{
    ah_mbedtls_server_t* server = server_;

    if (server == NULL || ln == NULL || conn == NULL || !ah_tcp_conn_obs_is_valid(&obs)) {
        return AH_EINVAL;
    }

    ah_mbedtls_client_t* client = ah_i_slab_alloc(&server->_client_slab);
    if (client == NULL) {
        return AH_ENOMEM;
    }

    ah_err_t err = ah_i_mbedtls_client_init(client, server->_trans, server->_ssl_conf, server->_on_handshake_done_cb);
    if (err != AH_ENONE) {
        ah_i_slab_free(&server->_client_slab, client);
        return err;
    }

    client->_conn = conn;
    client->_conn_obs = obs;
    client->_server = server;

    mbedtls_ssl_set_bio(&client->_ssl, client, ah_i_mbedtls_client_write_ciphertext, ah_i_mbedtls_client_read_ciphertext, NULL);

    return server->_trans.vtab->listener_set_conn_obs(server->_trans.ctx, ln, conn, (ah_tcp_conn_obs_t) { &ah_i_mbedtls_tcp_conn_cbs, client });
}
*/
ah_err_t ah_i_mbedtls_listener_open(void* server_, ah_tcp_listener_t* ln, const ah_sockaddr_t* laddr)
{
    ah_mbedtls_server_t* server = server_;
    if (server == NULL || server->_trans.vtab == NULL || server->_trans.vtab->listener_open == NULL) {
        return AH_ESTATE;
    }
    if (ln == NULL) {
        return AH_EINVAL;
    }
    return server->_trans.vtab->listener_open(server->_trans.ctx, ln, laddr);
}

static void ah_s_tcp_listener_on_open(void* server_, ah_tcp_listener_t* ln, ah_err_t err)
{
    ah_mbedtls_server_t* server = server_;
    ah_assert_if_debug(server != NULL);

    server->_ln_obs.cbs->on_open(server->_ln_obs.ctx, ln, err);
}

ah_err_t ah_i_mbedtls_listener_listen(void* server_, ah_tcp_listener_t* ln, unsigned backlog, ah_tcp_conn_obs_t conn_obs)
{
    ah_mbedtls_server_t* server = server_;
    if (server == NULL || server->_trans.vtab == NULL || server->_trans.vtab->listener_listen == NULL) {
        return AH_ESTATE;
    }
    if (ln == NULL) {
        return AH_EINVAL;
    }

    server->_conn_obs = conn_obs;

    return server->_trans.vtab->listener_listen(server->_trans.ctx, ln, backlog);
}

static void ah_s_tcp_listener_on_listen(void* server_, ah_tcp_listener_t* ln, ah_err_t err)
{
    ah_mbedtls_server_t* server = server_;
    ah_assert_if_debug(server != NULL);

    server->_ln_obs.cbs->on_listen(server->_ln_obs.ctx, ln, err);
}

ah_err_t ah_i_mbedtls_listener_close(void* server_, ah_tcp_listener_t* ln)
{
    ah_mbedtls_server_t* server = server_;
    if (server == NULL || server->_trans.vtab == NULL || server->_trans.vtab->listener_close == NULL) {
        return AH_ESTATE;
    }
    if (ln == NULL) {
        return AH_EINVAL;
    }

    return server->_trans.vtab->listener_close(server->_trans.ctx, ln);
}

static void ah_s_tcp_listener_on_accept(void* server_, ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr, ah_err_t err)
{
    ah_mbedtls_server_t* server = server_;
    ah_assert_if_debug(server != NULL);

    server->_ln_obs.cbs->on_accept(server->_ln_obs.ctx, ln, conn, NULL, raddr, err);
}

static void ah_s_tcp_listener_on_close(void* server_, ah_tcp_listener_t* ln, ah_err_t err)
{
    ah_mbedtls_server_t* server = server_;
    ah_assert_if_debug(server != NULL);

    server->_ln_obs.cbs->on_close(server->_ln_obs.ctx, ln, err);
}
