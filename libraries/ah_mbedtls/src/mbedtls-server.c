// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/mbedtls.h"

#include "mbedtls-client.h"
#include "mbedtls-utils.h"

#include <ah/assert.h>
#include <ah/conf.h>
#include <ah/err.h>
#include <ah/internal/page-allocator-gen.h>
#include <mbedtls/error.h>
#include <mbedtls/ssl.h>

#if AH_CONF_IS_CONSTRAINED
#define S_CLIENT_ALLOCATOR_PAGE_CAPACITY 4u
#else
#define S_CLIENT_ALLOCATOR_PAGE_CAPACITY 128u
#endif

struct ah_i_tls_client_page {
    struct ah_mbedtls_client _entries[S_CLIENT_ALLOCATOR_PAGE_CAPACITY];
    struct ah_i_tls_client_page* _next_page;
};

AH_I_PAGE_ALLOCATOR_GEN_GROW(static, s_client_allocator, struct ah_i_mbedtls_client_allocator, struct ah_i_tls_client_page, ah_mbedtls_client_t, S_CLIENT_ALLOCATOR_PAGE_CAPACITY)
AH_I_PAGE_ALLOCATOR_GEN_TERM(static, s_client_allocator, struct ah_i_mbedtls_client_allocator, struct ah_i_tls_client_page)

AH_I_PAGE_ALLOCATOR_GEN_ALLOC(static, s_client_allocator, struct ah_i_mbedtls_client_allocator, ah_mbedtls_client_t)
AH_I_PAGE_ALLOCATOR_GEN_FREE(static, s_client_allocator, struct ah_i_mbedtls_client_allocator, ah_mbedtls_client_t)
AH_I_PAGE_ALLOCATOR_GEN_INIT(static, s_client_allocator, struct ah_i_mbedtls_client_allocator, struct ah_i_tls_client_page, ah_mbedtls_client_t, S_CLIENT_ALLOCATOR_PAGE_CAPACITY)

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

ah_extern ah_err_t ah_mbedtls_server_init(ah_mbedtls_server_t* server, ah_tcp_trans_t trans, mbedtls_ssl_config* ssl_conf, ah_mbedtls_on_handshake_done_cb on_handshake_done_cb)
{
    if (server == NULL || !ah_tcp_vtab_is_valid(trans.vtab) || ssl_conf == NULL || on_handshake_done_cb == NULL) {
        return AH_EINVAL;
    }

    *server = (ah_mbedtls_server_t) {
        ._trans = trans,
        ._on_handshake_done_cb = on_handshake_done_cb,
        ._ssl_conf = ssl_conf,
    };

    return s_client_allocator_init(&server->_client_allocator, S_CLIENT_ALLOCATOR_PAGE_CAPACITY);
}

ah_extern int ah_mbedtls_server_get_last_err(ah_mbedtls_server_t* server)
{
    ah_assert(server != NULL);

    return server->_errs._last_mbedtls_err;
}

ah_extern mbedtls_ssl_config* ah_mbedtls_server_get_ssl_config(ah_mbedtls_server_t* server)
{
    ah_assert(server != NULL);

    return server->_ssl_conf;
}

ah_extern ah_tcp_trans_t ah_mbedtls_server_as_trans(ah_mbedtls_server_t* server)
{
    return (ah_tcp_trans_t) {
        .vtab = &ah_i_tls_tcp_vtab,
        .ctx = server,
    };
}

ah_extern void ah_mbedtls_server_term(ah_mbedtls_server_t* server)
{
    ah_assert_if_debug(server != NULL);

    s_client_allocator_term(&server->_client_allocator);
}

ah_extern ah_mbedtls_server_t* ah_mbedtls_listener_get_server(ah_tcp_listener_t* ln)
{
    if (ln == NULL || ln->_trans.vtab != &ah_i_tls_tcp_vtab) {
        return NULL;
    }
    return ln->_trans.ctx;
}

ah_extern int ah_mbedtls_listener_get_last_err(ah_tcp_listener_t* ln)
{
    ah_mbedtls_server_t* server = ah_mbedtls_listener_get_server(ln);
    if (server == NULL) {
        return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
    }
    return ah_mbedtls_server_get_last_err(server);
}

ah_extern mbedtls_ssl_config* ah_mbedtls_listener_get_ssl_config(ah_tcp_listener_t* ln)
{
    ah_mbedtls_server_t* server = ah_mbedtls_listener_get_server(ln);
    if (server == NULL) {
        return NULL;
    }
    return ah_mbedtls_server_get_ssl_config(server);
}

void ah_i_tls_server_free_accepted_client(ah_mbedtls_server_t* server, ah_mbedtls_client_t* client)
{
    ah_assert_if_debug(server != NULL);
    ah_assert_if_debug(client != NULL);

    s_client_allocator_free(&server->_client_allocator, client);
}

ah_err_t ah_i_tls_server_open(void* server_, ah_tcp_listener_t* ln, const ah_sockaddr_t* laddr)
{
    ah_mbedtls_server_t* server = server_;
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
    ah_mbedtls_server_t* server = server_;
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
    ah_mbedtls_server_t* server = server_;
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
    ah_mbedtls_server_t* server = ah_mbedtls_listener_get_server(ln);

    if (server == NULL) {
        ln->_cbs->on_open(ln, AH_ESTATE);
        return;
    }

    server->_ln_cbs->on_open(ln, err);
}

static void s_listener_on_listen(ah_tcp_listener_t* ln, ah_err_t err)
{
    ah_mbedtls_server_t* server = ah_mbedtls_listener_get_server(ln);

    if (server == NULL) {
        ln->_cbs->on_listen(ln, AH_ESTATE);
        return;
    }

    server->_ln_cbs->on_listen(ln, err);
}

static void s_listener_on_close(ah_tcp_listener_t* ln, ah_err_t err)
{
    ah_mbedtls_server_t* server = ah_mbedtls_listener_get_server(ln);

    if (server == NULL) {
        ln->_cbs->on_close(ln, AH_ESTATE);
        return;
    }

    server->_ln_cbs->on_close(ln, err);
}

static void s_listener_on_conn_alloc(ah_tcp_listener_t* ln, ah_tcp_conn_t** conn)
{
    ah_mbedtls_server_t* server = ah_mbedtls_listener_get_server(ln);

    if (server == NULL) {
        ln->_cbs->on_conn_accept(ln, NULL, NULL, AH_ESTATE);
        return;
    }

    server->_ln_cbs->on_conn_alloc(ln, conn);
}

static void s_listener_on_conn_accept(ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr, ah_err_t err)
{
    ah_mbedtls_server_t* server = ah_mbedtls_listener_get_server(ln);

    if (server == NULL) {
        ln->_cbs->on_conn_accept(ln, NULL, NULL, AH_ESTATE);
        return;
    }

    if (err != AH_ENONE) {
        goto handle_err;
    }

    ah_mbedtls_client_t* client;
    err = s_client_allocator_alloc(&server->_client_allocator, &client);
    if (err != AH_ENONE) {
        goto handle_err;
    }

    err = ah_i_tls_client_init(client, server->_trans, server->_ssl_conf);
    if (err != AH_ENONE) {
        s_client_allocator_free(&server->_client_allocator, client);
        goto handle_err;
    }

    client->_on_handshake_done_cb = server->_on_handshake_done_cb;
    client->_server = server;

handle_err:
    server->_ln_cbs->on_conn_accept(ln, conn, raddr, err);
}
