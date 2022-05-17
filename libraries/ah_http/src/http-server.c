// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include "http-rclient.h"
#include "http-utils.h"

#include <ah/assert.h>
#include <ah/err.h>
#include <ah/math.h>

static void s_on_listener_open(ah_tcp_listener_t* ln, ah_err_t err);
static void s_on_listener_listen(ah_tcp_listener_t* ln, ah_err_t err);
static void s_on_listener_close(ah_tcp_listener_t* ln, ah_err_t err);
static void s_on_listener_conn_alloc(ah_tcp_listener_t* ln, ah_tcp_conn_t** conn);
static void s_on_listener_conn_accept(ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr, ah_err_t err);

ah_extern ah_err_t ah_http_server_init(ah_http_server_t* srv, ah_tcp_trans_t trans, const ah_http_server_vtab_t* vtab)
{
    if (srv == NULL || trans._vtab == NULL || trans._loop == NULL || vtab == NULL) {
        return AH_EINVAL;
    }

    ah_assert_if_debug(trans._vtab->conn_init != NULL);
    ah_assert_if_debug(trans._vtab->conn_open != NULL);
    ah_assert_if_debug(trans._vtab->conn_connect != NULL);
    ah_assert_if_debug(trans._vtab->conn_read_start != NULL);
    ah_assert_if_debug(trans._vtab->conn_read_stop != NULL);
    ah_assert_if_debug(trans._vtab->conn_write != NULL);
    ah_assert_if_debug(trans._vtab->conn_shutdown != NULL);
    ah_assert_if_debug(trans._vtab->conn_close != NULL);
    ah_assert_if_debug(trans._vtab->listener_init != NULL);
    ah_assert_if_debug(trans._vtab->listener_open != NULL);
    ah_assert_if_debug(trans._vtab->listener_listen != NULL);
    ah_assert_if_debug(trans._vtab->listener_close != NULL);

    ah_assert_if_debug(vtab->on_open != NULL);
    ah_assert_if_debug(vtab->on_listen != NULL);
    ah_assert_if_debug(vtab->on_close != NULL);
    ah_assert_if_debug(vtab->on_client_alloc != NULL);
    ah_assert_if_debug(vtab->on_client_accept != NULL);

    static const ah_tcp_listener_vtab_t s_vtab = {
        .on_open = s_on_listener_open,
        .on_listen = s_on_listener_listen,
        .on_close = s_on_listener_close,
        .on_conn_alloc = s_on_listener_conn_alloc,
        .on_conn_accept = s_on_listener_conn_accept,
    };

    ah_err_t err = trans._vtab->listener_init(&srv->_ln, trans._loop, &s_vtab);
    if (err != AH_ENONE) {
        return err;
    }

    srv->_ln._trans_data = trans._data;
    srv->_trans_vtab = trans._vtab;
    srv->_vtab = vtab;

    return AH_ENONE;
}

ah_extern ah_err_t ah_http_server_open(ah_http_server_t* srv, const ah_sockaddr_t* laddr)
{
    if (srv == NULL) {
        return AH_EINVAL;
    }
    return srv->_trans_vtab->listener_open(&srv->_ln, laddr);
}

static void s_on_listener_open(ah_tcp_listener_t* ln, ah_err_t err)
{
    ah_http_server_t* srv = ah_i_http_upcast_to_server(ln);
    srv->_vtab->on_open(srv, err);
}

ah_extern ah_err_t ah_http_server_listen(ah_http_server_t* srv, unsigned backlog, const ah_http_rclient_vtab_t* vtab)
{
    if (srv == NULL || vtab == NULL) {
        return AH_EINVAL;
    }

    ah_assert_if_debug(vtab->on_close != NULL);
    ah_assert_if_debug(vtab->on_msg_alloc != NULL);
    ah_assert_if_debug(vtab->on_req_line != NULL);
    ah_assert_if_debug(vtab->on_req_header != NULL);
    ah_assert_if_debug(vtab->on_req_data != NULL);
    ah_assert_if_debug(vtab->on_req_end != NULL);
    ah_assert_if_debug(vtab->on_res_sent != NULL);

    srv->_rclient_vtab = vtab;
    return srv->_trans_vtab->listener_listen(&srv->_ln, backlog, ah_i_http_rclient_get_conn_vtab());
}

static void s_on_listener_listen(ah_tcp_listener_t* ln, ah_err_t err)
{
    ah_http_server_t* srv = ah_i_http_upcast_to_server(ln);
    srv->_vtab->on_listen(srv, err);
}

static void s_on_listener_conn_alloc(ah_tcp_listener_t* ln, ah_tcp_conn_t** conn)
{
    ah_assert_if_debug(conn != NULL);

    ah_http_server_t* srv = ah_i_http_upcast_to_server(ln);

    ah_http_rclient_t* cln;
    srv->_vtab->on_client_alloc(srv, &cln);
    if (cln != NULL) {
        *conn = &cln->_conn;
    }
}

static void s_on_listener_conn_accept(ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr, ah_err_t err)
{
    ah_http_server_t* srv = ah_i_http_upcast_to_server(ln);
    ah_http_rclient_t* cln = ah_i_http_upcast_to_rclient(conn);

    if (err == AH_ENONE) {
        err = ah_i_http_rclient_init(cln, srv, raddr);
    }
    srv->_vtab->on_client_accept(srv, cln, err);
}

ah_extern ah_err_t ah_http_server_close(ah_http_server_t* srv)
{
    if (srv == NULL) {
        return AH_EINVAL;
    }
    return srv->_trans_vtab->listener_close(&srv->_ln);
}

static void s_on_listener_close(ah_tcp_listener_t* ln, ah_err_t err)
{
    ah_http_server_t* srv = ah_i_http_upcast_to_server(ln);
    srv->_vtab->on_close(srv, err);
}

ah_extern ah_tcp_listener_t* ah_http_server_get_listener(ah_http_server_t* srv)
{
    ah_assert_if_debug(srv != NULL);

    return &srv->_ln;
}

ah_extern void* ah_http_server_get_user_data(ah_http_server_t* srv)
{
    ah_assert_if_debug(srv != NULL);

    return ah_tcp_listener_get_user_data(&srv->_ln);
}

ah_extern void ah_http_server_set_user_data(ah_http_server_t* srv, void* user_data)
{
    ah_assert_if_debug(srv != NULL);

    ah_tcp_listener_set_user_data(&srv->_ln, user_data);
}
