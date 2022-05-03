// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include <ah/err.h>
#include <ah/math.h>

static void s_on_open(ah_tcp_listener_t* ln, ah_err_t err);
static void s_on_listen(ah_tcp_listener_t* ln, ah_err_t err);
static void s_on_close(ah_tcp_listener_t* ln, ah_err_t err);
static void s_on_conn_alloc(ah_tcp_listener_t* ln, ah_tcp_conn_t** conn);
static void s_on_conn_accept(ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr, ah_err_t err);

static ah_http_client_t* s_upcast_to_client(ah_tcp_conn_t* conn);
static ah_http_server_t* s_upcast_to_server(ah_tcp_listener_t* ln);

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
    ah_assert_if_debug(vtab->on_client_close != NULL);
    ah_assert_if_debug(vtab->on_req_alloc != NULL);
    ah_assert_if_debug(vtab->on_req_line != NULL);
    ah_assert_if_debug(vtab->on_req_headers != NULL);
    ah_assert_if_debug(vtab->on_req_err != NULL);
    ah_assert_if_debug(vtab->on_body_alloc != NULL);
    ah_assert_if_debug(vtab->on_body_chunk != NULL);
    ah_assert_if_debug(vtab->on_body_received != NULL);
    ah_assert_if_debug(vtab->on_res_sent != NULL);

    static const ah_tcp_listener_vtab_t s_vtab = {
        .on_open = s_on_open,
        .on_listen = s_on_listen,
        .on_close = s_on_close,
        .on_conn_alloc = s_on_conn_alloc,
        .on_conn_accept = s_on_conn_accept,
    };

    ah_err_t err = trans._vtab->listener_init(&srv->_ln, trans._loop, &s_vtab);
    if (err != AH_ENONE) {
        return err;
    }

    srv->_trans = trans;
    srv->_vtab = vtab;

    return AH_ENONE;
}

ah_extern ah_err_t ah_http_server_open(ah_http_server_t* srv, const ah_sockaddr_t* laddr)
{
    if (srv == NULL) {
        return AH_EINVAL;
    }
    return srv->_trans._vtab->listener_open(&srv->_ln, laddr);
}

static void s_on_open(ah_tcp_listener_t* ln, ah_err_t err)
{
    ah_http_server_t* srv = s_upcast_to_server(ln);
    srv->_vtab->on_open(srv, err);
}

static ah_http_server_t* s_upcast_to_server(ah_tcp_listener_t* ln)
{
    ah_assert_if_debug(ln != NULL);

    // This is only safe if `ln` is a member of an ah_http_server_t value.
    ah_http_server_t* srv = (ah_http_server_t*) &((uint8_t*) ln)[-offsetof(ah_http_server_t, _ln)];

    ah_assert_if_debug(srv->_vtab != NULL);
    ah_assert_if_debug(srv->_trans._vtab != NULL);
    ah_assert_if_debug(srv->_trans._loop != NULL);

    return srv;
}

ah_extern ah_err_t ah_http_server_listen(ah_http_server_t* srv, unsigned backlog)
{
    if (srv == NULL) {
        return AH_EINVAL;
    }
    return srv->_trans._vtab->listener_listen(&srv->_ln, backlog, NULL); // TODO: conn vtab.
}

static void s_on_listen(ah_tcp_listener_t* ln, ah_err_t err)
{
    ah_http_server_t* srv = s_upcast_to_server(ln);
    srv->_vtab->on_listen(srv, err);
}

static void s_on_conn_alloc(ah_tcp_listener_t* ln, ah_tcp_conn_t** conn)
{
    ah_assert_if_debug(conn != NULL);

    ah_http_server_t* srv = s_upcast_to_server(ln);
    ah_http_client_t* cnt = NULL;
    srv->_vtab->on_client_alloc(srv, &cnt);
    if (cnt != NULL) {
        *conn = &cnt->_conn;
    }
}

static void s_on_conn_accept(ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr, ah_err_t err)
{
    ah_http_server_t* srv = s_upcast_to_server(ln);
    ah_http_client_t* cnt = conn != NULL ? s_upcast_to_client(conn) : NULL;

    if (conn != NULL && err == AH_ENONE) {
        err = srv->_trans._vtab->conn_read_start(conn);
    }

    srv->_vtab->on_client_accept(srv, cnt, raddr, err);
}

static ah_http_client_t* s_upcast_to_client(ah_tcp_conn_t* conn)
{
    ah_assert_if_debug(conn != NULL);

    // This is only safe if `conn` is a member of an ah_http_client_t value.
    ah_http_client_t* srv = (ah_http_client_t*) &((uint8_t*) conn)[-offsetof(ah_http_client_t, _conn)];

    ah_assert_if_debug(srv->_vtab != NULL);
    ah_assert_if_debug(srv->_trans._vtab != NULL);
    ah_assert_if_debug(srv->_trans._loop != NULL);

    return srv;
}

ah_extern ah_err_t ah_http_server_respond(ah_http_server_t* srv, const ah_http_ores_t* res)
{
    if (srv == NULL || res == NULL) {
        return AH_EINVAL;
    }

    (void) srv;
    (void) res;
    return AH_EOPNOTSUPP; // TODO: Implement.
}

ah_extern ah_err_t ah_http_server_close(ah_http_server_t* srv)
{
    if (srv == NULL) {
        return AH_EINVAL;
    }
    return srv->_trans._vtab->listener_close(&srv->_ln);
}

static void s_on_close(ah_tcp_listener_t* ln, ah_err_t err)
{
    ah_http_server_t* srv = s_upcast_to_server(ln);
    srv->_vtab->on_close(srv, err);
}
