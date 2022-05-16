// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include <ah/assert.h>
#include <ah/err.h>
#include <ah/math.h>

static void s_on_listener_open(ah_tcp_listener_t* ln, ah_err_t err);
static void s_on_listener_listen(ah_tcp_listener_t* ln, ah_err_t err);
static void s_on_listener_close(ah_tcp_listener_t* ln, ah_err_t err);
static void s_on_listener_conn_alloc(ah_tcp_listener_t* ln, ah_tcp_conn_t** conn);
static void s_on_listener_conn_accept(ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr);
static void s_on_listener_conn_err(ah_tcp_listener_t* ln, ah_err_t err);

static void s_on_conn_open(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_conn_connect(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_conn_close(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_conn_read_alloc(ah_tcp_conn_t* conn, ah_buf_t* buf);
static void s_on_conn_read_data(ah_tcp_conn_t* conn, const ah_buf_t* buf, size_t nread);
static void s_on_conn_read_err(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_conn_write_done(ah_tcp_conn_t* conn, ah_err_t err);

static ah_http_lclient_t* s_upcast_to_client(ah_tcp_conn_t* conn);
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
    ah_assert_if_debug(vtab->on_msg_alloc != NULL);
    ah_assert_if_debug(vtab->on_req_line != NULL);
    ah_assert_if_debug(vtab->on_req_header != NULL);
    ah_assert_if_debug(vtab->on_req_data != NULL);
    ah_assert_if_debug(vtab->on_req_end != NULL);
    ah_assert_if_debug(vtab->on_res_sent != NULL);

    static const ah_tcp_listener_vtab_t s_vtab = {
        .on_open = s_on_listener_open,
        .on_listen = s_on_listener_listen,
        .on_close = s_on_listener_close,
        .on_conn_alloc = s_on_listener_conn_alloc,
        .on_conn_accept = s_on_listener_conn_accept,
        .on_conn_err = s_on_listener_conn_err,
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
    ah_http_server_t* srv = s_upcast_to_server(ln);
    srv->_vtab->on_open(srv, err);
}

static ah_http_server_t* s_upcast_to_server(ah_tcp_listener_t* ln)
{
    ah_assert_if_debug(ln != NULL);

    // This is only safe if `ln` is a member of an ah_http_server_t value.
    const size_t ln_member_offset = offsetof(ah_http_server_t, _ln);
    ah_assert_if_debug(ln_member_offset <= PTRDIFF_MAX);
    ah_http_server_t* srv = (ah_http_server_t*) &((uint8_t*) ln)[-((ptrdiff_t) ln_member_offset)];

    ah_assert_if_debug(srv->_vtab != NULL);
    ah_assert_if_debug(srv->_trans_vtab != NULL);

    return srv;
}

ah_extern ah_err_t ah_http_server_listen(ah_http_server_t* srv, unsigned backlog)
{
    if (srv == NULL) {
        return AH_EINVAL;
    }

    static const ah_tcp_conn_vtab_t s_vtab = {
        .on_open = s_on_conn_open,
        .on_connect = s_on_conn_connect,
        .on_close = s_on_conn_close,
        .on_read_alloc = s_on_conn_read_alloc,
        .on_read_data = s_on_conn_read_data,
        .on_read_err = s_on_conn_read_err,
        .on_write_done = s_on_conn_write_done,
    };

    return srv->_trans_vtab->listener_listen(&srv->_ln, backlog, &s_vtab);
}

static void s_on_listener_listen(ah_tcp_listener_t* ln, ah_err_t err)
{
    ah_http_server_t* srv = s_upcast_to_server(ln);
    srv->_vtab->on_listen(srv, err);
}

static void s_on_conn_open(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_assert_if_debug(conn != NULL);
    (void) err; // TODO: Implement.
}

static void s_on_conn_connect(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_assert_if_debug(conn != NULL);
    (void) err; // TODO: Implement.
}

static void s_on_conn_close(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_assert_if_debug(conn != NULL);
    (void) err; // TODO: Implement.
}

static void s_on_conn_read_alloc(ah_tcp_conn_t* conn, ah_buf_t* buf)
{
    ah_assert_if_debug(conn != NULL);
    (void) buf; // TODO: Implement.
}

static void s_on_conn_read_data(ah_tcp_conn_t* conn, const ah_buf_t* buf, size_t nread)
{
    ah_assert_if_debug(conn != NULL);
    (void) buf; // TODO: Implement.
    (void) nread;
}

static void s_on_conn_read_err(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_assert_if_debug(conn != NULL);
    (void) err; // TODO: Implement.
}

static void s_on_conn_write_done(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_assert_if_debug(conn != NULL);
    (void) err; // TODO: Implement.
}

static void s_on_listener_conn_alloc(ah_tcp_listener_t* ln, ah_tcp_conn_t** conn)
{
    ah_assert_if_debug(conn != NULL);

    ah_http_server_t* srv = s_upcast_to_server(ln);
    (void) srv;
    (void) conn; // TODO: Handle.
}

static void s_on_listener_conn_accept(ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr)
{
    ah_http_server_t* srv = s_upcast_to_server(ln);
    ah_http_lclient_t* cnt = s_upcast_to_client(conn);

    ah_err_t err = srv->_trans_vtab->conn_read_start(conn);

    (void) cnt;
    (void) raddr;
    (void) err; // TODO: Handle.
}

static void s_on_listener_conn_err(ah_tcp_listener_t* ln, ah_err_t err)
{
    ah_http_server_t* srv = s_upcast_to_server(ln);
    (void) srv;
    (void) err; // TODO: Handle.
}

static ah_http_lclient_t* s_upcast_to_client(ah_tcp_conn_t* conn)
{
    ah_assert_if_debug(conn != NULL);

    // This is only safe if `conn` is a member of an ah_http_client_t value.
    const size_t conn_member_offset = offsetof(ah_http_lclient_t, _conn);
    ah_assert_if_debug(conn_member_offset <= PTRDIFF_MAX);
    ah_http_lclient_t* cln = (ah_http_lclient_t*) &((uint8_t*) conn)[-((ptrdiff_t) conn_member_offset)];

    ah_assert_if_debug(cln->_vtab != NULL);
    ah_assert_if_debug(cln->_trans_vtab != NULL);

    return cln;
}

ah_extern ah_err_t ah_http_server_respond(ah_http_server_t* srv, const ah_http_res_t* res)
{
    if (srv == NULL || res == NULL) {
        return AH_EINVAL;
    }

    (void) srv;
    (void) res;
    return AH_EOPNOTSUPP; // TODO: Implement.
}

ah_extern ah_err_t ah_http_server_send_end(ah_http_server_t* srv)
{
    (void) srv;
    return AH_EOPNOTSUPP; // TODO: Implement.
}

ah_extern ah_err_t ah_http_server_send_chunk(ah_http_server_t* srv, ah_http_chunk_t* chunk)
{
    (void) srv;
    (void) chunk;
    return AH_EOPNOTSUPP; // TODO: Implement.
}

ah_extern ah_err_t ah_http_server_send_data(ah_http_server_t* srv, ah_tcp_msg_t* msg)
{
    (void) srv;
    (void) msg;
    return AH_EOPNOTSUPP; // TODO: Implement.
}

ah_extern ah_err_t ah_http_server_send_trailer(ah_http_server_t* srv, ah_http_trailer_t* trailer)
{
    (void) srv;
    (void) trailer;
    return AH_EOPNOTSUPP; // TODO: Implement.
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
    ah_http_server_t* srv = s_upcast_to_server(ln);
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
