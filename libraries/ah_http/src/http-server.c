// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include <ah/err.h>
#include <ah/math.h>

static void s_on_accept(ah_tcp_sock_t* sock, ah_tcp_sock_t* conn, const ah_sockaddr_t* remote_addr, ah_err_t err);
static void s_on_alloc_bufs(ah_tcp_sock_t* sock, ah_bufs_t* bufs, size_t n_bytes_expected);
static void s_on_alloc_sock(ah_tcp_sock_t* sock, ah_tcp_sock_t** conn);
static void s_on_close(ah_tcp_sock_t* sock, ah_err_t err);
static void s_on_listen(ah_tcp_sock_t* sock, ah_err_t err);
static void s_on_open(ah_tcp_sock_t* sock, ah_err_t err);
static void s_on_read(ah_tcp_sock_t* sock, ah_bufs_t* bufs, size_t n_bytes_read, ah_err_t err);

static ah_http_client_t* s_upcast_to_client(ah_tcp_sock_t* sock);
static ah_http_server_t* s_upcast_to_server(ah_tcp_sock_t* sock);

ah_extern void ah_http_server_init(ah_http_server_t* srv, ah_tcp_trans_t trans, const ah_http_server_vtab_t* vtab)
{
    ah_assert_if_debug(srv != NULL);

    ah_assert_if_debug(trans._loop != NULL);
    ah_assert_if_debug(trans._vtab != NULL);
    ah_assert_if_debug(trans._vtab->init != NULL);
    ah_assert_if_debug(trans._vtab->open != NULL);
    ah_assert_if_debug(trans._vtab->connect != NULL);
    ah_assert_if_debug(trans._vtab->read_start != NULL);
    ah_assert_if_debug(trans._vtab->read_stop != NULL);
    ah_assert_if_debug(trans._vtab->write != NULL);
    ah_assert_if_debug(trans._vtab->shutdown != NULL);
    ah_assert_if_debug(trans._vtab->close != NULL);

    ah_assert_if_debug(vtab != NULL);
    ah_assert_if_debug(vtab->on_open != NULL);
    ah_assert_if_debug(vtab->on_listen != NULL);
    ah_assert_if_debug(vtab->on_close != NULL);
    ah_assert_if_debug(vtab->on_client_alloc != NULL);
    ah_assert_if_debug(vtab->on_client_accept != NULL);
    ah_assert_if_debug(vtab->on_client_close != NULL);
    ah_assert_if_debug(vtab->on_req_alloc != NULL);
    ah_assert_if_debug(vtab->on_req_line != NULL);
    ah_assert_if_debug(vtab->on_req_headers != NULL);
    ah_assert_if_debug(vtab->on_req_body != NULL);
    ah_assert_if_debug(vtab->on_req_done != NULL);
    ah_assert_if_debug(vtab->on_req_err != NULL);

    trans._vtab->init(&srv->_sock, trans._loop);
    srv->_trans = trans;
    srv->_vtab = vtab;
    srv->_listen_ctx.listen_cb = s_on_listen;
    srv->_listen_ctx.accept_cb = s_on_accept;
    srv->_listen_ctx.alloc_cb = s_on_alloc_sock;
}

ah_extern ah_err_t ah_http_server_open(ah_http_server_t* srv, const ah_sockaddr_t* local_addr)
{
    if (srv == NULL) {
        return AH_EINVAL;
    }
    return srv->_trans._vtab->open(&srv->_sock, local_addr, s_on_open);
}

static void s_on_open(ah_tcp_sock_t* sock, ah_err_t err)
{
    ah_http_server_t* srv = s_upcast_to_server(sock);
    srv->_vtab->on_open(srv, err);
}

static ah_http_server_t* s_upcast_to_server(ah_tcp_sock_t* sock)
{
    ah_assert_if_debug(sock != NULL);

    // This is only safe if `sock` is a member of an ah_http_server_t value.
    ah_http_server_t* srv = (ah_http_server_t*) &((uint8_t*) sock)[-offsetof(ah_http_server_t, _sock)];

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
    return srv->_trans._vtab->listen(&srv->_sock, backlog, &srv->_listen_ctx);
}

static void s_on_listen(ah_tcp_sock_t* sock, ah_err_t err)
{
    ah_http_server_t* srv = s_upcast_to_server(sock);
    srv->_vtab->on_listen(srv, err);
}

static void s_on_alloc_sock(ah_tcp_sock_t* sock, ah_tcp_sock_t** conn)
{
    ah_assert_if_debug(conn != NULL);

    ah_http_server_t* srv = s_upcast_to_server(sock);
    ah_http_client_t* cnt = NULL;
    srv->_vtab->on_client_alloc(srv, &cnt);
    if (cnt != NULL) {
        *conn = &cnt->_sock;
    }
}

static void s_on_accept(ah_tcp_sock_t* sock, ah_tcp_sock_t* conn, const ah_sockaddr_t* remote_addr, ah_err_t err)
{
    ah_http_server_t* srv = s_upcast_to_server(sock);
    ah_http_client_t* cnt = conn != NULL ? s_upcast_to_client(conn) : NULL;

    srv->_vtab->on_client_accept(srv, cnt, remote_addr, err);

    if (conn == NULL || err != AH_ENONE) {
        return;
    }

    cnt->_read_ctx.alloc_cb = s_on_alloc_bufs;
    cnt->_read_ctx.read_cb = s_on_read;

    srv->_trans._vtab->read_start(sock, &cnt->_read_ctx);
}

static ah_http_client_t* s_upcast_to_client(ah_tcp_sock_t* sock)
{
    ah_assert_if_debug(sock != NULL);

    // This is only safe if `sock` is a member of an ah_http_client_t value.
    ah_http_client_t* srv = (ah_http_client_t*) &((uint8_t*) sock)[-offsetof(ah_http_client_t, _sock)];

    ah_assert_if_debug(srv->_vtab != NULL);
    ah_assert_if_debug(srv->_trans._vtab != NULL);
    ah_assert_if_debug(srv->_trans._loop != NULL);

    return srv;
}

static void s_on_alloc_bufs(ah_tcp_sock_t* sock, ah_bufs_t* bufs, const size_t n_bytes_expected)
{
    ah_http_server_t* srv = s_upcast_to_server(sock);

    size_t n_bytes_expected0;
    ah_err_t err = ah_add_size(n_bytes_expected, sizeof(ah_http_ireq_t) + sizeof(ah_http_ores_t), &n_bytes_expected0);
    if (err != AH_ENONE) {
        n_bytes_expected0 = SIZE_MAX;
    }

    (void) srv;
    (void) bufs;
    (void) n_bytes_expected0;
}

static void s_on_read(ah_tcp_sock_t* sock, ah_bufs_t* bufs, size_t n_bytes_read, ah_err_t err)
{
    (void) sock;
    (void) bufs;
    (void) n_bytes_read;
    (void) err;
}

ah_extern ah_err_t ah_http_server_respond(ah_http_server_t* srv, const ah_http_ores_t* res)
{
    if (srv == NULL || res == NULL) {
        return AH_EINVAL;
    }

    (void) srv;
    (void) res;
    return AH_EOPNOTSUPP;
}

ah_extern ah_err_t ah_http_server_close(ah_http_server_t* srv)
{
    if (srv == NULL) {
        return AH_EINVAL;
    }
    return srv->_trans._vtab->close(&srv->_sock, s_on_close);
}

static void s_on_close(ah_tcp_sock_t* sock, ah_err_t err)
{
    ah_http_server_t* srv = s_upcast_to_server(sock);
    srv->_vtab->on_close(srv, err);
}
