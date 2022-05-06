// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include <ah/err.h>
#include <ah/math.h>

static const ah_http_ireq_err_t s_ireq_err_content_length_respecified = {
    "'content-length' already specified",
    AH_HTTP_IREQ_ERR_CONTENT_LENGTH_RESPECIFIED,
    400,
    AH_EILSEQ,
};
static const ah_http_ireq_err_t s_ireq_err_headers_too_large = {
    "headers section too large",
    AH_HTTP_IREQ_ERR_HEADERS_TOO_LARGE,
    431,
    AH_ENOBUFS,
};
static const ah_http_ireq_err_t s_ireq_err_headers_too_many = {
    "too many headers",
    AH_HTTP_IREQ_ERR_HEADERS_TOO_MANY,
    400,
    AH_ENOBUFS,
};
static const ah_http_ireq_err_t s_ireq_err_host_respecified = {
    "'host' already specified",
    AH_HTTP_IREQ_ERR_HOST_RESPECIFIED,
    400,
    AH_EILSEQ,
};
static const ah_http_ireq_err_t s_ireq_err_host_unspecified = {
    "'host' not specified",
    AH_HTTP_IREQ_ERR_HOST_UNSPECIFIED,
    400,
    AH_EILSEQ,
};
static const ah_http_ireq_err_t s_ireq_err_req_line_too_long = {
    "request line too long",
    AH_HTTP_IREQ_ERR_REQ_LINE_TOO_LONG,
    400,
    AH_ENOBUFS,
};

static void s_on_conn_alloc(ah_tcp_listener_t* ln, ah_tcp_conn_t** conn);
static void s_on_conn_accept(ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr);
static void s_on_conn_err(ah_tcp_listener_t* ln, ah_err_t err);

static ah_http_ireq_err_t s_ireq_err_internal_error_from(ah_err_t err);
static ah_http_client_t* s_upcast_to_client(ah_tcp_conn_t* conn);
static ah_http_server_t* s_upcast_to_server(ah_tcp_listener_t* ln);

ah_extern ah_err_t ah_http_server_init(ah_http_server_t* srv, ah_tcp_trans_t trans, const ah_http_server_vtab_t* vtab)
{
    if (srv == NULL || trans._vtab == NULL || trans._loop == NULL || vtab == NULL) {
        return AH_EINVAL;
    }

    (void) s_ireq_err_content_length_respecified;
    (void) s_ireq_err_headers_too_large;
    (void) s_ireq_err_headers_too_many;
    (void) s_ireq_err_host_respecified;
    (void) s_ireq_err_host_unspecified;
    (void) s_ireq_err_req_line_too_long;
    (void) s_ireq_err_internal_error_from;

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
    ah_assert_if_debug(vtab->on_req_alloc_head != NULL);
    ah_assert_if_debug(vtab->on_req_alloc_more != NULL);
    ah_assert_if_debug(vtab->on_req_line != NULL);
    ah_assert_if_debug(vtab->on_req_headers != NULL);
    ah_assert_if_debug(vtab->on_req_chunk != NULL);
    ah_assert_if_debug(vtab->on_req_data != NULL);
    ah_assert_if_debug(vtab->on_req_err != NULL);
    ah_assert_if_debug(vtab->on_req_end != NULL);
    ah_assert_if_debug(vtab->on_res_sent != NULL);

    const ah_tcp_listener_vtab_t s_vtab = {
        .on_open = (void (*)(ah_tcp_listener_t*, ah_err_t)) srv->_vtab->on_open,
        .on_listen = (void (*)(ah_tcp_listener_t*, ah_err_t)) srv->_vtab->on_listen,
        .on_close = (void (*)(ah_tcp_listener_t*, ah_err_t)) srv->_vtab->on_close,
        .on_conn_alloc = s_on_conn_alloc,
        .on_conn_accept = s_on_conn_accept,
        .on_conn_err = s_on_conn_err,
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
    return srv->_trans_vtab->listener_listen(&srv->_ln, backlog, NULL); // TODO: conn vtab.
}

static void s_on_conn_alloc(ah_tcp_listener_t* ln, ah_tcp_conn_t** conn)
{
    ah_assert_if_debug(conn != NULL);

    ah_http_server_t* srv = s_upcast_to_server(ln);
    (void) srv;
    (void) conn; // TODO: Handle.
}

static void s_on_conn_accept(ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr)
{
    ah_http_server_t* srv = s_upcast_to_server(ln);
    ah_http_client_t* cnt = s_upcast_to_client(conn);

    ah_err_t err = srv->_trans_vtab->conn_read_start(conn);

    (void) cnt;
    (void) raddr;
    (void) err; // TODO: Handle.
}

static void s_on_conn_err(ah_tcp_listener_t* ln, ah_err_t err)
{
    ah_http_server_t* srv = s_upcast_to_server(ln);
    (void) srv;
    (void) err; // TODO: Handle.
}

static ah_http_client_t* s_upcast_to_client(ah_tcp_conn_t* conn)
{
    ah_assert_if_debug(conn != NULL);

    // This is only safe if `conn` is a member of an ah_http_client_t value.
    const size_t conn_member_offset = offsetof(ah_http_client_t, _conn);
    ah_assert_if_debug(conn_member_offset <= PTRDIFF_MAX);
    ah_http_client_t* cln = (ah_http_client_t*) &((uint8_t*) conn)[-((ptrdiff_t) conn_member_offset)];

    ah_assert_if_debug(cln->_vtab != NULL);
    ah_assert_if_debug(cln->_trans_vtab != NULL);

    return cln;
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
    return srv->_trans_vtab->listener_close(&srv->_ln);
}

static ah_http_ireq_err_t s_ireq_err_internal_error_from(ah_err_t err)
{
    return (ah_http_ireq_err_t) { "internal server error", AH_HTTP_IREQ_ERR_INTERNAL, 500, err };
}
