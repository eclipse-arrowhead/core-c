// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include <ah/err.h>

static const ah_http_ires_err_t s_ires_err_alloc_failed = {
    "memory allocation failed",
    AH_HTTP_IRES_ERR_ALLOC_FAILED,
    AH_ENOMEM,
};
static const ah_http_ires_err_t s_ires_err_headers_too_large = {
    "headers section too large",
    AH_HTTP_IRES_ERR_HEADERS_TOO_LARGE,
    AH_ENOBUFS,
};
static const ah_http_ires_err_t s_ires_err_headers_too_many = {
    "too many headers",
    AH_HTTP_IRES_ERR_HEADERS_TOO_MANY,
    AH_ENOBUFS,
};
static const ah_http_ires_err_t s_ires_err_stat_line_too_long = {
    "status line too long",
    AH_HTTP_IRES_ERR_STAT_LINE_TOO_LONG,
    AH_ENOBUFS,
};
static const ah_http_ires_err_t s_ires_err_ver_unsupported = {
    "HTTP version not supported",
    AH_HTTP_IRES_ERR_VER_UNSUPPORTED,
    AH_EILSEQ,
};

static void s_on_open(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_connect(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_close(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_read_alloc(ah_tcp_conn_t* conn, ah_bufs_t* bufs);
static void s_on_read_done(ah_tcp_conn_t* conn, ah_bufs_t bufs, size_t n_read, ah_err_t err);
static void s_on_write_done(ah_tcp_conn_t* conn, ah_err_t err);

static ah_http_client_t* s_upcast_to_client(ah_tcp_conn_t* conn);

ah_extern ah_err_t ah_http_client_init(ah_http_client_t* cln, ah_tcp_trans_t trans, const ah_http_client_vtab_t* vtab)
{
    if (cln == NULL || trans._vtab == NULL || trans._loop == NULL || vtab == NULL) {
        return AH_EINVAL;
    }

    (void) s_ires_err_headers_too_large;
    (void) s_ires_err_headers_too_many;
    (void) s_ires_err_stat_line_too_long;
    (void) s_ires_err_ver_unsupported;

    ah_assert_if_debug(trans._vtab->conn_init != NULL);
    ah_assert_if_debug(trans._vtab->conn_open != NULL);
    ah_assert_if_debug(trans._vtab->conn_connect != NULL);
    ah_assert_if_debug(trans._vtab->conn_read_start != NULL);
    ah_assert_if_debug(trans._vtab->conn_read_stop != NULL);
    ah_assert_if_debug(trans._vtab->conn_write != NULL);
    ah_assert_if_debug(trans._vtab->conn_shutdown != NULL);
    ah_assert_if_debug(trans._vtab->conn_close != NULL);

    ah_assert_if_debug(vtab->on_open != NULL);
    ah_assert_if_debug(vtab->on_connect != NULL);
    ah_assert_if_debug(vtab->on_close != NULL);
    ah_assert_if_debug(vtab->on_req_sent != NULL);
    ah_assert_if_debug(vtab->on_res_alloc != NULL);
    ah_assert_if_debug(vtab->on_res_line != NULL);
    ah_assert_if_debug(vtab->on_res_headers != NULL);
    ah_assert_if_debug(vtab->on_res_err != NULL);
    ah_assert_if_debug(vtab->on_res_body_alloc != NULL);
    ah_assert_if_debug(vtab->on_res_body != NULL);
    ah_assert_if_debug(vtab->on_res_body_received != NULL);

    static const ah_tcp_conn_vtab_t s_vtab = {
        .on_open = s_on_open,
        .on_connect = s_on_connect,
        .on_close = s_on_close,
        .on_read_alloc = s_on_read_alloc,
        .on_read_done = s_on_read_done,
        .on_write_done = s_on_write_done,
    };

    ah_err_t err = trans._vtab->conn_init(&cln->_conn, trans._loop, &s_vtab);
    if (err != AH_ENONE) {
        return err;
    }

    cln->_trans = trans;
    cln->_vtab = vtab;

    return AH_ENONE;
}

ah_extern ah_err_t ah_http_client_open(ah_http_client_t* cln, const ah_sockaddr_t* laddr)
{
    if (cln == NULL) {
        return AH_EINVAL;
    }
    return cln->_trans._vtab->conn_open(&cln->_conn, laddr);
}

static void s_on_open(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_http_client_t* cln = s_upcast_to_client(conn);
    cln->_vtab->on_open(cln, err);
}

static ah_http_client_t* s_upcast_to_client(ah_tcp_conn_t* conn)
{
    ah_assert_if_debug(conn != NULL);

    // This is only safe if `conn` is a member of an ah_http_client_t value.
    const size_t conn_member_offset = offsetof(ah_http_client_t, _conn);
    ah_assert_if_debug(conn_member_offset <= PTRDIFF_MAX);
    ah_http_client_t* cln = (ah_http_client_t*) &((uint8_t*) conn)[-((ptrdiff_t) conn_member_offset)];

    ah_assert_if_debug(cln->_vtab != NULL);
    ah_assert_if_debug(cln->_trans._vtab != NULL);
    ah_assert_if_debug(cln->_trans._loop != NULL);

    return cln;
}

ah_extern ah_err_t ah_http_client_connect(ah_http_client_t* cln, const ah_sockaddr_t* raddr)
{
    if (cln == NULL) {
        return AH_EINVAL;
    }
    return cln->_trans._vtab->conn_connect(&cln->_conn, raddr);
}

static void s_on_connect(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_http_client_t* cln = s_upcast_to_client(conn);

    if (err == AH_ENONE) {
        err = ah_tcp_conn_read_start(conn);
    }

    cln->_vtab->on_connect(cln, err);
}

static void s_on_read_alloc(ah_tcp_conn_t* conn, ah_bufs_t* bufs)
{
    ah_http_client_t* cln = s_upcast_to_client(conn);

    if (cln->_ires != NULL) {
        cln->_vtab->on_res_body_alloc(cln, bufs);
        return;
    }

    cln->_ibuf._octets = NULL;
    cln->_ibuf._size = 0u;

    cln->_vtab->on_res_alloc(cln, &cln->_ires, &cln->_ibuf);

    if (cln->_ires == NULL || cln->_ibuf._octets == NULL || cln->_ibuf._size == 0u) {
        cln->_ires = NULL;
        cln->_vtab->on_res_err(cln, NULL, &s_ires_err_alloc_failed);
        return;
    }

    bufs->items = &cln->_ibuf;
    bufs->length = 1u;
}

static void s_on_read_done(ah_tcp_conn_t* conn, ah_bufs_t bufs, size_t n_read, ah_err_t err)
{
    ah_http_client_t* cln = s_upcast_to_client(conn);

    // TODO: Check state, parse res line, headers or pass on body, respectively. Make sure to handle chunked encoding.
    (void) cln;
    (void) bufs;
    (void) n_read;
    (void) err;
}

ah_extern ah_err_t ah_http_client_request(ah_http_client_t* cln, const ah_http_oreq_t* req)
{
    if (cln == NULL || req == NULL) {
        return AH_EINVAL;
    }

    (void) cln;
    (void) req;
    return AH_EOPNOTSUPP; // TODO: Implement.
}

static void s_on_write_done(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_http_client_t* cln = s_upcast_to_client(conn);

    // TODO: Check state, report if sending is complete or failed.
    (void) cln;
    (void) err;
}

ah_extern ah_err_t ah_http_client_close(ah_http_client_t* cln)
{
    if (cln == NULL) {
        return AH_EINVAL;
    }
    return cln->_trans._vtab->conn_close(&cln->_conn);
}

static void s_on_close(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_http_client_t* cln = s_upcast_to_client(conn);
    cln->_vtab->on_close(cln, err);
}
