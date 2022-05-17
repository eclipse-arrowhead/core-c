// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include <ah/assert.h>
#include <ah/err.h>

static void s_on_conn_close(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_conn_read_alloc(ah_tcp_conn_t* conn, ah_buf_t* buf);
static void s_on_conn_read_data(ah_tcp_conn_t* conn, const ah_buf_t* buf, size_t nread);
static void s_on_conn_read_err(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_conn_write_done(ah_tcp_conn_t* conn, ah_err_t err);

ah_err_t ah_i_http_rclient_init(ah_http_rclient_t* cln, ah_http_server_t* srv, const ah_sockaddr_t* raddr)
{
    (void) cln;
    (void) srv;
    (void) raddr;
    return AH_ENONE;
}

const ah_tcp_conn_vtab_t* ah_i_http_rclient_get_conn_vtab()
{
    static const ah_tcp_conn_vtab_t s_vtab = {
        .on_close = s_on_conn_close,
        .on_read_alloc = s_on_conn_read_alloc,
        .on_read_data = s_on_conn_read_data,
        .on_read_err = s_on_conn_read_err,
        .on_write_done = s_on_conn_write_done,
    };
    return &s_vtab;
}

static void s_on_conn_close(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_assert_if_debug(conn != NULL);
    (void) conn;
    (void) err; // TODO: Implement.
}

static void s_on_conn_read_alloc(ah_tcp_conn_t* conn, ah_buf_t* buf)
{
    ah_assert_if_debug(conn != NULL);
    (void) conn;
    (void) buf; // TODO: Implement.
}

static void s_on_conn_read_data(ah_tcp_conn_t* conn, const ah_buf_t* buf, size_t nread)
{
    ah_assert_if_debug(conn != NULL);
    (void) conn;
    (void) buf; // TODO: Implement.
    (void) nread;
}

static void s_on_conn_read_err(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_assert_if_debug(conn != NULL);
    (void) conn;
    (void) err; // TODO: Implement.
}

static void s_on_conn_write_done(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_assert_if_debug(conn != NULL);
    (void) conn;
    (void) err; // TODO: Implement.
}
