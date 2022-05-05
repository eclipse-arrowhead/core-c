// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include "http-parser.h"

#include <ah/err.h>

static const ah_http_ires_err_t s_ires_err_alloc_failed = {
    "memory allocation failed",
    AH_HTTP_IRES_ERR_ALLOC_FAILED,
    AH_ENOMEM,
};
static const ah_http_ires_err_t s_ires_err_buffer_overflow = {
    "response buffer overflowed (should be impossible)",
    AH_HTTP_IRES_ERR_BUFFER_OVERFLOW,
    AH_EOVERFLOW,
};
static const ah_http_ires_err_t s_ires_err_format_invalid = {
    "not an HTTP/1 response",
    AH_HTTP_IRES_ERR_FORMAT_INVALID,
    AH_EILSEQ,
};
static const ah_http_ires_err_t s_ires_err_head_too_large = {
    "status line and headers too large for allocated head buffer",
    AH_HTTP_IRES_ERR_HEAD_TOO_LARGE,
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
static void s_on_read_alloc(ah_tcp_conn_t* conn, ah_buf_t* buf);
static void s_on_read_data(ah_tcp_conn_t* conn, const ah_buf_t* buf, size_t nread);
static void s_on_read_err(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_write_done(ah_tcp_conn_t* conn, ah_err_t err);

static ah_http_client_t* s_upcast_to_client(ah_tcp_conn_t* conn);

ah_extern ah_err_t ah_http_client_init(ah_http_client_t* cln, ah_tcp_trans_t trans, const ah_http_client_vtab_t* vtab)
{
    if (cln == NULL || trans._vtab == NULL || trans._loop == NULL || vtab == NULL) {
        return AH_EINVAL;
    }

    (void) s_ires_err_format_invalid;
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
    ah_assert_if_debug(vtab->on_res_body_data != NULL);
    ah_assert_if_debug(vtab->on_res_body_done != NULL);

    static const ah_tcp_conn_vtab_t s_vtab = {
        .on_open = s_on_open,
        .on_connect = s_on_connect,
        .on_close = s_on_close,
        .on_read_alloc = s_on_read_alloc,
        .on_read_data = s_on_read_data,
        .on_read_err = s_on_read_err,
        .on_write_done = s_on_write_done,
    };

    ah_err_t err = trans._vtab->conn_init(&cln->_conn, trans._loop, &s_vtab);
    if (err != AH_ENONE) {
        return err;
    }

    cln->_conn._trans_data = trans._data;
    cln->_trans_vtab = trans._vtab;
    cln->_vtab = vtab;

    cln->_istate = AH_I_HTTP_CLIENT_ISTATE_EXPECTING_NOTHING;
    cln->_ostate = AH_I_HTTP_CLIENT_OSTATE_READY;

    return AH_ENONE;
}

ah_extern ah_err_t ah_http_client_open(ah_http_client_t* cln, const ah_sockaddr_t* laddr)
{
    if (cln == NULL) {
        return AH_EINVAL;
    }
    return cln->_trans_vtab->conn_open(&cln->_conn, laddr);
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
    ah_assert_if_debug(cln->_trans_vtab != NULL);

    return cln;
}

ah_extern ah_err_t ah_http_client_connect(ah_http_client_t* cln, const ah_sockaddr_t* raddr)
{
    if (cln == NULL) {
        return AH_EINVAL;
    }
    return cln->_trans_vtab->conn_connect(&cln->_conn, raddr);
}

static void s_on_connect(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_http_client_t* cln = s_upcast_to_client(conn);
    cln->_vtab->on_connect(cln, err);
}

static void s_on_read_alloc(ah_tcp_conn_t* conn, ah_buf_t* buf)
{
    ah_http_client_t* cln = s_upcast_to_client(conn);

    const ah_http_ires_err_t* ires_err;

    switch (cln->_istate) {
    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_RES_LINE_START:
        cln->_ires = NULL;

        cln->_vtab->on_res_alloc(cln, &cln->_ires, buf);

        if (cln->_ires == NULL) {
            ires_err = &s_ires_err_alloc_failed;
            goto stop_reading_and_report_ires_err;
        }

        cln->_istate = AH_I_HTTP_CLIENT_ISTATE_EXPECTING_RES_LINE_CONT;
        cln->_ihead_rd = *buf;
        cln->_ihead_wr = cln->_ihead_rd;
        return;

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_RES_LINE_CONT:
    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_HEADERS:
        if (ah_buf_is_empty(&cln->_ihead_wr)) {
            ires_err = &s_ires_err_head_too_large;
            goto stop_reading_and_report_ires_err;
        }
        *buf = cln->_ihead_wr;
        return;

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_BODY:
        cln->_vtab->on_res_body_alloc(cln, buf);
        return;

    default:
        ah_unreachable();
    }

stop_reading_and_report_ires_err:
    if (ah_tcp_conn_read_stop(conn) == AH_ENONE) {
        cln->_vtab->on_res_err(cln, NULL, ires_err);
    }
}

static void s_on_read_data(ah_tcp_conn_t* conn, const ah_buf_t* buf, size_t nread)
{
    ah_http_client_t* cln = s_upcast_to_client(conn);

    const ah_http_ires_err_t* ires_err;

    ah_err_t err = ah_buf_shrinkl(&cln->_ihead_wr, nread);
    if (err != AH_ENONE) {
        ires_err = &s_ires_err_buffer_overflow;
        goto stop_reading_and_report_ires_err;
    }

    switch (cln->_istate) {
    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_RES_LINE_CONT:
        if (!ah_i_http_buf_has_line_end(buf)) {
            return;
        }
        /*
        TODO: Make first argument into const ah_buf_t*.
        if (!ah_i_http_parse_stat_line(&r, &cln->_ires->stat_line)) {
            cln->_istate = AH_I_HTTP_CLIENT_ISTATE_EXPECTING_NOTHING;
            cln->_vtab->on_res_err(cln, NULL, &s_ires_err_format_invalid);
            return;
        }

        cln->_vtab->on_res_line(cln, cln->_ires);

        if (ah_tcp_conn_is_closed(&cln->_conn)) {
            return;
        }

        cln->_ostate = AH_I_HTTP_CLIENT_ISTATE_EXPECTING_HEADERS;
        */
        // TODO: Continue with headers.
        return;

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_HEADERS:
        return;

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_BODY:
        return;

    default:
        ah_unreachable();
    }

stop_reading_and_report_ires_err:
    if (ah_tcp_conn_read_stop(conn) == AH_ENONE) {
        cln->_vtab->on_res_err(cln, NULL, ires_err);
    }
}

static void s_on_read_err(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_http_client_t* cln = s_upcast_to_client(conn);

    if (err == AH_ENOBUFS) {
        cln->_vtab->on_res_err(cln, NULL, &s_ires_err_alloc_failed);
        return;
    }

    ah_http_ires_err_t ires_err = { "unexpected transport error", AH_HTTP_IRES_ERR_TRANSPORT_ERROR, err };
    cln->_vtab->on_res_err(cln, NULL, &ires_err);
}

ah_extern ah_err_t ah_http_client_request(ah_http_client_t* cln, const ah_http_oreq_t* req)
{
    if (cln == NULL || req == NULL) {
        return AH_EINVAL;
    }

    ah_err_t err = ah_tcp_conn_read_start(&cln->_conn);

    (void) err;
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
    return cln->_trans_vtab->conn_close(&cln->_conn);
}

static void s_on_close(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_http_client_t* cln = s_upcast_to_client(conn);
    cln->_vtab->on_close(cln, err);
}
