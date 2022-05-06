// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include "http-hmap.h"
#include "http-parser.h"

#include <ah/err.h>
#include <ah/math.h>

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
    ah_assert_if_debug(vtab->on_res_alloc_head != NULL);
    ah_assert_if_debug(vtab->on_res_alloc_more != NULL);
    ah_assert_if_debug(vtab->on_res_line != NULL);
    ah_assert_if_debug(vtab->on_res_headers != NULL);
    ah_assert_if_debug(vtab->on_res_chunk != NULL);
    ah_assert_if_debug(vtab->on_res_data != NULL);
    ah_assert_if_debug(vtab->on_res_err != NULL);
    ah_assert_if_debug(vtab->on_res_end != NULL);

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
    cln->_istate = AH_I_HTTP_CLIENT_OSTATE_READY;

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

    ah_err_t err;

    switch (cln->_istate) {
    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_NOTHING:
        err = AH_ESTATE;
        goto close_conn_and_report_err;

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_RES_LINE_START:
        cln->_ires = NULL;

        cln->_vtab->on_res_alloc_head(cln, &cln->_ires, buf);

        if (cln->_ires == NULL) {
            err = AH_ENOBUFS;
            goto close_conn_and_report_err;
        }

        cln->_istate = AH_I_HTTP_CLIENT_ISTATE_EXPECTING_RES_LINE_CONT;
        cln->_i_non_data_buf_rd = *buf;
        cln->_i_non_data_buf_wr = cln->_i_non_data_buf_rd;
        return;

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_RES_LINE_CONT:
    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_HEADERS:
    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_CHUNK:
    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_TRAILER:
        if (ah_buf_is_empty(&cln->_i_non_data_buf_wr)) {
            err = AH_EOVERFLOW;
            goto close_conn_and_report_err;
        }
        *buf = cln->_i_non_data_buf_wr;
        return;

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_DATA:
        cln->_vtab->on_res_alloc_more(cln, buf);
        return;

    default:
        ah_unreachable();
    }

close_conn_and_report_err:
    cln->_trans_vtab->conn_close(conn);
    cln->_vtab->on_res_err(cln, NULL, err);
}

static void s_on_read_data(ah_tcp_conn_t* conn, const ah_buf_t* buf, size_t nread)
{
    ah_http_client_t* cln = s_upcast_to_client(conn);

    ah_err_t err;
    ah_http_chunk_t chunk;

    switch (cln->_istate) {
    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_RES_LINE_CONT:
        if (!ah_i_http_buf_has_crlf(buf)) {
            err = ah_buf_shrinkl(&cln->_i_non_data_buf_wr, nread);
            if (err != AH_ENONE) {
                err = AH_EDOM;
                goto close_conn_and_report_ires_err;
            }
            return;
        }
        if (!ah_i_http_parse_stat_line(&cln->_i_non_data_buf_rd, &cln->_ires->stat_line)) {
            err = AH_EILSEQ;
            goto close_conn_and_report_ires_err;
        }

        cln->_vtab->on_res_line(cln, cln->_ires);

        if (ah_tcp_conn_is_closed(&cln->_conn)) {
            return;
        }

        cln->_istate = AH_I_HTTP_CLIENT_ISTATE_EXPECTING_HEADERS;
        // fallthrough

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_HEADERS:
        if (!ah_i_http_buf_has_crlfx2(buf)) {
            err = ah_buf_shrinkl(&cln->_i_non_data_buf_wr, nread);
            if (err != AH_ENONE) {
                err = AH_EDOM;
                goto close_conn_and_report_ires_err;
            }
            return;
        }
        if (!ah_i_http_parse_headers(&cln->_i_non_data_buf_rd, &cln->_ires->headers)) {
            err = AH_EILSEQ;
            goto close_conn_and_report_ires_err;
        }

        cln->_vtab->on_res_headers(cln, cln->_ires);

        if (ah_tcp_conn_is_closed(&cln->_conn)) {
            return;
        }

        if (ah_i_http_hmap_is_transfer_encoding_chunked(&cln->_ires->headers)) {
            cln->_istate = AH_I_HTTP_CLIENT_ISTATE_EXPECTING_CHUNK;
            goto expect_chunk;
        }

        err = ah_i_http_hmap_get_content_length(&cln->_ires->headers, &cln->_i_n_bytes_expected);
        if (err != AH_ENONE) {
            goto close_conn_and_report_ires_err;
        }

        if (cln->_i_n_bytes_expected == 0u) {
            cln->_n_pending_responses -= 1u;
            if (cln->_n_pending_responses == 0u) {
                cln->_istate = AH_I_HTTP_CLIENT_ISTATE_EXPECTING_NOTHING;
            }
            else {
                cln->_istate = AH_I_HTTP_CLIENT_ISTATE_EXPECTING_RES_LINE_START;
            }
            return;
        }

        cln->_istate = AH_I_HTTP_CLIENT_ISTATE_EXPECTING_DATA;
        goto expect_data;

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_CHUNK:
    expect_chunk:
        err = ah_i_http_parse_chunk(&cln->_i_non_data_buf_rd, &chunk);
        if (err != AH_ENONE) {
            // TODO: Shrink non-data buf rd?
            goto close_conn_and_report_ires_err;
        }
        cln->_i_n_bytes_expected = chunk.size;
        return;

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_DATA:
    expect_data:
        // TODO: If non_buf_rd is not empty, present data immediately and check if we are done.
        return;

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_TRAILER:
        return;

    default:
        ah_unreachable();
    }

close_conn_and_report_ires_err:
    cln->_trans_vtab->conn_close(conn);
    cln->_vtab->on_res_err(cln, NULL, err);
}

static void s_on_read_err(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_http_client_t* cln = s_upcast_to_client(conn);
    cln->_vtab->on_res_err(cln, NULL, err);
}

ah_extern ah_err_t ah_http_client_request(ah_http_client_t* cln, const ah_http_oreq_t* req)
{
    if (cln == NULL || req == NULL) {
        return AH_EINVAL;
    }

    // TODO: Send message.

    if (cln->_n_pending_responses == 0u) {
        ah_assert_if_debug(cln->_istate == AH_I_HTTP_CLIENT_ISTATE_EXPECTING_NOTHING);
        cln->_istate = AH_I_HTTP_CLIENT_ISTATE_EXPECTING_RES_LINE_START;
    }
    cln->_n_pending_responses += 1u; // TODO: Check overflow.

    return AH_EOPNOTSUPP; // TODO: Change to AH_ENONE once implemented.
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
